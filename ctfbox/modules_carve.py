# -*- coding: utf-8 -*-
"""文件雕刻：签名扫描 + 严格结构校验 + 内嵌文件切割（binwalk/foremost 的轻量替代）。
关键设计：二进制中短签名误报极多，每种类型必须通过结构校验才雕刻；
并限制单文件大小、每类数量与总数，避免递归爆炸把磁盘/内存撑爆。"""
import os
import io
import gzip
import bz2
import lzma
import zlib
import struct
import zipfile
from .common import Finding, Report, scan_flags, extract_strings, shannon_entropy, WORKSPACE

# 签名: (bytes, 名称, 扩展名)
SIGS = [
    (b"PK\x03\x04", "ZIP", ".zip"),
    (b"Rar!\x1a\x07\x00", "RAR4", ".rar"),
    (b"Rar!\x1a\x07\x01\x00", "RAR5", ".rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z", ".7z"),
    (b"\x1f\x8b\x08", "GZIP", ".gz"),
    (b"BZh", "BZIP2", ".bz2"),
    (b"\xfd7zXZ\x00", "XZ", ".xz"),
    (b"\x89PNG\r\n\x1a\n", "PNG", ".png"),
    (b"\xff\xd8\xff", "JPEG", ".jpg"),
    (b"GIF87a", "GIF", ".gif"),
    (b"GIF89a", "GIF", ".gif"),
    (b"BM", "BMP", ".bmp"),
    (b"%PDF", "PDF", ".pdf"),
    (b"\x7fELF", "ELF", ".elf"),
    (b"MZ", "PE", ".exe"),
    (b"SQLite format 3\x00", "SQLite", ".sqlite"),
    (b"\xd4\xc3\xb2\xa1", "PCAP", ".pcap"),
    (b"\xa1\xb2\xc3\xd4", "PCAP", ".pcap"),
    (b"\x0a\x0d\x0d\x0a", "PCAPNG", ".pcapng"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE", ".ole"),
    (b"ID3", "MP3", ".mp3"),
    (b"OggS", "OGG", ".ogg"),
    (b"RIFF", "RIFF", ".riff"),
    (b"fLaC", "FLAC", ".flac"),
]

MAX_CARVE_BYTES = 30 * 1024 * 1024     # 单个雕刻文件上限 30MB
MAX_PER_TYPE = 6                        # 每类签名最多雕刻数量
PER_TYPE_OVERRIDE = {"ELF": 2, "PE": 3, "JPEG": 4}   # 二进制内嵌 ELF(cubin)/PE 对 CTF 价值低，从严
MAX_TOTAL_CARVED = 24                   # 总雕刻文件数
MAX_SCAN_BYTES = 80 * 1024 * 1024       # 超过 80MB 的文件只在前 80MB 扫描短签名（尾部另扫长签名）


def _find_all(data: bytes, sig: bytes, start=0, end=None):
    idx = start
    end = len(data) if end is None else end
    while True:
        i = data.find(sig, idx, end)
        if i == -1:
            return
        yield i
        idx = i + 1


def _end_zip(data, start):
    eocd = data.rfind(b"PK\x05\x06", start)
    if eocd == -1:
        return None
    if eocd + 22 <= len(data):
        comment_len = struct.unpack("<H", data[eocd + 20:eocd + 22])[0]
        return min(len(data), eocd + 22 + comment_len)
    return None


def _valid_png(data, off):
    """签名后必须紧跟 IHDR，宽高合理；返回 IEND 后的结束偏移。"""
    p = off + 8
    if data[p:p + 4] != b"IHDR" or p + 24 > len(data):
        return None
    w, h = struct.unpack(">II", data[p + 4:p + 12])
    if not (1 <= w <= 30000 and 1 <= h <= 30000):
        return None
    # 位深/颜色类型合法
    bitdepth, colortype = data[p + 12], data[p + 13]
    if bitdepth not in (1, 2, 4, 8, 16) or colortype not in (0, 2, 3, 4, 6):
        return None
    iend = data.find(b"IEND\xaeB`\x82", p)
    if iend == -1 or iend - off > MAX_CARVE_BYTES:
        return None
    return iend + 12


def _valid_jpeg(data, off):
    """SOI 后 marker 合法，且窗口内存在 SOF 与 EOI；返回 EOI 后偏移。"""
    if off + 4 > len(data):
        return None
    marker = data[off + 3]
    # 紧跟的 marker：APP0/APP1、DQT(DB)、SOF(C0-C3)、DHT(C4)、DRST(DD)、COM(FE) 等
    if marker != 0xFF or data[off + 2] != 0xFF:
        return None
    seg = data[off + 4] if off + 4 < len(data) else 0
    valid_segs = set(list(range(0xC0, 0xC4)) + list(range(0xE0, 0xF0)) +
                     [0xDB, 0xC4, 0xDD, 0xDA, 0xFE, 0xD8, 0xD9])
    if seg not in valid_segs:
        return None
    # 合法性只切 2MB 小窗口（避免对海量误报命中切 30MB 导致性能灾难）
    head_end = min(len(data), off + 2_000_000)
    head = data[off:head_end]
    # 必须出现 SOF0/2 标记（0xFFC0/0xFFC2），排除随机数据
    sof = head.find(b"\xff\xc0")
    sof2 = head.find(b"\xff\xc2")
    sof = min(x for x in (sof, sof2) if x != -1) if (sof != -1 or sof2 != -1) else -1
    if sof == -1:
        return None
    eoi = data.find(b"\xff\xd9", off + sof, min(len(data), off + MAX_CARVE_BYTES))
    if eoi == -1:
        return None
    return eoi + 2


def _valid_gif(data, off):
    hdr = data[off:off + 6]
    if hdr not in (b"GIF87a", b"GIF89a") or off + 10 > len(data):
        return None
    w, h = struct.unpack("<HH", data[off + 6:off + 10])
    if not (1 <= w <= 30000 and 1 <= h <= 30000):
        return None
    term = data.find(b"\x3b", off + 10)
    if term == -1 or term - off > MAX_CARVE_BYTES:
        return None
    return term + 1


def _valid_bmp(data, off):
    if off + 6 > len(data):
        return None
    size_field = struct.unpack("<I", data[off + 2:off + 6])[0]
    if not (100 <= size_field <= MAX_CARVE_BYTES and off + size_field <= len(data)):
        return None
    dib = struct.unpack("<I", data[off + 14:off + 18])[0] if off + 18 <= len(data) else 0
    if dib not in (12, 40, 52, 56, 108, 124):
        return None
    return off + size_field


def _valid_pdf(data, off):
    eof = data.rfind(b"%%EOF", off, min(len(data), off + MAX_CARVE_BYTES))
    if eof == -1:
        return None
    # 至少出现 obj/endobj 或 xref，排除随机 %PDF
    window = data[off:eof]
    if b"obj" not in window[:4000]:
        return None
    return eof + 5


ELF_CARVE_BYTES = 8 * 1024 * 1024     # ELF 无结束标记，盲切限 8MB（多为固件/cubin）

def _valid_elf(data, off):
    # \x7fELF + class(1/2) + data(1/2) + version(1)
    if off + 16 > len(data) or data[off:off + 4] != b"\x7fELF":
        return None
    if data[off + 4] not in (1, 2) or data[off + 5] not in (1, 2) or data[off + 6] != 1:
        return None
    # e_type（偏移16，2字节）应为合法类型：1=REL 2=EXEC 3=DYN 4=CORE
    import struct as _st
    if data[off + 5] == 1:  # 小端
        etype = _st.unpack_from("<H", data, off + 16)[0]
    else:
        etype = _st.unpack_from(">H", data, off + 16)[0]
    if etype not in (1, 2, 3, 4):
        return None
    return min(len(data), off + ELF_CARVE_BYTES)


DECOMP_FEED_BYTES = 2 * 1024 * 1024     # 解压尝试只喂 2MB，非法流快速失败
MAX_DECOMP_TRY = 6                       # 每类压缩签名最多尝试的命中数（解压昂贵）

def _gunzip_limited(data, off, max_out=20 * 1024 * 1024):
    """增量解压 gzip，限制输出，非法流快速失败。"""
    try:
        if data[off + 3] & ~0x1f:  # FLG 保留位必须为 0
            return None
        if data[off + 4] != 8:    # CM 必须是 deflate
            return None
        d = zlib.decompressobj(-zlib.MAX_WBITS)
        out = d.decompress(data[off:off + DECOMP_FEED_BYTES])
        if not out or len(out) < 16:
            return None
        return out[:max_out]
    except Exception:
        return None


def _bz2_limited(data, off, max_out=20 * 1024 * 1024):
    try:
        # BZh 后必须是块大小 1-9
        if chr(data[off + 3]) not in "123456789":
            return None
        dec = bz2.BZ2Decompressor()
        out = dec.decompress(data[off:off + DECOMP_FEED_BYTES])
        return out[:max_out] if (out and len(out) >= 16) else None
    except Exception:
        return None


def _xz_limited(data, off, max_out=20 * 1024 * 1024):
    try:
        if data[off:off + 6] != b"\xfd7zXZ\x00":
            return None
        dec = lzma.LZMADecompressor()
        out = dec.decompress(data[off:off + DECOMP_FEED_BYTES], max_length=max_out)
        return out if (out and len(out) >= 16) else None
    except Exception:
        return None


def scan_and_carve(path, report: Report, outdir: str, carve: bool = True, depth: int = 0):
    with open(path, "rb") as f:
        data = f.read()
    size = len(data)
    # 递归层级越深预算越紧：雕刻出的文件再次内嵌文件对 CTF 价值递减，严控耗时
    if depth == 0:
        short_end, per_type_cap, total_cap = min(size, MAX_SCAN_BYTES), MAX_PER_TYPE, MAX_TOTAL_CARVED
    elif depth == 1:
        short_end, per_type_cap, total_cap = min(size, 30 * 1024 * 1024), 3, 10
    else:
        short_end, per_type_cap, total_cap = min(size, 10 * 1024 * 1024), 2, 6
    carve_dir = os.path.join(outdir, "carved")
    # 校验阶段只记录轻量元组 (off,name,ext,kind,arg)，不切大 blob，避免上百次大切片
    hits = []
    decomp_tries = {}
    for sig, name, ext in SIGS:
        scan_end = size if len(sig) >= 6 else short_end
        for off in _find_all(data, sig, 0, scan_end):
            if off == 0:
                continue  # 本体头部一律跳过
            end = None
            kind = None
            if name == "BMP":
                end = _valid_bmp(data, off)
            elif name == "PNG":
                end = _valid_png(data, off)
            elif name == "JPEG":
                end = _valid_jpeg(data, off)
            elif name == "GIF":
                end = _valid_gif(data, off)
            elif name == "PDF":
                end = _valid_pdf(data, off)
            elif name == "ELF":
                end = _valid_elf(data, off)
            elif name == "PE":
                if off + 0x40 <= len(data):
                    e_lfanew = struct.unpack("<I", data[off + 0x3c:off + 0x40])[0]
                    p = off + e_lfanew
                    if 0 < e_lfanew < 0x1000 and p + 4 <= len(data) and data[p:p + 4] == b"PE\x00\x00":
                        end = min(len(data), off + MAX_CARVE_BYTES)
            elif name == "RIFF" and off + 12 <= len(data):
                if data[off + 8:off + 12] in (b"WAVE", b"WEBP", b"AVI "):
                    riff_size = struct.unpack("<I", data[off + 4:off + 8])[0]
                    if 16 <= riff_size <= MAX_CARVE_BYTES:
                        end = min(len(data), off + 8 + riff_size)
            elif name == "ZIP":
                end = _end_zip(data, off)
                if end and end - off > MAX_CARVE_BYTES:
                    end = None
            elif name == "GZIP":
                kind = "gunzip" if decomp_tries.get("GZIP", 0) < MAX_DECOMP_TRY else None
                decomp_tries["GZIP"] = decomp_tries.get("GZIP", 0) + 1
            elif name == "BZIP2":
                kind = "bunzip2" if decomp_tries.get("BZIP2", 0) < MAX_DECOMP_TRY else None
                decomp_tries["BZIP2"] = decomp_tries.get("BZIP2", 0) + 1
            elif name == "XZ":
                kind = "unxz" if decomp_tries.get("XZ", 0) < MAX_DECOMP_TRY else None
                decomp_tries["XZ"] = decomp_tries.get("XZ", 0) + 1
            elif name in ("RAR4", "RAR5", "7z", "SQLite", "PCAP", "PCAPNG", "OLE",
                          "MP3", "OGG", "FLAC"):
                end = min(len(data), off + MAX_CARVE_BYTES)
            if end and end > off:
                hits.append((off, name, ext, "slice", end))
            elif kind:
                hits.append((off, name, ext, kind, None))

    # 每类数量上限 + 总数上限（按偏移排序后截取）
    hits.sort(key=lambda x: x[0])
    type_count = {}
    picked = []
    for h in hits:
        nm = h[1]
        limit = min(per_type_cap, PER_TYPE_OVERRIDE.get(nm, MAX_PER_TYPE))
        if type_count.get(nm, 0) >= limit:
            continue
        if len(picked) >= total_cap:
            break
        type_count[nm] = type_count.get(nm, 0) + 1
        picked.append(h)

    # 筛选后才真正切片/解压（最多 24 个）
    materialized = []
    for off, name, ext, kind, arg in picked:
        try:
            if kind == "slice":
                blob = data[off:arg]
            elif kind == "gunzip":
                blob = _gunzip_limited(data, off)
            elif kind == "bunzip2":
                blob = _bz2_limited(data, off)
            elif kind == "unxz":
                blob = _xz_limited(data, off)
            else:
                blob = None
        except Exception:
            blob = None
        if blob and len(blob) >= 16:
            materialized.append((off, name, ext, blob))

    # dispatcher 可能对同一文件多次调用本函数（通用流+压缩包流），
    # 已出过同类结论时不再重复刷屏。
    existing_titles = {f.title for f in report.findings}
    if not materialized:
        if "内嵌文件扫描" not in existing_titles:
            report.add("info", "内嵌文件扫描", "未发现通过结构校验的内嵌文件")
    else:
        if not any(t.endswith("个内嵌文件") for t in existing_titles):
            lines = [f"偏移 0x{off:x}({off})  {name} ({len(blob)} 字节)" for off, name, _, blob in materialized]
            report.add("ok", f"发现 {len(lines)} 个内嵌文件", "\n".join(lines)[:3000])

    if not carve:
        return
    os.makedirs(carve_dir, exist_ok=True)
    for n, (off, name, ext, blob) in enumerate(materialized):
        fp = os.path.join(carve_dir, f"carved_{n:02d}_0x{off:x}"
                          + (ext if name not in ("GZIP", "BZIP2", "XZ") else ".out"))
        # 同一路径已雕刻且内容大小一致（重复调用）则跳过
        if fp in report.extracted and (not os.path.exists(fp) or os.path.getsize(fp) == len(blob)):
            continue
        try:
            with open(fp, "wb") as f:
                f.write(blob)
        except Exception:
            continue
        report.add("ok", f"雕刻出 {name} @0x{off:x}", f"{len(blob)} 字节 -> {fp}")
        if fp not in report.extracted:
            report.extracted.append(fp)
        for fl in scan_flags(blob):
            report.add("flag", f"雕刻出的 {name} 中发现 flag", fl)

    # 完整性结论同样去重：已对该 zip 下过结论就不再重复
    # （ok 结论 detail 是完整路径，warn 结论 detail 以文件名开头，两种都收录）
    checked_zip = set()
    for f in report.findings:
        if f.title.startswith("雕刻 ZIP") and f.detail:
            checked_zip.add(f.detail)
            checked_zip.add(os.path.basename(f.detail.split(":", 1)[0]))
    ok_fingerprints = set()   # 已判定"完整"的压缩包成员指纹，修复副本/雕刻副本只报一次
    for fn in list(report.extracted):
        if fn.endswith(".zip") and fn not in checked_zip and os.path.basename(fn) not in checked_zip:
            # testzip() 只读本地头/CRC，尾部残缺（中央目录在、数据不全）时也会返回 None，
            # 必须真正尝试解压每个条目才能发现 negative seek / 数据缺失。
            try:
                with zipfile.ZipFile(fn) as z:
                    fp = "|".join(f"{i.filename}:{i.CRC}:{i.file_size}" for i in
                                  sorted(z.infolist(), key=lambda i: i.filename))
                    bad = z.testzip()
                    if bad is not None:
                        report.add("warn", "雕刻 ZIP 可能被截断",
                                   f"{os.path.basename(fn)}: CRC 校验失败条目 {bad}")
                        continue
                    failed = []
                    for info in z.infolist():
                        if info.is_dir():
                            continue
                        try:
                            with z.open(info) as zf:
                                while zf.read(1 << 16):
                                    pass
                        except Exception as e:
                            failed.append(f"{info.filename}: {e}")
                    if failed:
                        # 截断/损坏结论必须逐条报告（即使成员指纹与完整包相同）
                        report.add("warn", "雕刻 ZIP 数据不完整（结构在但内容被截断，无法正常解压）",
                                   f"{os.path.basename(fn)}\n" + "\n".join(failed[:5]))
                    elif fp in ok_fingerprints:
                        # 与已判定完整的容器成员完全一致（修复副本 vs 雕刻副本），不再重复报正常
                        continue
                    else:
                        ok_fingerprints.add(fp)
                        report.add("ok", "雕刻 ZIP 完整性正常（可正常解压）", fn)
            except Exception as e:
                report.add("info", "雕刻 ZIP 可能被截断", f"{os.path.basename(fn)}: {e}")


def strings_scan(path, report: Report, min_len=5):
    with open(path, "rb") as f:
        data = f.read(MAX_SCAN_BYTES)
    strs = extract_strings(data, min_len)
    import re
    urls = sorted(set(s for s in strs if s.startswith(("http://", "https://", "ftp://"))))[:50]
    ips = sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b", "\n".join(strs))))[:50]
    emails = sorted(set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", "\n".join(strs))))[:50]
    interesting = [s for s in strs if any(k in s.lower() for k in
                   ("flag", "password", "passwd", "secret", "key{", "token", "api_key", "private"))][:100]
    if urls:
        report.add("info", "字符串中的 URL", "\n".join(urls))
    if ips:
        report.add("info", "字符串中的 IP:端口", "\n".join(ips))
    if emails:
        report.add("info", "字符串中的邮箱", "\n".join(emails))
    if interesting:
        report.add("ok", "可疑/敏感字符串", "\n".join(interesting)[:3000])
    for fl in scan_flags("\n".join(strs).encode("utf-8", "ignore")):
        report.add("flag", "字符串中发现 flag", fl)
    return strs
