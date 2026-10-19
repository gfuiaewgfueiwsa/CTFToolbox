# -*- coding: utf-8 -*-
"""压缩包分析：ZIP 伪加密检测/修复、注释、弱口令爆破、CRC 小文件碰撞、多格式解压。"""
import os
import re
import io
import gzip
import bz2
import lzma
import zipfile
import tarfile
import binascii
import subprocess
from collections import defaultdict
from .common import Finding, Report, scan_flags, WORKSPACE
from .modules_text import WEAK_PASSWORDS

def _sevenz():
    from .toolsmgr import get_tool
    return get_tool("7z")

# ----------------------------------------------------------------------------
# ZIP
# ----------------------------------------------------------------------------
def _zip_fake_encryption(raw: bytes):
    """返回 (是否伪加密, 修复后的bytes或None, 描述)。"""
    local_flags = []
    central_flags = []
    # 本地文件头
    for m in re.finditer(b"PK\x03\x04", raw):
        off = m.start()
        if off + 8 <= len(raw):
            flag = int.from_bytes(raw[off + 6:off + 8], "little")
            local_flags.append((off, flag))
    for m in re.finditer(b"PK\x01\x02", raw):
        off = m.start()
        if off + 10 <= len(raw):
            flag = int.from_bytes(raw[off + 8:off + 10], "little")
            central_flags.append((off, flag))
    fake = False
    fixed = bytearray(raw)
    for off, lf in local_flags:
        cf_enc = None
        # 中央目录条目顺序与本地一致（近似）
        idx = local_flags.index((off, lf))
        if idx < len(central_flags):
            cf_enc = central_flags[idx][1] & 1
        if (lf & 1) and cf_enc == 0:
            fake = True
            fixed[off + 6] &= 0xFE      # 清本地头加密位
    # 反向情形：中央目录被置加密位而数据未加密
    for off, cf in central_flags:
        idx = central_flags.index((off, cf))
        if idx < len(local_flags):
            lf = local_flags[idx][1]
            if (cf & 1) and not (lf & 1):
                fake = True
                fixed[off + 8] &= 0xFE
    return fake, (bytes(fixed) if fake else None), f"本地头{len(local_flags)}个/中央目录{len(central_flags)}个"

def _crc_scan_chunk(args):
    """进程池 worker：在 [start, start+count) 混合进制区间内同时碰撞一批 CRC。
    targets: 待求 CRC 集合（dict 的键）；charset[d] 为数字 d 对应的字节值。
    返回 [(crc, 明文字节)]。直接维护数字位，避免 index 查找。"""
    targets, charset, size, start, count = args
    n = len(charset)
    digits = [0] * size
    x = start
    for i in range(size - 1, -1, -1):
        digits[i] = x % n
        x //= n
    buf = bytearray(charset[d] for d in digits)
    crc = binascii.crc32
    found = []
    remain = dict.fromkeys(targets)
    for _ in range(count):
        h = crc(bytes(buf)) & 0xffffffff
        if h in remain:
            found.append((h, bytes(buf)))
            del remain[h]
            if not remain:
                return found
        p = size - 1
        while p >= 0:
            d = digits[p] + 1
            if d < n:
                digits[p] = d
                buf[p] = charset[d]
                break
            digits[p] = 0
            buf[p] = charset[0]
            p -= 1
        if p < 0:
            break
    return found


def _crc_charset_for_size(size: int):
    import string
    if size <= 4:
        cs = (string.digits + string.ascii_lowercase + string.ascii_uppercase
              + string.punctuation + " ").encode("latin-1")
    elif size == 5:
        cs = (string.digits + string.ascii_lowercase).encode()
    elif size == 6:
        cs = string.digits.encode()
    else:
        return None
    return cs


def _zip_crc_crack_batch(jobs, log=print):
    """jobs: [(name, crc, size)]；一次遍历同时碰撞全部，返回 {name: 明文字节}。
    同一 CRC 可能对应多个同名片段（如多个 AAAA），统一映射回全部名字。"""
    import multiprocessing as mp
    result = {}
    # size -> {crc: [name,...]}
    by_size = defaultdict(lambda: defaultdict(list))
    for name, crc, size in jobs:
        if 1 <= size <= 6:
            by_size[size][crc].append(name)

    def assign(h, b):
        for nm in by_size[size][h]:
            result[nm] = b

    for size, crc_map in by_size.items():
        # 弱口令快速通道
        for w in WEAK_PASSWORDS:
            b = w.encode()
            if len(b) == size:
                h = binascii.crc32(b) & 0xffffffff
                if h in crc_map and crc_map[h][0] not in result:
                    assign(h, b)
        # 数字串通道（含前导零）
        digit_total = 10 ** size
        if digit_total <= 100_000_000:
            for i in range(digit_total):
                b = str(i).zfill(size).encode()
                h = binascii.crc32(b) & 0xffffffff
                if h in crc_map and crc_map[h][0] not in result:
                    assign(h, b)

        def run_charset(cs, label):
            remain = {h: None for h in crc_map if crc_map[h][0] not in result}
            if not remain:
                return
            total = len(cs) ** size
            workers = max(1, mp.cpu_count() - 1)
            chunk = 1_000_000
            tasks = [(list(remain), cs, size, s, min(chunk, total - s))
                     for s in range(0, total, chunk)]
            log(f"CRC32 批量碰撞：{size} 字节 {len(remain)} 个目标，{label}，"
                f"空间 {total:,}，{workers} 进程")
            done = set()

            def consume(found):
                for h, b in found:
                    if crc_map[h][0] not in result:
                        assign(h, b)
                        done.add(h)

            try:
                with mp.Pool(workers) as pool:
                    for found in pool.imap_unordered(_crc_scan_chunk, tasks, chunksize=1):
                        if found:
                            consume(found)
                            if len(done) >= len(remain):
                                pool.terminate()
                                break
            except Exception as e:
                log(f"多进程爆破失败，回退单进程: {e}")
                for t in tasks:
                    consume(_crc_scan_chunk(t))

        cs = _crc_charset_for_size(size)
        if cs:
            run_charset(cs, f"可打印字符集 {len(cs)} 种")
        # ≤4 字节且仍有未命中（可能是任意二进制），全字节域兜底
        if size <= 4:
            left = [h for h in crc_map if crc_map[h][0] not in result]
            if left:
                run_charset(bytes(range(256)), "全字节域 256 种")
    return result


def _zip_crc_crack(crc_target: int, size: int, log=print):
    """单目标 CRC32 碰撞（兼容旧入口）。"""
    r = _zip_crc_crack_batch([("x", crc_target, size)], log)
    return r.get("x")

def analyze_zip(path, report: Report, outdir: str):
    with open(path, "rb") as f:
        raw = f.read()

    fake, fixed, desc = _zip_fake_encryption(raw)
    if fake:
        fp = os.path.join(outdir, "fixed_fakeenc.zip")
        with open(fp, "wb") as f:
            f.write(fixed)
        report.add("ok", "检测到 ZIP 伪加密！已自动修复", fp)
        report.extracted.append(fp)
        try:
            with zipfile.ZipFile(fp) as z:
                z.extractall(os.path.join(outdir, "fixed_extracted"))
        except Exception:
            pass

    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except Exception as e:
        report.add("warn", "ZIP 解析失败", str(e))
        return

    comment = zf.comment
    if comment:
        report.add("ok", "ZIP 全局注释", comment.decode("latin-1", "replace"))
        for fl in scan_flags(comment):
            report.add("flag", "ZIP 注释中发现 flag", fl)

    rows = []
    encrypted = False
    small_crc_jobs = []
    for zi in zf.infolist():
        enc = bool(zi.flag_bits & 1)
        encrypted |= enc
        rows.append(f"{'[加密]' if enc else '[    ]'} {zi.filename}  "
                    f"大小={zi.file_size} 压缩={zi.compress_size} CRC={zi.CRC:08x} "
                    f"方式={zi.compress_type} 注释={zi.comment.decode('latin-1','replace') if zi.comment else ''}")
        if zi.comment:
            for fl in scan_flags(zi.comment):
                report.add("flag", f"条目 {zi.filename} 注释中发现 flag", fl)
        # CRC 碰撞只依赖明文 CRC（中央目录始终给出），与压缩/加密方式无关；
        # 未加密文件可直接解压，故仅对加密的极小文件做碰撞
        if 1 <= zi.file_size <= 6 and (zi.flag_bits & 1):
            small_crc_jobs.append(zi)
    report.add("info", "ZIP 内容列表", "\n".join(rows)[:4000])

    # CRC32 批量碰撞（加密的极小文件，一次遍历还原全部）
    if small_crc_jobs:
        jobs = [(zi.filename, zi.CRC, zi.file_size) for zi in small_crc_jobs]
        report.add("info", f"发现 {len(jobs)} 个极小加密文件，尝试 CRC32 批量碰撞",
                   "\n".join(f"{n}（{s}字节,CRC={c:08x}）" for n, c, s in jobs[:30]))
        try:
            hits = _zip_crc_crack_batch(
                jobs, log=lambda m: report.add("info", "CRC 碰撞", m))
            recovered = {}
            for zi in small_crc_jobs:
                hit = hits.get(zi.filename)
                if hit is not None:
                    report.add("flag", f"CRC32 碰撞还原 {zi.filename}", repr(hit))
                    recovered[zi.filename] = hit
                    for fl in scan_flags(hit):
                        report.add("flag", f"{zi.filename} 中发现 flag", fl)
            # 多个 4 字节片段常拼合为 base64/二进制，按条目顺序尝试重组
            if len(recovered) >= 2:
                _crc_reassemble(recovered, small_crc_jobs, report, outdir)
        except Exception as e:
            report.add("warn", "CRC 碰撞失败", str(e))

    if not encrypted:
        exdir = os.path.join(outdir, "extracted")
        try:
            zf.extractall(exdir)
            for root, _, files in os.walk(exdir):
                for fn in files:
                    report.extracted.append(os.path.join(root, fn))
            report.add("ok", "ZIP 已解压（无密码）", exdir)
        except Exception as e:
            report.add("warn", "无密码解压失败", str(e))
        # 存储型小文件直接就是明文
        for zi in small_crc_jobs:
            data = zf.read(zi.filename)
            report.add("info", f"小文件 {zi.filename} 为存储模式，内容即明文",
                       data[:200].decode("latin-1", "replace"))
            for fl in scan_flags(data):
                report.add("flag", f"{zi.filename} 中发现 flag", fl)
    else:
        report.add("warn", "ZIP 已加密", "开始尝试空密码与内置弱口令…")
        ok, pwd, extracted_dir = _crack_7z(path, outdir)
        if ok:
            report.add("ok", f"压缩包密码命中: {pwd}", f"解压目录: {extracted_dir}")
            for root, _, files in os.walk(extracted_dir):
                for fn in files:
                    report.extracted.append(os.path.join(root, fn))
        else:
            report.add("warn", "弱口令字典未命中",
                       "可在界面中选择大字典（如 rockyou）继续爆破；或判断是否为 CRC 碰撞/明文攻击题")

def _natural_num(name):
    m = re.search(r"(\d+)", name)
    return int(m.group(1)) if m else 0


def _reassemble_chunks(joined: bytes, outdir: str, report, title="拼合片段"):
    """拼合 CRC 片段并尝试 Base64 还原为文件。joined 为字节串。"""
    import base64
    if isinstance(joined, str):
        joined = joined.encode("latin-1")
    report.add("ok", title, joined.decode("latin-1", "replace"))
    for fl in scan_flags(joined):
        report.add("flag", title + "中发现 flag", fl)
    try:
        raw = base64.b64decode(joined + b"=" * (-len(joined) % 4), validate=False)
    except Exception:
        return None
    if len(raw) < 8:
        return None
    ext, kind = ".bin", "数据"
    if raw.startswith(b"\x89PNG"):
        ext, kind = ".png", "PNG 图片"
    elif raw[:2] == b"MZ":
        ext, kind = ".exe", "PE 可执行文件"
    elif raw[:4] == b"PK\x03\x04":
        ext, kind = ".zip", "ZIP 压缩包"
    elif raw[:3] == b"GIF":
        ext, kind = ".gif", "GIF 图片"
    elif raw[:2] == b"\xff\xd8":
        ext, kind = ".jpg", "JPEG 图片"
    # 看似 ZIP 结构（含文件名条目）却无法直接打开时，做容错本地头雕刻
    if not raw.startswith(b"PK\x03\x04") and (b"PK\x03\x04" in raw or
                                             re.search(rb"[A-Za-z0-9_-]{1,40}\.[A-Za-z0-9]{1,4}", raw)):
        carve_broken_zip(raw, outdir, report)
    fp = os.path.join(outdir, "crc_reassembled" + ext)
    with open(fp, "wb") as f:
        f.write(raw)
    report.add("ok", f"{title}经 Base64 还原为{kind}（{len(raw)}字节）", fp, fp)
    report.extracted.append(fp)
    for fl in scan_flags(raw):
        report.add("flag", "重组数据中发现 flag", fl)
    return fp


def carve_broken(raw: bytes, outdir: str, report: Report):
    """对签名/长度字段损坏的 ZIP 数据做容错雕刻：
    依据文件名锚点，尝试其后的 raw-deflate 流与最长可打印片段（STORED）。"""
    import zlib
    os.makedirs(outdir, exist_ok=True)
    name_re = re.compile(rb"[A-Za-z0-9_\-]{1,40}\.[A-Za-z0-9]{1,4}")
    n = 0
    for m in name_re.finditer(raw):
        name = m.group()
        ne = m.end()
        content = None
        how = ""
        # 1) 在文件名后 0..16 字节偏移尝试 raw deflate
        for skip in range(0, 17):
            try:
                dobj = zlib.decompressobj(-15)
                dec = dobj.decompress(raw[ne + skip:ne + skip + 50_000_000])
                if dec and len(dobj.unused_data) >= 0 and (
                        scan_flags(dec) or sum(
                            1 for b in dec if 9 <= b <= 13 or 32 <= b < 127) /
                        max(1, len(dec)) > 0.8):
                    content, how = dec, f"deflate@+{skip}"
                    break
            except Exception:
                continue
        # 2) STORED：取文件名后最长可打印片段
        if content is None:
            run = bytearray()
            best = b""
            for b in raw[ne:ne + 4096]:
                if 9 <= b <= 13 or 32 <= b < 127:
                    run.append(b)
                else:
                    if len(run) > len(best):
                        best = bytes(run)
                    run = bytearray()
                    if len(best) > 200:
                        break
            if len(best) >= 4:
                content, how = best, "stored"
        if content is None:
            continue
        safe = re.sub(rb"[^A-Za-z0-9._-]", b"_", name).decode("latin-1")
        dst = os.path.join(outdir, "carved_" + safe)
        with open(dst, "wb") as f:
            f.write(content)
        report.add("ok", f"容错雕刻出条目 {name.decode('latin-1','replace')}（{how}，{len(content)}字节）",
                   dst, dst)
        report.extracted.append(dst)
        shown = content[:200]
        try:
            report.add("info", f"{name.decode('latin-1','replace')} 内容预览",
                       shown.decode("utf-8", "replace"))
        except Exception:
            pass
        for fl in scan_flags(content):
            report.add("flag", f"{name.decode('latin-1','replace')} 中发现 flag", fl)
        n += 1
    if n:
        report.add("info", "损坏 ZIP 修复提示",
                   "已按文件名锚点容错雕刻出条目；若仍不完整，可在 010 Editor 中把本地头签名改回 "
                   "PK\\x03\\x04、重建中央目录，或用完整 7-Zip/WinRAR 的修复功能打开")
    return n


carve_broken_zip = carve_broken


def _crc_reassemble(recovered, infos, report, outdir):
    """同一压缩包内多个 CRC 碰撞片段按条目名自然序拼合。"""
    order = sorted(recovered, key=lambda n: _natural_num(n))
    _reassemble_chunks(b"".join(recovered[n] for n in order), outdir, report,
                       "CRC 片段按序拼合")


def collect_crc_jobs_from_zips(zip_paths):
    """从多个 zip 中收集加密的极小文件 CRC 任务。
    返回 [(标签, crc, size, zip_path, entry_name)]。"""
    jobs = []
    for zp in zip_paths:
        try:
            z = zipfile.ZipFile(zp)
        except Exception:
            continue
        for zi in z.infolist():
            if (zi.flag_bits & 1) and 1 <= zi.file_size <= 6:
                label = os.path.basename(zp) + "/" + zi.filename
                jobs.append((label, zi.CRC, zi.file_size, zp, zi.filename))
    return jobs


def analyze_crc_suite(zip_paths, report, outdir):
    """对一批 zip（如 out0.zip…outN.zip）做跨文件 CRC32 批量碰撞并重组。"""
    jobs_raw = collect_crc_jobs_from_zips(zip_paths)
    if not jobs_raw:
        report.add("warn", "CRC 套件", "所选压缩包中没有加密的极小(≤6字节)文件")
        return
    os.makedirs(outdir, exist_ok=True)
    jobs = [(label, crc, size) for label, crc, size, _, _ in jobs_raw]
    report.add("info", f"共 {len(jobs)} 个 CRC 目标，开始批量碰撞",
               "\n".join(f"{n}（{s}字节,CRC={c:08x}）" for n, c, s in jobs[:40]))
    hits = _zip_crc_crack_batch(jobs, log=lambda m: report.add("info", "CRC 碰撞", m))
    recovered = {}
    for label, crc, size, zp, entry in jobs_raw:
        h = hits.get(label)
        if h is not None:
            recovered[label] = h
            report.add("flag", f"还原 {label}", repr(h))
    if len(recovered) >= 2:
        order = sorted(recovered, key=lambda n: _natural_num(n.split("/")[0]))
        _reassemble_chunks(b"".join(recovered[n] for n in order), outdir, report,
                           "全部片段按序拼合")
    elif recovered:
        report.add("ok", "碰撞结果", "\n".join(f"{k}: {v!r}" for k, v in recovered.items()))
    else:
        report.add("warn", "CRC 套件", "全部目标均未碰撞成功")


def bkcrack_attack(enc_zip: str, plain_zip: str, report: Report, outdir: str,
                   entry: str = None, log=print):
    """ZIP 明文攻击（bkcrack）。
    enc_zip: 加密压缩包；plain_zip: 含同名未加密文件的原始压缩包；
    entry: 指定加密包内条目名（缺省自动按同名+大小匹配）。
    成功后生成无密码 deciphered.zip 并解压。"""
    from .toolsmgr import get_tool
    bk = get_tool("bkcrack")
    if not bk:
        report.add("warn", "需要 bkcrack", "请在工具中心安装 bkcrack 后进行明文攻击")
        return False
    os.makedirs(outdir, exist_ok=True)
    try:
        ze = zipfile.ZipFile(enc_zip)
        zp = zipfile.ZipFile(plain_zip)
    except Exception as e:
        report.add("warn", "压缩包打开失败", str(e))
        return False
    pairs = []
    pinfo = {i.filename: i for i in zp.infolist() if not i.is_dir()}
    for ie in ze.infolist():
        if ie.is_dir():
            continue
        if entry:
            if ie.filename == entry and ie.filename in pinfo:
                pairs.append((ie.filename, ie.filename))
            continue
        p = pinfo.get(ie.filename)
        if p and p.file_size == ie.file_size and p.file_size >= 12:
            pairs.append((ie.filename, ie.filename))
    if not pairs:
        report.add("warn", "明文攻击",
                   "未找到同名且大小一致(≥12字节)的文件对；bkcrack 至少需要 12 字节已知明文")
        return False
    report.add("info", "明文候选", ", ".join(c for c, _ in pairs))
    keys = None
    for ce, pe in pairs[:4]:
        log(f"bkcrack 正在对 {ce} 求内部密钥（可能需要数分钟到数十分钟）…")
        try:
            r = subprocess.run([bk, "-C", enc_zip, "-c", ce, "-P", plain_zip, "-p", pe],
                               capture_output=True, text=True, timeout=7200,
                               errors="replace")
        except subprocess.TimeoutExpired:
            log(f"{ce} 超时，跳过")
            continue
        out = r.stdout + r.stderr
        m = re.search(r"Keys?\D{0,20}?([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})", out)
        if m:
            keys = (m.group(1), m.group(2), m.group(3))
            log(f"命中内部密钥: {' '.join(keys)}")
            break
        log(f"{ce} 未求出密钥")
    if not keys:
        report.add("warn", "明文攻击失败", "所有候选均未求出密钥，确认明文是否正确且≥12字节")
        return False
    deciphered = os.path.join(outdir, "deciphered.zip")
    r = subprocess.run([bk, "-C", enc_zip, "-k", *keys, "-D", deciphered],
                       capture_output=True, text=True, timeout=600, errors="replace")
    if not os.path.exists(deciphered):
        report.add("warn", "解密失败", (r.stdout + r.stderr)[-300:])
        return False
    report.add("ok", "明文攻击成功，已生成无密码压缩包", deciphered, deciphered)
    exdir = os.path.join(outdir, "plaintext_extracted")
    try:
        with zipfile.ZipFile(deciphered) as z:
            z.extractall(exdir)
        for root, _, files in os.walk(exdir):
            for fn in files:
                fp = os.path.join(root, fn)
                report.extracted.append(fp)
                data = open(fp, "rb").read()
                for fl in scan_flags(data):
                    report.add("flag", f"{fn} 中发现 flag", fl)
        report.add("ok", "明文攻击产物已解压", exdir, exdir)
    except Exception as e:
        report.add("warn", "解压解密包失败", str(e))
    return True


def _crack_7z(path, outdir, extra_wordlist=None):
    """用 7z 测试密码并解压。返回 (成功, 密码, 解压目录)。"""
    sz = _sevenz()
    if not sz:
        return False, None, None
    words = [""] + WEAK_PASSWORDS
    if extra_wordlist and os.path.exists(extra_wordlist):
        with open(extra_wordlist, "r", errors="ignore") as f:
            words += [w.strip() for w in f if w.strip()]
    for pwd in words:
        try:
            r = subprocess.run([sz, "t", path, f"-p{pwd}", "-y"],
                               capture_output=True, timeout=60)
            out = r.stdout + r.stderr
            if r.returncode == 0 and b"Everything is Ok" in out:
                exdir = os.path.join(outdir, "cracked_" + str(abs(binascii.crc32(pwd.encode() or b' '))))
                os.makedirs(exdir, exist_ok=True)
                subprocess.run([sz, "x", path, f"-p{pwd}", "-y", f"-o{exdir}"],
                               capture_output=True, timeout=300)
                return True, pwd or "(空密码)", exdir
        except subprocess.TimeoutExpired:
            continue
        except Exception:
            continue
    return False, None, None

# ----------------------------------------------------------------------------
# tar / gz / bz2 / xz / 7z / rar 统一入口
# ----------------------------------------------------------------------------
def analyze(path, report: Report, ftype: str, outdir: str):
    name = os.path.basename(path).lower()
    if ftype.startswith("ZIP") or name.endswith((".zip", ".jar", ".apk", ".docx", ".xlsx")):
        analyze_zip(path, report, outdir)
        return

    # tar 家族
    tar_mode = None
    if name.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")):
        tar_mode = "r:*"
    if tar_mode:
        try:
            with tarfile.open(path, tar_mode) as tf:
                members = tf.getmembers()
                report.add("info", "TAR 内容",
                           "\n".join(f"{m.name} 大小={m.size}" for m in members)[:4000])
                exdir = os.path.join(outdir, "extracted")
                tf.extractall(exdir, filter="data")
                for m in members:
                    fp = os.path.join(exdir, m.name)
                    if os.path.isfile(fp):
                        report.extracted.append(fp)
                report.add("ok", "TAR 已解压", exdir)
            return
        except Exception as e:
            report.add("warn", "TAR 解压失败", str(e))

    # 单层压缩
    for ext, opener in ((".gz", gzip.open), (".bz2", bz2.open), (".xz", lzma.open)):
        if name.endswith(ext) or ftype.startswith(("GZIP", "BZIP", "XZ")):
            try:
                with opener(path, "rb") as f:
                    data = f.read()
                inner = os.path.splitext(os.path.basename(path))[0] or "decompressed.bin"
                fp = os.path.join(outdir, inner)
                with open(fp, "wb") as f:
                    f.write(data)
                report.add("ok", f"已解压 {ext}", fp)
                report.extracted.append(fp)
                return
            except Exception as e:
                report.add("warn", f"{ext} 解压失败", str(e))

    # RAR / 7z / 其他 → 7z
    sz = _sevenz()
    if sz:
        # 先判断是否加密
        r = subprocess.run([sz, "l", "-slt", path], capture_output=True, timeout=60)
        txt = r.stdout.decode("utf-8", "replace") + r.stderr.decode("utf-8", "replace")
        if "Encrypted = +" in txt or "Headers Encrypted = +" in txt:
            report.add("warn", "压缩包已加密(7z/RAR)", "尝试弱口令…")
            ok, pwd, exdir = _crack_7z(path, outdir)
            if ok:
                report.add("ok", f"密码命中: {pwd}", exdir)
                for root, _, files in os.walk(exdir):
                    for fn in files:
                        report.extracted.append(os.path.join(root, fn))
            else:
                report.add("warn", "弱口令未命中", "请在界面挂载大字典继续爆破")
        else:
            exdir = os.path.join(outdir, "extracted")
            os.makedirs(exdir, exist_ok=True)
            r = subprocess.run([sz, "x", path, "-y", f"-o{exdir}"],
                               capture_output=True, timeout=300)
            if r.returncode == 0:
                for root, _, files in os.walk(exdir):
                    for fn in files:
                        report.extracted.append(os.path.join(root, fn))
                report.add("ok", "已通过 7-Zip 解压", exdir)
            else:
                report.add("warn", "7-Zip 解压失败", (r.stderr or r.stdout).decode("utf-8", "replace")[:500])
    else:
        report.add("warn", "未找到 7-Zip",
                   "请在「工具中心」下载便携 7-Zip，以支持 RAR/7z/加密压缩包")
