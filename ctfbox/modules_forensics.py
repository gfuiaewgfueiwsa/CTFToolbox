# -*- coding: utf-8 -*-
"""取证 / 隐写扩展：NTFS 数据流、vim swap、分片合并、图片马检测、PE 修复、
路由配置提取、磁盘镜像、DTMF 拨号音、注册表/事件日志、盲水印/隐写工具链等。

全部为通用技术实现，不内置任何具体题目数据。
"""
import os
import re
import sys
import wave
import shutil
import struct
import subprocess
from ctypes import (windll, byref, c_wchar, c_wchar_p, c_void_p, Structure,
                    c_ulonglong, c_ulong, WinError)

from .common import (
    Report, Finding, save_text, save_artifact, strings,
    scan_flags, file_hashes, safe_name, WORKSPACE, TOOLS_DIR,
)

FLAG_RE = re.compile(rb"(?:flag|ctf)\{[^\x00\r\n]{1,200}\}", re.I)


# ============================================================================
# NTFS 交换数据流（ADS）
# ============================================================================
class _WIN32_FIND_STREAM_DATA(Structure):
    _fields_ = [("StreamSize", c_ulonglong),
                ("StreamName", c_wchar * 296)]


def list_ads(path: str):
    """返回 [(流全名, 大小)]；仅 Windows NTFS 有效。"""
    out = []
    if not sys.platform.startswith("win"):
        return out
    try:
        FindFirstStreamW = windll.kernel32.FindFirstStreamW
        FindNextStreamW = windll.kernel32.FindNextStreamW
        FindFirstStreamW.restype = c_void_p
        FindFirstStreamW.argtypes = [c_wchar_p, c_ulong, c_void_p, c_ulong]
        FindNextStreamW.argtypes = [c_void_p, c_void_p]
        windll.kernel32.FindClose.argtypes = [c_void_p]
        data = _WIN32_FIND_STREAM_DATA()
        INVALID = c_void_p(-1).value
        h = FindFirstStreamW(c_wchar_p(path), 0, byref(data), 0)
        if not h or h == INVALID:
            return out
        try:
            while True:
                name = data.StreamName
                if name and not name.endswith("::$DATA"):
                    out.append((name, data.StreamSize))
                if not FindNextStreamW(h, byref(data)):
                    break
        finally:
            windll.kernel32.FindClose(h)
    except Exception:
        return out
    return out


def extract_ads(path: str, report: Report, out_dir: str = None):
    streams = list_ads(path)
    if not streams:
        report.add("info", "NTFS 数据流", "未发现附加数据流（非 NTFS 或无 ADS）")
        return
    out_dir = out_dir or os.path.join(WORKSPACE, "ads_" + safe_name(os.path.basename(path)))
    os.makedirs(out_dir, exist_ok=True)
    for name, size in streams:
        # name 形如 ":secret:$DATA"
        label = name.strip(":").replace(":$DATA", "").replace(":", "_") or "stream"
        dst = os.path.join(out_dir, safe_name(label))
        try:
            with open(path + name, "rb") as f:     # Windows 支持 文件名:流名
                data = f.read()
            with open(dst, "wb") as f:
                f.write(data)
            f = Finding("ok", f"NTFS 隐藏数据流 {name}",
                        f"大小 {len(data)} 字节，已导出: {dst}", dst)
            f.flags = scan_flags(data)
            report.add_item(f)
        except Exception as e:
            report.add("warn", f"数据流 {name} 读取失败", str(e)[:120])


# ============================================================================
# vim swap（.swp/.swo/.swn）恢复
# ============================================================================
def recover_vim_swap(path: str, report: Report, out_dir: str = None):
    raw = open(path, "rb").read()
    out_dir = out_dir or os.path.join(WORKSPACE, "swap_" + safe_name(os.path.basename(path)))
    os.makedirs(out_dir, exist_ok=True)
    # swap 头部块含文件名等信息，正文以块方式存放；先提取全部可打印行
    runs = strings(raw, 4)
    text = "\n".join(r for r in runs if re.search(r"[A-Za-z0-9\u4e00-\u9fff{}]", r))
    dst = os.path.join(out_dir, "recovered.txt")
    save_text(dst, text)
    flags = scan_flags(raw)
    f = Finding("ok", "vim swap 文本提取",
                f"从 {os.path.basename(path)} 提取可打印文本 {len(text)} 字: {dst}", dst)
    f.flags = flags
    report.add_item(f)
    # swap 头部中的原始文件名（b0: 文件名以 NUL 分隔，位于 0x27 附近的块0头部）
    m = re.search(rb"[\x20-\x7e]{0,40}?([^/\x00\\:*?\"<>|]{1,60}\.[A-Za-z0-9]{1,6})", raw[:4096])
    if m:
        report.add("info", "swap 记录的原文件名", m.group(1).decode("latin-1", "replace"))
    report.add("info", "完整恢复建议",
               "用 vim 自带恢复（保留原目录结构时最佳）: vim -r " + os.path.basename(path)
               + " ，然后 :w 保存；本工具导出的 recovered.txt 为应急提取")
    return dst


# ============================================================================
# 文件分片合并（.001/.002、_1/_2、out0/out1 等）
# ============================================================================
_NAT_RE = re.compile(r"(\d+)")


def natural_key(name: str):
    return [int(t) if t.isdigit() else t.lower() for t in _NAT_RE.split(name)]


def merge_fragments(files, out_path: str = None, report: Report = None):
    files = sorted(files, key=lambda p: natural_key(os.path.basename(p)))
    if out_path is None:
        os.makedirs(WORKSPACE, exist_ok=True)
        base = re.sub(r"[._-]?\d+$", "", os.path.splitext(os.path.basename(files[0]))[0])
        out_path = os.path.join(WORKSPACE, safe_name(base) + "_merged.bin")
    total = 0
    with open(out_path, "wb") as w:
        for p in files:
            b = open(p, "rb").read()
            w.write(b)
            total += len(b)
    head = open(out_path, "rb").read(16)
    from .identifier import identify
    kind = identify(head)
    msg = f"按序合并 {len(files)} 个分片，共 {total} 字节: {out_path}\n文件头: {kind}"
    if report:
        f = Finding("ok", "分片合并", msg, out_path)
        f.flags = scan_flags(head)
        report.add_item(f)
    else:
        print(msg)
    return out_path


def detect_fragment_dir(folder: str):
    """自动发现目录中成组的等大小/连续编号分片。"""
    files = [os.path.join(folder, f) for f in os.listdir(folder)
             if os.path.isfile(os.path.join(folder, f))]
    groups = {}
    for p in files:
        name = os.path.basename(p)
        stem, ext = os.path.splitext(name)
        # .001 / part1 / out0
        m = re.search(r"(\d+)$", ext.lstrip(".")) or re.search(r"(\d+)$", stem)
        if not m:
            continue
        key = (re.sub(r"\d+$", "#", stem), re.sub(r"\d+", "#", ext))
        groups.setdefault(key, []).append(p)
    result = []
    for key, lst in groups.items():
        if len(lst) >= 2:
            result.append(sorted(lst, key=lambda p: natural_key(os.path.basename(p))))
    return result


# ============================================================================
# 图片马 / 多态文件中的脚本代码检测（防御向本地静态扫描）
# ============================================================================
SHELL_SIGS = [
    (rb"<\?php", "PHP 代码 <?php"),
    (rb"<\?=", "PHP 短标签 <?="),
    (rb"<%[@\s]", "ASP/JSP 脚本块 <%"),
    (rb"<%@", "JSP/ASP 指令 <%@"),
    (rb"eval\s*\(", "eval() 动态执行"),
    (rb"assert\s*\(", "assert() 动态执行"),
    (rb"base64_decode\s*\(", "base64_decode 解码执行"),
    (rb"system\s*\(\s*\$_(GET|POST|REQUEST)", "命令执行后门(GET/POST)"),
    (rb"\$_(GET|POST|REQUEST|COOKIE)\s*\[", "Web 参数接收（可疑后门）"),
    (rb"ExecuteGlobal", "ASP 全局执行"),
    (rb"Runtime\.getRuntime", "Java 命令执行"),
    (rb"ProcessStartInfo", ".NET 进程启动"),
    (rb"powershell(?:\.exe)?\s+-e", "PowerShell 编码命令"),
    (rb"cmd\.exe\s*/c", "cmd 命令执行"),
    (rb"<script[^>]+runat\s*=\s*[\"']server", "服务端脚本块"),
]


_PHP_CODE = re.compile(rb"(<\?php|<%|eval\s*\(|assert\s*\(|base64_decode|\$_(GET|POST|REQUEST|COOKIE)"
                       rb"|include|require|system|exec|passthru|shell_exec|popen|@?\$\w+\s*=)", re.I)


def scan_polyglot(path: str, report: Report, out_dir: str = None):
    raw = open(path, "rb").read()
    ext = os.path.splitext(path)[1].lower()
    # 图片正常结束位置：JPEG FFD9 / PNG IEND / GIF 0x3B
    eof = -1
    if ext in (".jpg", ".jpeg"):
        eof = raw.rfind(b"\xff\xd9")
    elif ext == ".png":
        eof = raw.rfind(b"IEND\xaeB`\x82")
    elif ext == ".gif":
        eof = raw.rfind(b"\x3b")
    hits = []
    for sig, desc in SHELL_SIGS:
        for m in re.finditer(sig, raw, re.I):
            ctx_win = raw[m.start():m.start() + 200]
            after_eof = eof >= 0 and m.start() > eof
            # 图内命中必须伴随真实代码关键字，避免高熵图像数据误报
            has_code = bool(_PHP_CODE.search(ctx_win))
            if not after_eof and not has_code:
                continue
            ctx = raw[max(0, m.start() - 40):m.start() + 120]
            printable = "".join(chr(b) if 32 <= b < 127 else "." for b in ctx)
            hits.append((m.start(), ("[图尾]" if after_eof else "[图内]") + desc, printable))
    # 非图片（如 .jpg 但实际是 GIF89a+PHP）直接全量扫
    if not hits and raw[:6] in (b"GIF89a", b"GIF87a"):
        for sig, desc in SHELL_SIGS:
            for m in re.finditer(sig, raw, re.I):
                ctx = raw[max(0, m.start() - 20):m.start() + 120]
                hits.append((m.start(), desc,
                             "".join(chr(b) if 32 <= b < 127 else "." for b in ctx)))
    if not hits:
        report.add("info", "图片马/脚本扫描", "未在文件尾部/内容中发现脚本代码特征")
        return
    out_dir = out_dir or os.path.join(WORKSPACE, "polyglot_" + safe_name(os.path.basename(path)))
    os.makedirs(out_dir, exist_ok=True)
    # 导出首个脚本起始位置之后的数据
    first = min(h[0] for h in hits)
    if first > 0:
        tail = os.path.join(out_dir, "embedded_code.bin")
        open(tail, "wb").write(raw[first:])
    else:
        tail = None
    f = Finding("warn", f"发现图片马/嵌入脚本代码（{len(hits)} 处）",
                "命中: " + "; ".join(sorted({h[1] for h in hits})),
                tail)
    f.flags = scan_flags(raw[first:])
    report.add_item(f)
    for off, desc, ctx in hits[:12]:
        report.add("info", f"@0x{off:x} {desc}", ctx)
    report.add("info", "处置建议",
               "CTF 中常见为 copy /b 图片+脚本 合成的图片马；可用 binwalk/ foremost 分离，"
               "或直接用文本编辑器查看文件尾部。真实场景请勿上传至服务器执行。")


# ============================================================================
# PE 头修复（MZ/PE 签名被破坏，如 CyberPunk 类）
# ============================================================================
def repair_pe(path: str, report: Report, out_dir: str = None):
    raw = bytearray(open(path, "rb").read())
    out_dir = out_dir or os.path.join(WORKSPACE, "pe_repair")
    os.makedirs(out_dir, exist_ok=True)
    changes = []
    # 1) MZ 头
    if raw[:2] != b"MZ":
        raw[0:2] = b"MZ"
        changes.append("重建 DOS MZ 签名")
    # 2) 找 PE\0\0
    pe_off = struct.unpack("<I", bytes(raw[0x3C:0x40]))[0] if len(raw) >= 0x40 else 0
    found = -1
    for m in re.finditer(rb"PE\x00\x00", bytes(raw[:0x2000])):
        found = m.start()
        break
    if found >= 0:
        if pe_off != found or raw[found:found + 4] != b"PE\x00\x00":
            raw[found:found + 4] = b"PE\x00\x00"
            changes.append(f"重建 PE 签名 @0x{found:x}")
        if struct.unpack("<I", bytes(raw[0x3C:0x40]))[0] != found:
            raw[0x3C:0x40] = struct.pack("<I", found)
            changes.append(f"修正 e_lfanew 指向 0x{found:x}")
    else:
        report.add("warn", "未找到 PE\\0\\0", "无法仅靠签名修复，需在 010 Editor 中按节表手工重建")
        return None
    dst = os.path.join(out_dir, safe_name(os.path.basename(path)) + ".repaired.exe")
    open(dst, "wb").write(raw)
    # 验证 pefile 能否解析
    try:
        import pefile
        pe = pefile.PE(dst, fast_load=True)
        ok = f"pefile 解析成功，{len(pe.sections)} 个节，入口 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}"
        pe.parse_data_directories()
        ok_imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            ok_imports = [e.dll.decode("latin-1") for e in pe.DIRECTORY_ENTRY_IMPORT]
        report.add("ok", "PE 修复完成", "; ".join(changes) + "\n" + ok
                   + (f"\n导入表 DLL: {', '.join(ok_imports[:10])}" if ok_imports else ""), dst)
        pe.close()
    except Exception as e:
        report.add("warn", "PE 已写回但解析仍异常",
                   "; ".join(changes) + f"\n{str(e)[:150]}\n可继续用 010 Editor 检查节表", dst)
    return dst


# ============================================================================
# 路由器配置备份 conf.bin / 通用 zlib-gzip 流提取
# ============================================================================
def extract_embedded_streams(path: str, report: Report, out_dir: str = None):
    raw = open(path, "rb").read()
    out_dir = out_dir or os.path.join(WORKSPACE, "stream_" + safe_name(os.path.basename(path)))
    os.makedirs(out_dir, exist_ok=True)
    n = 0
    seen = set()
    # zlib 流
    for m in re.finditer(rb"\x78[\x01\x5e\x9c\xda]", raw):
        off = m.start()
        try:
            import zlib
            dec = zlib.decompressobj()
            data = dec.decompress(raw[off:])
            if len(data) >= 32 and (scan_flags(data) or sum(
                    1 for b in data if 9 <= b <= 13 or 32 <= b < 127) / len(data) > 0.7):
                h = data[:16]
                if h not in seen:
                    seen.add(h)
                    n += 1
                    dst = os.path.join(out_dir, f"zlib_{off:x}.bin")
                    open(dst, "wb").write(data)
                    f = Finding("ok", f"zlib 流 @0x{off:x}", f"解压出 {len(data)} 字节: {dst}", dst)
                    f.flags = scan_flags(data)
                    report.add_item(f)
        except Exception:
            continue
    # gzip 流
    for m in re.finditer(rb"\x1f\x8b\x08", raw):
        off = m.start()
        try:
            import gzip
            data = gzip.decompress(raw[off:off + 20 * 1024 * 1024])
            if len(data) >= 16:
                n += 1
                dst = os.path.join(out_dir, f"gzip_{off:x}.bin")
                open(dst, "wb").write(data)
                f = Finding("ok", f"gzip 流 @0x{off:x}", f"解压出 {len(data)} 字节: {dst}", dst)
                f.flags = scan_flags(data)
                report.add_item(f)
        except Exception:
            continue
    # 可打印字符串中的账号/口令/SSID/宽带字段
    interesting = []
    for s in strings(raw, 5):
        if re.search(r"(password|passwd|pwd|pppoe|ssid|wifi|wan|account|user|登录|口令|宽带|密钥|"
                     r"wireless|psk|auth|admin|telecomadmin|cuadmin|CMCCAdmin)", s, re.I):
            interesting.append(s)
    for s in interesting[:30]:
        report.add("info", "配置敏感字段", s[:200])
    if interesting:
        dst = os.path.join(out_dir, "config_strings.txt")
        save_text(dst, "\n".join(interesting))
        report.add("info", "敏感字段已汇总", dst, dst)
    if n == 0 and not interesting:
        report.add("info", "嵌入流提取", "未发现 zlib/gzip 流或敏感配置字段")
    else:
        report.add("info", "路由器配置提示",
                   "常见厂商配置备份可用 RouterPassView（工具中心有入口）查看 PPPoE/宽带口令、"
                   "无线 PSK；华为光猫常见超级账号 telecomadmin / 联通 cuadmin / 移动 CMCCAdmin")
    return out_dir


# ============================================================================
# VMDK 稀疏盘解析（纯 Python，支持未压缩 sparse extent）
# ============================================================================
VMDK_MAGIC = 0x564D444B  # "KDMV"


def parse_vmdk(path: str, out_raw: str = None, report: Report = None):
    raw = open(path, "rb").read()
    if len(raw) < 512 or struct.unpack("<I", raw[:4])[0] != VMDK_MAGIC:
        return None
    (version, flags) = struct.unpack("<II", raw[4:12])
    capacity, grain_size = struct.unpack("<QQ", raw[12:28])
    num_gtes = struct.unpack("<I", raw[44:48])[0]
    gd_off = struct.unpack("<Q", raw[56:64])[0] * 512
    if not num_gtes:
        num_gtes = 512
    grain_sectors = grain_size or 128
    total = capacity * 512
    out = bytearray(total)
    filled = 0
    #  grain directory: 每项 u32 指向 grain table（扇区）
    n_gd = (capacity + grain_sectors * num_gtes - 1) // (grain_sectors * num_gtes)
    for gde in range(n_gd):
        gt_sector = struct.unpack("<I", raw[gd_off + gde * 4: gd_off + gde * 4 + 4])[0]
        if gt_sector == 0 or (gt_sector & 0x80000000):
            continue
        gt_off = gt_sector * 512
        for gte_idx in range(num_gtes):
            p = gt_off + gte_idx * 4
            if p + 4 > len(raw):
                break
            grain_sector = struct.unpack("<I", raw[p:p + 4])[0]
            if grain_sector == 0 or (grain_sector & 0x80000000):
                continue
            gstart = (gde * num_gtes + gte_idx) * grain_sectors * 512
            glen = min(grain_sectors * 512, total - gstart)
            data = raw[grain_sector * 512: grain_sector * 512 + glen]
            if data:
                out[gstart:gstart + len(data)] = data
                filled += len(data)
    if report:
        report.add("info", "VMDK 解析",
                   f"version={version} flags=0x{flags:x} 虚拟容量={total // 1024}KB "
                   f"实际数据={filled // 1024}KB")
    if out_raw:
        with open(out_raw, "wb") as f:
            f.write(out)
    return bytes(out)


# ============================================================================
# 磁盘镜像（vmdk/vhd/ova/...）：VMDK 先转 raw，再交 7-Zip/雕刻/flag 扫描
# ============================================================================
def extract_disk_image(path: str, report: Report, out_dir: str = None):
    out_dir = out_dir or os.path.join(WORKSPACE, "disk_" + safe_name(os.path.basename(path)))
    os.makedirs(out_dir, exist_ok=True)
    target = path
    # VMDK 先纯 Python 展平为 raw
    try:
        head = open(path, "rb").read(512)
        if len(head) >= 4 and struct.unpack("<I", head[:4])[0] == VMDK_MAGIC:
            raw_path = os.path.join(out_dir, "disk_flat.img")
            img = parse_vmdk(path, raw_path, report)
            if img:
                target = raw_path
                report.add("ok", "VMDK 已展平为原始磁盘镜像", raw_path, raw_path)
    except Exception as e:
        report.add("warn", "VMDK 展平失败", str(e)[:150])

    from .toolsmgr import get_tool
    sz = get_tool("7z")
    extracted = False
    if sz:
        r = subprocess.run([sz, "x", "-y", f"-o{out_dir}", target],
                           capture_output=True, text=True, errors="replace", timeout=1800)
        if r.returncode == 0 and any(f != os.path.basename(target) for f in os.listdir(out_dir)):
            extracted = True
        elif r.returncode != 0:
            report.add("info", "7-Zip 提示", (r.stderr or r.stdout)[-200:])
    # raw 镜像直接 flag 扫描 + 内部雕刻
    if target != path or os.path.exists(target):
        img = open(target, "rb").read() if os.path.exists(target) else b""
        flags = scan_flags(img[:200_000_000])
        for fl in flags:
            report.add("flag", "磁盘镜像中发现 flag", fl)
        try:
            from .modules_carve import scan_and_carve
            sub = Report(target)
            scan_and_carve(target, sub, out_dir, carve=True, depth=1)
            for fnd in sub.findings:
                report.add(fnd.level, "[雕刻] " + fnd.title, fnd.detail, fnd.data)
            if sub.extracted:
                extracted = True
        except Exception as e:
            report.add("info", "磁盘雕刻跳过", str(e)[:100])
    files = []
    for root, _, fs in os.walk(out_dir):
        files.extend(os.path.join(root, f) for f in fs)
    if files:
        f = Finding("ok", "磁盘镜像处理完成",
                    f"{os.path.basename(path)} -> {out_dir}\n共 {len(files)} 个产物", out_dir)
        report.add_item(f)
    elif not extracted:
        report.add("warn", "磁盘镜像",
                   "未提取出文件：7za 精简版不支持 VMDK/ext，请在工具中心补装完整版 7z.exe，"
                   "或用 010 Editor/FTK Imager 挂载后再分析")
    return out_dir


# ============================================================================
# DTMF 拨号音解码（Goertzel）
# ============================================================================
_DTMF_ROW = [697, 770, 852, 941]
_DTMF_COL = [1209, 1336, 1477, 1633]
_DTMF_KEYS = [["1", "2", "3", "A"], ["4", "5", "6", "B"],
              ["7", "8", "9", "C"], ["*", "0", "#", "D"]]


def _goertzel(samples, sr, freq):
    n = len(samples)
    k = int(0.5 + n * freq / sr)
    w = 2 * 3.141592653589793 * k / n
    coeff = 2 * __import__("math").cos(w)
    s_prev = s_prev2 = 0.0
    for x in samples:
        s = x + coeff * s_prev - s_prev2
        s_prev2 = s_prev
        s_prev = s
    return s_prev2 ** 2 + s_prev ** 2 - coeff * s_prev2 * s_prev


def dtmf_decode_wav(path: str, report: Report = None):
    import numpy as np
    w = wave.open(path, "rb")
    sr, ch, sw = w.getframerate(), w.getnchannels(), w.getsampwidth()
    n = w.getnframes()
    raw = w.readframes(n)
    w.close()
    if sw == 1:
        data = (np.frombuffer(raw, dtype=np.uint8).astype(np.float32) - 128)
    elif sw == 2:
        data = np.frombuffer(raw, dtype="<i2").astype(np.float32)
    elif sw == 4:
        data = np.frombuffer(raw, dtype="<i4").astype(np.float32)
    else:
        raise ValueError(f"不支持的采样宽度 {sw}")
    if ch > 1:
        data = data.reshape(-1, ch)[:, 0]
    # 归一化
    mx = np.abs(data).max() or 1.0
    data = data / mx
    win = int(sr * 0.04)
    hop = int(sr * 0.02)
    digits, last, silence = [], None, 0
    for st in range(0, len(data) - win, hop):
        seg = data[st:st + win]
        rp = [_goertzel(seg, sr, f) for f in _DTMF_ROW]
        cp = [_goertzel(seg, sr, f) for f in _DTMF_COL]
        ri, ci = int(np.argmax(rp)), int(np.argmax(cp))
        power = np.sum(seg ** 2) / win
        if power > 0.0008 and rp[ri] > np.mean(rp) * 3 and cp[ci] > np.mean(cp) * 3:
            d = _DTMF_KEYS[ri][ci]
            if d != last:
                digits.append(d)
            last = d
            silence = 0
        else:
            silence += 1
            if silence > 3:
                last = None
    number = "".join(digits)
    if report:
        report.add("ok" if number else "warn", "DTMF 拨号音解码",
                   f"号码序列: {number or '（未检出，检查是否为拨号录音/阈值）'}\n采样率 {sr}Hz")
        if number:
            dst = os.path.join(WORKSPACE, "dtmf_result.txt")
            save_text(dst, number)
            report.add("info", "结果已保存", dst, dst)
    return number


# ============================================================================
# DeepSound / 常见音频隐写特征
# ============================================================================
def audio_stego_signatures(path: str, report: Report):
    raw = open(path, "rb").read()
    if b"DeepSound" in raw:
        off = raw.find(b"DeepSound")
        report.add("warn", "DeepSound 痕迹",
                   f"@0x{off:x} 出现 DeepSound 签名，该音频可能由 DeepSound 写入隐藏数据，"
                   "需 Windows 下 DeepSound 工具提取（工具中心有入口），可能带口令")
    if b"mp3stego" in raw.lower() or raw[-128:-1].count(b"\x00") > 100:
        report.add("info", "MP3Stego 提示",
                   "若为 MP3 且频谱/LSB 无果，尝试 MP3Stego（Decode 模式，需口令，空口令先试）")
    # WAV 尾部附加数据
    try:
        w = wave.open(path, "rb")
        audio_len = w.getnframes() * w.getnchannels() * w.getsampwidth() + 44
        w.close()
        if len(raw) > audio_len + 64:
            tail = raw[audio_len:]
            if len(tail.strip(b"\x00")) > 32:
                report.add("warn", "WAV 尾部附加数据",
                           f"音频数据结束后还有 {len(raw) - audio_len} 字节，可能藏文件，"
                           "建议 binwalk/自动雕刻")
    except Exception:
        pass


# ============================================================================
# steghide / outguess / stegseek / MP3Stego 自动链（外部工具在 tools 目录时）
# ============================================================================
def steghide_chain(path: str, report: Report, passwords=None, out_dir: str = None):
    """对 jpg/jpeg/wav/bmp/au 尝试 steghide 空口令与弱口令提取。"""
    from .toolsmgr import get_tool
    from .modules_text import WEAK_PASSWORDS
    exe = get_tool("steghide")
    if not exe:
        report.add("info", "steghide 未安装",
                   "JPEG/WAV 的 steghide 隐写需 steghide.exe；可在工具中心一键下载，"
                   "或 Kali: steghide extract -sf 文件 -p 口令")
        return False
    out_dir = out_dir or os.path.join(WORKSPACE, "steghide_" + safe_name(os.path.basename(path)))
    os.makedirs(out_dir, exist_ok=True)
    pws = [""] + (passwords or []) + WEAK_PASSWORDS[:60]
    seen = set()
    for pwd in pws:
        if pwd in seen:
            continue
        seen.add(pwd)
        xf = os.path.join(out_dir, f"out_{len(seen)}.bin")
        r = subprocess.run([exe, "extract", "-sf", path, "-p", pwd, "-xf", xf, "-f"],
                           capture_output=True, text=True, errors="replace", timeout=120)
        if r.returncode == 0 and os.path.exists(xf) and os.path.getsize(xf) > 0:
            data = open(xf, "rb").read()
            f = Finding("ok", f"steghide 提取成功（口令 {pwd!r}）",
                        f"隐藏数据 {len(data)} 字节: {xf}", xf)
            f.flags = scan_flags(data)
            report.add_item(f)
            return True
    report.add("info", "steghide 链结束", "空口令与内置弱口令均未提取出数据")
    return False


# ============================================================================
# 注册表 hive 分析（python-registry，离线）
# ============================================================================
def analyze_registry_hive(path: str, report: Report, out_dir: str = None):
    try:
        from Registry import Registry
    except ImportError:
        report.add("warn", "缺少 python-registry",
                   "注册表 hive 解析需要该库（打包版已内置；源码运行: pip install python-registry）")
        return
    out_dir = out_dir or os.path.join(WORKSPACE, "reg_" + safe_name(os.path.basename(path)))
    os.makedirs(out_dir, exist_ok=True)
    reg = Registry.Registry(path)
    root = reg.root().name().upper()
    hive_name = os.path.basename(path).upper()
    report.add("info", "注册表 hive", f"根键: {root}")

    def values_at(key_path):
        try:
            k = reg.open(key_path)
            return [(v.name(), v.value()) for v in k.values()]
        except Exception:
            return []

    dump_lines = []
    # 通用：递归收集 Run / 自启 / 浏览器 URL / 最近文档等
    wanted_patterns = re.compile(
        r"(Run|RunOnce|TypedURLs|TypedPaths|RecentDocs|WinRAR|7-Zip|Notepad|Recent|MountPoints)",
        re.I)
    if "SOFTWARE" in root or hive_name == "SOFTWARE" or "SOFTWARE" in hive_name:
        for sub in (r"Microsoft\Windows\CurrentVersion\Uninstall",):
            try:
                k = reg.open(sub)
                progs = []
                for sk in k.subkeys():
                    name = disp = ver = ""
                    for v in sk.values():
                        if v.name() == "DisplayName":
                            disp = str(v.value())
                        if v.name() == "DisplayVersion":
                            ver = str(v.value())
                    if disp:
                        progs.append(f"{disp} {ver}".strip())
                if progs:
                    report.add("info", "已安装软件", f"{len(progs)} 个: " + "; ".join(progs[:40]))
                    dump_lines += ["[已安装软件]"] + progs
            except Exception:
                pass
        for p in (r"Microsoft\Windows\CurrentVersion\Run",):
            vals = values_at(p)
            for n, v in vals:
                report.add("warn", f"开机自启 {n}", str(v)[:200])
                dump_lines.append(f"[Run] {n} = {v}")
        vals = values_at(r"Microsoft\Windows NT\CurrentVersion")
        for n, v in vals:
            if n in ("ProductName", "ReleaseId", "CurrentBuild", "RegisteredOwner",
                     "RegisteredOrganization", "InstallDate"):
                report.add("info", f"系统 {n}", str(v))
    if "SYSTEM" in root or hive_name == "SYSTEM" or "SYSTEM" in hive_name:
        vals = values_at(r"ControlSet001\Control\ComputerName\ComputerName")
        for n, v in vals:
            if n == "ComputerName":
                report.add("info", "计算机名", str(v))
    if "NTUSER" in hive_name or root.endswith("NTUSER.DAT"):
        for p, label in ((r"Software\Microsoft\Internet Explorer\TypedURLs", "IE 历史 URL"),
                         (r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
                          "资源管理器路径")):
            for n, v in values_at(p):
                report.add("info", label, str(v)[:300])
                dump_lines.append(f"[{label}] {v}")
    if "SAM" in hive_name or root.endswith("\\SAM"):
        try:
            k = reg.open(r"SAM\Domains\Account\Users\Names")
            names = [sk.name() for sk in k.subkeys()]
            report.add("info", "SAM 本地用户", ", ".join(names))
            dump_lines.append("[用户] " + ", ".join(names))
        except Exception:
            pass
    # 全 hive 字符串 flag 扫描
    all_strings = []

    def walk(key, depth=0):
        if depth > 12:
            return
        for v in key.values():
            try:
                val = v.value()
                if isinstance(val, bytes):
                    all_strings.extend(strings(val, 5))
                else:
                    all_strings.append(str(val))
            except Exception:
                pass
        for sk in key.subkeys():
            try:
                walk(sk, depth + 1)
            except Exception:
                pass

    try:
        walk(reg.root())
    except Exception:
        pass
    flags = scan_flags("\n".join(all_strings).encode("utf-8", "replace"))
    if flags:
        report.add("ok", "hive 中发现 flag", "\n".join(flags))
    if dump_lines:
        dst = os.path.join(out_dir, "registry_summary.txt")
        save_text(dst, "\n".join(dump_lines))
        report.add("info", "摘要已导出", dst, dst)


# ============================================================================
# Windows 事件日志 evtx
# ============================================================================
def analyze_evtx(path: str, report: Report, out_dir: str = None):
    try:
        from Evtx.Evtx import Evtx
    except ImportError:
        report.add("warn", "缺少 python-evtx", "pip install python-evtx 后重试")
        return
    out_dir = out_dir or os.path.join(WORKSPACE, "evtx_" + safe_name(os.path.basename(path)))
    os.makedirs(out_dir, exist_ok=True)
    counts, logons, total = {}, [], 0
    import xml.etree.ElementTree as ET
    with Evtx(path) as log:
        for rec in log.records():
            total += 1
            try:
                root = ET.fromstring(rec.xml())
                eid = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}EventID")
                eid = eid.text if eid is not None else "?"
                counts[eid] = counts.get(eid, 0) + 1
                if eid in ("4624", "4625"):
                    data = {d.get("Name"): d.text for d in root.iter(
                        "{http://schemas.microsoft.com/win/2004/08/events/event}Data")}
                    logons.append(f"{eid} 目标用户={data.get('TargetUserName')} "
                                  f"来源IP={data.get('IpAddress')} 类型={data.get('LogonType')}")
            except Exception:
                continue
    report.add("info", "事件统计", f"共 {total} 条; " +
               ", ".join(f"ID {k}:{v}" for k, v in sorted(counts.items(),
                                                          key=lambda x: -x[1])[:12]))
    for line in logons[:40]:
        report.add("info", "登录事件", line)
    fail = counts.get("4625", 0)
    if fail:
        report.add("warn", "登录失败", f"{fail} 次 4625，可能存在暴力破解")
    dst = os.path.join(out_dir, "logons.txt")
    save_text(dst, "\n".join(logons))
    report.add("info", "登录事件已导出", dst, dst)


# ============================================================================
# 盲水印（blind-watermark 库，pip 通道，best-effort）
# ============================================================================
def blind_watermark_decode(path: str, wm_shape=(64, 64), out_path: str = None, report: Report = None):
    try:
        from blind_watermark import WaterMark
    except ImportError:
        if report:
            report.add("warn", "缺少 blind-watermark",
                       "频域盲水印解码需要该库: pip install blind-watermark opencv-python-headless")
        return None
    bwm = WaterMark(password_wm=1, password_img=1)
    out_path = out_path or os.path.join(WORKSPACE, "watermark_extracted.png")
    wm = bwm.extract(filename=path, wm_shape=wm_shape, out_wm_name=out_path)
    if report:
        report.add("ok", "盲水印提取", f"按形状 {wm_shape} 提取: {out_path}", out_path)
    return out_path
