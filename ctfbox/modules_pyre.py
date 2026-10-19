# -*- coding: utf-8 -*-
"""Python / 打包类逆向：PyInstaller 解包、pyc 识别与反编译、Electron asar 解包、
PE 资源提取。纯 Python 实现解包，反编译优先调用工具中心的 pycdc。"""
import os
import re
import sys
import json
import struct
import subprocess

from .common import (
    Report, Finding, save_text, save_artifact, strings,
    scan_flags, safe_name, WORKSPACE,
)

PYINST_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"

# Python 字节码 magic（PyInstaller pyvers 字段形如 309=3.9、313=3.13）
PYC_MAGIC = {
    306: 3379, 307: 3394, 308: 3413, 309: 3425, 310: 3439,
    311: 3495, 312: 3531, 313: 3571, 314: 3613,
}


def pyc_version(magic_int: int):
    for v, m in PYC_MAGIC.items():
        if m == magic_int:
            return f"{v // 100}.{v % 100}"
    return None


# ============================================================================
# PyInstaller 解包（pyinstxtractor 等价实现）
# ============================================================================
def extract_pyinstaller(path: str, report: Report, out_dir: str = None):
    raw = open(path, "rb").read()
    pos = raw.rfind(PYINST_MAGIC)
    if pos < 0:
        report.add("info", "PyInstaller", "未发现 PyInstaller 归档魔数 MEI")
        return None
    # 新版 cookie: magic(8)+pkgLen(4)+tocOff(4)+tocLen(4)+pyvers(4)+pylib(64)=92
    # 旧版 cookie: 8+4+4+4+4 = 24
    tail = raw[pos:]
    pyvers = None
    if len(tail) >= 92:
        pkg_len, toc_off, toc_len, pyvers = struct.unpack("!IIII", tail[8:24])
        cookie_ok = (toc_len + toc_off) <= len(raw)
    else:
        cookie_ok = False
    if not cookie_ok:
        pkg_len, toc_off, toc_len, pyvers = struct.unpack("!IIII", tail[8:24])
    # toc_off/pkg_len 是相对包起始（cookie 位置 + 24 - pkg_len 为包基址，旧版）
    # pyinstxtractor: overlayPos = filesize - pkgLen; tocPos = overlayPos + tocOff
    overlay_pos = len(raw) - pkg_len
    toc_pos = overlay_pos + toc_off
    toc = raw[toc_pos:toc_pos + toc_len]
    out_dir = out_dir or os.path.join(WORKSPACE, "pyinst_" + safe_name(os.path.basename(path)))
    os.makedirs(out_dir, exist_ok=True)

    try:
        cur_magic = struct.unpack("<H", __import__("importlib.util", fromlist=["MAGIC_NUMBER"]).MAGIC_NUMBER[:2])[0]
    except Exception:
        cur_magic = PYC_MAGIC[313]
    magic_int = PYC_MAGIC.get(pyvers, cur_magic)
    pyc_header = struct.pack("<Hcc", magic_int, b"\r", b"\n") + b"\0" * 12

    entries, i = [], 0
    while i < len(toc):
        (entry_len, entry_off, data_len, uncomp_len, cflag, typecode) = struct.unpack(
            "!IIIIBc", toc[i:i + 18])
        name = toc[i + 18:i + entry_len].rstrip(b"\0").decode("utf-8", "replace")
        entries.append((entry_off, data_len, uncomp_len, cflag, typecode.decode("latin-1"), name))
        i += entry_len

    n_pyc = 0
    for entry_off, data_len, uncomp_len, cflag, tcode, name in entries:
        data = raw[overlay_pos + entry_off: overlay_pos + entry_off + data_len]
        if cflag:
            try:
                import zlib
                data = zlib.decompress(data)
            except Exception as e:
                report.add("warn", f"{name} 解压失败", str(e)[:100])
                continue
        # 脚本/模块/包 -> pyc
        if tcode in ("s", "m", "M"):
            if not data.startswith(b"\x0d\x0c") and not data[:4] == pyc_header[:4]:
                # 入口脚本缺 16 字节头
                data = pyc_header + data
            dst = os.path.join(out_dir, safe_name(name) + (".pyc" if not name.endswith(".pyc") else ""))
        elif tcode == "z":
            dst = os.path.join(out_dir, safe_name(name) + ".pyz")
        elif tcode in ("b", "x"):
            dst = os.path.join(out_dir, safe_name(os.path.basename(name)))
        else:
            dst = os.path.join(out_dir, safe_name(name) + "." + tcode)
        os.makedirs(os.path.dirname(dst) or out_dir, exist_ok=True)
        try:
            with open(dst, "wb") as f:
                f.write(data)
            if dst.endswith(".pyc"):
                n_pyc += 1
        except Exception:
            pass

    ver = pyc_version(magic_int) or f"magic {magic_int}"
    f = Finding("ok", "PyInstaller 解包完成",
                f"Python {ver}（cookie 字段 {pyvers}），{len(entries)} 个条目、{n_pyc} 个 pyc，"
                f"输出: {out_dir}\n下一步: 对关键 pyc（主脚本、业务模块）右键反编译", out_dir)
    flags = scan_flags(raw[overlay_pos:overlay_pos + min(len(raw) - overlay_pos, 50_000_000)])
    f.flags = flags
    report.add_item(f)
    report.add("info", "PyInstaller 逆向提示",
               "1) 入口脚本通常是同名 pyc（无包路径）；2) 业务逻辑在同包名目录下；"
               "3) 3.9+ 推荐 pycdc 反编译（工具中心），3.8 及以下可用 uncompyle6/decompyle3；"
               "4) PYZ 内模块可用 pyc_archive_viewer 思路继续解")
    return out_dir


def is_pyinstaller(raw: bytes) -> bool:
    return PYINST_MAGIC in raw[-4096:] or raw.rfind(PYINST_MAGIC) > len(raw) - 4096 if raw else False


# ============================================================================
# pyc 识别与反编译
# ============================================================================
def identify_pyc(path: str, report: Report):
    raw = open(path, "rb").read()
    if len(raw) < 16:
        return None
    magic_int = struct.unpack("<H", raw[:2])[0]
    ver = pyc_version(magic_int)
    if not ver:
        # 容差：当前运行版本
        try:
            cur = struct.unpack("<H", __import__("importlib.util", fromlist=["MAGIC_NUMBER"]).MAGIC_NUMBER[:2])[0]
            if magic_int == cur:
                ver = ".".join(map(str, sys.version_info[:2]))
        except Exception:
            pass
    if not ver:
        report.add("info", "pyc 识别", f"未知 magic 0x{magic_int:x}，可能为非常规 Python 版本")
        return None
    mtime = struct.unpack("<I", raw[8:12])[0]
    report.add("info", "pyc 信息", f"Python {ver}，magic={magic_int}，源文件 mtime 字段={mtime}")
    return ver


def decompile_pyc(path: str, report: Report, out_dir: str = None):
    ver = identify_pyc(path, report)
    out_dir = out_dir or os.path.join(WORKSPACE, "pyc_decompiled")
    os.makedirs(out_dir, exist_ok=True)
    dst = os.path.join(out_dir, safe_name(os.path.basename(path).replace(".pyc", "")) + ".py")

    # 1) pycdc（工具中心，支持新版本）
    from .toolsmgr import get_tool
    pycdc = get_tool("pycdc")
    if pycdc:
        r = subprocess.run([pycdc, path], capture_output=True, timeout=300,
                           errors="replace")
        code = r.stdout
        if code and len(code.strip()) > 10:
            with open(dst, "w", encoding="utf-8", errors="replace") as f:
                f.write(code)
            fnd = Finding("ok", "pycdc 反编译成功", f"输出: {dst}（Python {ver or '?'}）", dst)
            fnd.flags = scan_flags(code.encode("utf-8", "replace"))
            report.add_item(fnd)
            if r.stderr:
                report.add("info", "pycdc 警告", r.stderr[-300:])
            return dst
        report.add("warn", "pycdc 反编译失败", (r.stderr or "无输出")[-300:])

    # 2) uncompyle6 / decompyle3（仅 ≤3.8）
    for mod in ("decompyle3", "uncompyle6"):
        try:
            r = subprocess.run([sys.executable, "-m", mod, "-o", out_dir, path],
                               capture_output=True, text=True, errors="replace", timeout=300)
            if os.path.exists(dst):
                report.add("ok", f"{mod} 反编译成功", dst, dst)
                return dst
        except Exception:
            continue
    report.add("warn", "无可用反编译器",
               "建议在工具中心下载 pycdc（支持 3.9-3.13）；或 pip install decompyle3（≤3.8）。"
               "下面给出字节码反汇编（pycdas/dis）供人工分析")
    # 3) 兜底：dis 反汇编
    try:
        import dis, marshal, importlib.util
        raw = open(path, "rb").read()
        header = 16
        code_obj = marshal.loads(raw[header:])
        import io as _io
        buf = _io.StringIO()
        dis.dis(code_obj, file=buf)
        asm = os.path.join(out_dir, safe_name(os.path.basename(path)) + ".dis.txt")
        save_text(asm, buf.getvalue())
        report.add("info", "字节码反汇编", asm, asm)
        return asm
    except Exception as e:
        report.add("warn", "反汇编也失败", str(e)[:150])
    return None


# ============================================================================
# Electron app.asar 解包
# ============================================================================
def extract_asar(path: str, report: Report, out_dir: str = None):
    raw = open(path, "rb").read()
    if raw[4:8] != raw[8:12]:
        # asar: uint32(4) + pickleSize + headerSize + 0
        pass
    (p1, pickle_size, header_size, p4) = struct.unpack("<IIII", raw[:16])
    header_json = raw[16:16 + header_size].rstrip(b"\0")
    header = json.loads(header_json.decode("utf-8", "replace"))
    data_start = 8 + pickle_size
    out_dir = out_dir or os.path.join(WORKSPACE, "asar_" + safe_name(os.path.basename(path)))
    os.makedirs(out_dir, exist_ok=True)
    count = 0

    def walk(node, prefix):
        nonlocal count
        files = node.get("files", {})
        for name, meta in files.items():
            rel = os.path.join(prefix, name)
            if "files" in meta:
                walk(meta, rel)
            elif "offset" in meta:
                off = int(meta["offset"])
                size = int(meta["size"])
                dst = os.path.join(out_dir, rel.replace("/", os.sep))
                os.makedirs(os.path.dirname(dst) or out_dir, exist_ok=True)
                with open(dst, "wb") as f:
                    f.write(raw[data_start + off: data_start + off + size])
                count += 1

    walk(header, "")
    f = Finding("ok", "asar 解包完成", f"{count} 个文件 -> {out_dir}\n"
                "Electron 业务逻辑多在 resources/app 下的 .js / .node，搜索 flag、接口、密钥",
                out_dir)
    report.add_item(f)
    return out_dir


# ============================================================================
# PE 资源提取（图标/位图/清单/RCDATA/版本信息）
# ============================================================================
RT_NAMES = {1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG",
            6: "STRING", 7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR",
            10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR", 14: "GROUP_ICON",
            16: "VERSION", 20: "DLGINCLUDE", 24: "MANIFEST"}


def extract_pe_resources(path: str, report: Report, out_dir: str = None):
    import pefile
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        report.add("info", "PE 资源", "该文件没有资源目录")
        pe.close()
        return None
    out_dir = out_dir or os.path.join(WORKSPACE, "res_" + safe_name(os.path.basename(path)))
    os.makedirs(out_dir, exist_ok=True)
    n = 0
    for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        type_id = rtype.struct.Id
        tname = RT_NAMES.get(type_id, str(type_id))
        if not hasattr(rtype, "directory"):
            continue
        for rid in rtype.directory.entries:
            if not hasattr(rid, "directory"):
                continue
            for lang in rid.directory.entries:
                off = lang.data.struct.OffsetToData
                size = lang.data.struct.Size
                data = pe.get_data(off, size)
                rid_name = rid.struct.Id if rid.struct.Id is not None else getattr(rid, "name", "x")
                ext = ".bin"
                if tname in ("MANIFEST",):
                    ext = ".xml"
                elif tname == "VERSION":
                    ext = ".bin"
                elif tname == "BITMAP":
                    # RT_BITMAP 数据从 BITMAPINFOHEADER 开始，补 BMP 文件头
                    ext = ".bmp"
                    bfh = b"BM" + struct.pack("<IHHI", size + 14, 0, 0,
                                              14 + (struct.unpack("<I", data[10:14])[0]
                                                    if len(data) >= 14 else 0))
                    data = bfh + data
                elif tname == "ICON":
                    ext = ".ico_raw"
                dst = os.path.join(out_dir, f"{tname}_{rid_name}{ext}")
                with open(dst, "wb") as f:
                    f.write(data)
                n += 1
                flags = scan_flags(data)
                if flags or tname in ("MANIFEST", "RCDATA", "MESSAGETABLE"):
                    report.add("info", f"资源 {tname}/{rid_name} ({size}B)",
                               f"已导出 {dst}" + (f" 含 flag: {flags}" if flags else ""), dst)
    # 版本信息
    try:
        if hasattr(pe, "FileInfo"):
            for finfo in pe.FileInfo:
                for entry in finfo:
                    if hasattr(entry, "StringTable"):
                        for st in entry.StringTable:
                            for k, v in st.entries.items():
                                report.add("info", f"版本 {k.decode('latin-1')}",
                                           v.decode("utf-8", "replace"))
    except Exception:
        pass
    f = Finding("ok", "PE 资源提取完成", f"{n} 个资源对象 -> {out_dir}", out_dir)
    report.add_item(f)
    pe.close()
    return out_dir
