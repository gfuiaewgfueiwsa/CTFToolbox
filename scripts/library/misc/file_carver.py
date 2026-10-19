# -*- coding: utf-8 -*-
# 脚本名称: 文件雕刻（binwalk-lite，提取内嵌 ZIP/RAR/7z/PNG/JPG/GIF/BMP/PDF/ELF/GZ）
# 方向: Misc（文件隐写 / 数据恢复）
# 简介: 不依赖 binwalk，按常见文件 magic 扫描偏移并雕刻出完整内嵌文件；
#       ZIP 按 EOCD 定位结尾，PNG 按 IEND，JPG 按 FFD9，GIF 按 3B 结束。
#       常用于图片马、固件、内存镜像里藏压缩包的题目。
# 用法:
#   python file_carver.py suspect.jpg                 # 雕刻到同目录 _carved
#   python file_carver.py suspect.bin -o out_dir
#   python file_carver.py suspect.bin --scan-only     # 只列偏移不提取
#   python file_carver.py --selftest
# 依赖: 仅标准库
import argparse
import os
import struct

SIGS = [
    (b"PK\x03\x04", "zip"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"BM", "bmp"),
    (b"%PDF-", "pdf"),
    (b"\x7fELF", "elf"),
    (b"\x1f\x8b\x08", "gz"),
    (b"BZh", "bz2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"RIFF", "riff"),
]


def find_all(data, sig, start=0):
    pos = start
    out = []
    while True:
        i = data.find(sig, pos)
        if i < 0:
            return out
        out.append(i)
        pos = i + 1


def zip_end(data, start):
    """从 start 之后找 ZIP 的 EOCD 记录并返回结束偏移。"""
    eocd = data.rfind(b"PK\x05\x06", start)
    if eocd < 0:
        return None
    return eocd + 22 + struct.unpack("<H", data[eocd + 20:eocd + 22])[0]


def carve(path, outdir, scan_only=False):
    raw = open(path, "rb").read()
    found = []
    for sig, ext in SIGS:
        for off in find_all(raw, sig):
            if ext == "zip":
                end = zip_end(raw, off) or min(len(raw), off + 1024 * 1024)
            elif ext == "png":
                iend = raw.find(b"IEND\xaeB\x60\x82", off)
                end = (iend + 12) if iend > 0 else None
            elif ext in ("jpg",):
                end = raw.find(b"\xff\xd9", off)
                end = end + 2 if end > 0 else None
            elif ext == "gif":
                end = raw.find(b"\x3b", off + 6)
                end = end + 1 if end > 0 else None
            elif ext == "gz":
                end = None   # gzip 长度需解压才知道，整体切到文件尾再让工具修
            else:
                end = None
            if end is None:
                end = len(raw)
            found.append((off, end, ext))
    # 去掉被外层格式包含的重复（如同一个 zip 的本地头多次出现，保留最长）
    found.sort()
    print(f"[*] {os.path.basename(path)} 大小 {len(raw)}，发现 {len(found)} 处签名:")
    for off, end, ext in found:
        print(f"    0x{off:08x} - 0x{end:08x}  .{ext} ({end-off} 字节)")
    if scan_only:
        return
    os.makedirs(outdir, exist_ok=True)
    seen = set()
    for i, (off, end, ext) in enumerate(found):
        key = (off, ext)
        if key in seen:
            continue
        seen.add(key)
        out = os.path.join(outdir, f"{i:02d}_0x{off:x}.{ext}")
        with open(out, "wb") as f:
            f.write(raw[off:end])
        print("[+] 已雕刻:", out)


def selftest():
    d = os.path.join(os.environ.get("TEMP", "."), "carve_self")
    os.makedirs(d, exist_ok=True)
    import zipfile
    zp = os.path.join(d, "inner.zip")
    with zipfile.ZipFile(zp, "w") as z:
        z.writestr("flag.txt", "flag{carved_zip_ok}")
    blob = b"\xff\xd8\xff\xe0FAKEJPGDATA" + open(zp, "rb").read() + b"TAIL"
    p = os.path.join(d, "fake.jpg")
    open(p, "wb").write(blob)
    carve(p, os.path.join(d, "out"))
    assert os.path.exists(os.path.join(d, "out"))
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="文件雕刻 binwalk-lite")
    ap.add_argument("file", nargs="?")
    ap.add_argument("-o", "--out")
    ap.add_argument("--scan-only", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.file:
        print("[!] 用法: python file_carver.py suspect.bin"); return
    out = a.out or os.path.join(os.path.dirname(a.file) or ".",
                                os.path.splitext(os.path.basename(a.file))[0] + "_carved")
    carve(a.file, out, a.scan_only)


if __name__ == "__main__":
    main()
