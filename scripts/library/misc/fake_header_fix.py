# -*- coding: utf-8 -*-
# 脚本名称: 文件头（Magic）修复 / 垃圾头剥离
# 方向: Misc（文件修复）
# 简介: 题目常把文件头删掉、改掉或在前面加垃圾数据导致打不开。本脚本内置常见
#       文件 magic 表，自动在文件头部搜索真实 magic，剥离垃圾头并补齐缺失头，
#       输出修复副本；ZIP 伪加密标志位也会一并清除。
# 用法:
#   python fake_header_fix.py broken.bin
#   python fake_header_fix.py broken.png --type png     # 强制类型
#   python fake_header_fix.py --selftest
# 依赖: 仅标准库
import argparse
import os
import struct

MAGICS = [
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"BM", "bmp"),
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),     # 只有 EOCD
    (b"Rar!\x1a\x07\x00", "rar"),
    (b"Rar!\x1a\x07\x01\x00", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"%PDF-", "pdf"),
    (b"\x7fELF", "elf"),
    (b"MZ", "exe"),
    (b"ID3", "mp3"),
    (b"\xff\xfb", "mp3"),
    (b"fLaC", "flac"),
    (b"OggS", "ogg"),
    (b"RIFF", "wav/avi"),
    (b"flag{", "text"),
    (b"SQLite format 3\x00", "sqlite"),
    (b"regf", "registry hive"),
    (b"ElfFile\x00", "evtx"),
]


def fix(path, force=None):
    raw = open(path, "rb").read()
    hits = []
    for magic, typ in MAGICS:
        if force and typ != force:
            continue
        idx = raw.find(magic)
        if 0 <= idx <= 4096:        # 垃圾头通常很短
            hits.append((idx, magic, typ))
    hits.sort()
    if not hits:
        print("[-] 未在文件头 4KB 内发现已知 magic，可用 file/binwalk/010editor 人工判断")
        return
    idx, magic, typ = hits[0]
    print(f"[+] 在偏移 0x{idx:x} 发现 {typ} magic {magic!r}")
    body = raw[idx:]
    out = os.path.splitext(path)[0] + f"_fixed.{typ.split('/')[0]}"
    open(out, "wb").write(body)
    print("[+] 已剥离垃圾头 ->", out)
    if typ == "zip":
        clear_zip_encryption_bit(out)


def clear_zip_encryption_bit(path):
    raw = bytearray(open(path, "rb").read())
    fixed = 0
    for mark, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        pos = 0
        while True:
            i = raw.find(mark, pos)
            if i < 0:
                break
            if raw[i + off] & 1:
                raw[i + off] &= 0xFE
                fixed += 1
            pos = i + 4
    if fixed:
        open(path, "wb").write(bytes(raw))
        print(f"[+] 顺带清除 {fixed} 处 ZIP 加密标志位（伪加密）")


def selftest():
    d = os.path.join(os.environ.get("TEMP", "."), "hdr_self")
    os.makedirs(d, exist_ok=True)
    payload = b"\x89PNG\r\n\x1a\n_rest_of_png_data"
    p = os.path.join(d, "broken.bin")
    open(p, "wb").write(b"GARBAGEHEADER123" + payload)
    fix(p)
    out = os.path.join(d, "broken_fixed.png")
    assert open(out, "rb").read().startswith(b"\x89PNG")
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="文件头修复")
    ap.add_argument("file", nargs="?")
    ap.add_argument("--type")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.file:
        print("[!] 用法: python fake_header_fix.py broken.bin"); return
    fix(a.file, a.type)


if __name__ == "__main__":
    main()
