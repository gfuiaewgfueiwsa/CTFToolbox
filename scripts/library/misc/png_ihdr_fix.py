# -*- coding: utf-8 -*-
# 脚本名称: PNG 宽高篡改修复（IHDR CRC 爆破真实尺寸）
# 方向: Misc（图片隐写 / 修复）
# 简介: 题目常把 PNG 的 IHDR 中宽度或高度改小/改 0，导致画面被截断或无法打开。
#       本脚本根据 IHDR 的 CRC 校验值爆破出原始宽高（也可只固定宽度爆破高度），
#       并自动修复 CRC 输出新图片；顺带修复普通 CRC 损坏。
# 用法:
#   python png_ihdr_fix.py broken.png                 # 全自动爆破宽高
#   python png_ihdr_fix.py broken.png --width 800     # 已知宽度，只爆高度
#   python png_ihdr_fix.py --selftest
# 依赖: 仅标准库（zlib）
# 参考: https://ctf-wiki.org/misc/lsb/png/
import argparse
import os
import struct
import zlib


def parse_ihdr(data):
    assert data[:8] == b"\x89PNG\r\n\x1a\n", "不是 PNG 文件"
    length = struct.unpack(">I", data[8:12])[0]
    ctype = data[12:16]
    assert ctype == b"IHDR"
    body = data[16:16 + length]
    crc_stored = struct.unpack(">I", data[16 + length:20 + length])[0]
    w, h = struct.unpack(">II", body[:8])
    return length, body, crc_stored, w, h


def brute(data, fixed_w=None, limit=20000):
    length, body, crc, w0, h0 = parse_ihdr(data)
    rest = body[8:]
    found = []
    if fixed_w:
        cand = ((fixed_w, hh) for hh in range(1, limit))
    else:
        # 常见情形只改高度；先爆高度，再爆宽度，避免双重循环过大
        cand = itertools_wh(w0, limit)
    for w, h in cand:
        nb = struct.pack(">II", w, h) + rest
        if zlib.crc32(b"IHDR" + nb) & 0xffffffff == crc:
            found.append((w, h))
            if fixed_w or w != w0 or h != h0:
                return w, h
    return (found[0] if found else None)


def itertools_wh(w0, limit):
    # 先以当前宽度枚举高度（最常见），再枚举宽度配合原高度
    for hh in range(1, limit):
        yield w0, hh
    for ww in range(1, limit):
        yield ww, w0


def fix(path, fixed_w=None):
    data = open(path, "rb").read()
    length, body, crc, w0, h0 = parse_ihdr(data)
    print(f"[*] 当前 IHDR: {w0} x {h0}, CRC={crc:08x}")
    r = brute(data, fixed_w)
    if not r:
        print("[-] 未爆破到匹配 CRC 的宽高（可加大范围或检查是否被多重篡改）")
        return
    w, h = r
    print(f"[+] 原始尺寸: {w} x {h}")
    nb = struct.pack(">II", w, h) + body[8:]
    new = data[:16] + nb + data[16 + length:]
    out = os.path.splitext(path)[0] + "_fixed.png"
    open(out, "wb").write(new)
    print("[+] 已修复并保存:", out)


def selftest():
    # 手工构造一个最小合法 PNG 再篡改高度
    import zlib as z
    w, h = 64, 48
    raw = b"".join(b"\x00" + b"\x2a\x7d\x3a" * w for _ in range(h))
    comp = z.compress(raw)

    def chunk(typ, payload):
        c = struct.pack(">I", len(payload)) + typ + payload
        return c + struct.pack(">I", z.crc32(typ + payload) & 0xffffffff)

    ihdr_body = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr_body) + chunk(b"IDAT", comp) + chunk(b"IEND", b"")
    # 篡改高度为 10
    bad = png[:16 + 4] + struct.pack(">I", 10) + png[24:]
    p = os.path.join(os.environ.get("TEMP", "."), "ihdr_bad.png")
    open(p, "wb").write(bad)
    r = brute(bad, fixed_w=w)
    assert r == (w, h), r
    print("[+] selftest OK, 还原", r)


def main():
    ap = argparse.ArgumentParser(description="PNG IHDR 宽高修复")
    ap.add_argument("png", nargs="?")
    ap.add_argument("--width", type=int)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.png:
        print("[!] 用法: python png_ihdr_fix.py broken.png"); return
    fix(a.png, a.width)


if __name__ == "__main__":
    main()
