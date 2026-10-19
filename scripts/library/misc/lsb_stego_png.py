# -*- coding: utf-8 -*-
# 脚本名称: PNG/BMP LSB 隐写提取（最低位平面，含通道/位序组合）
# 方向: Misc（图片隐写）
# 简介: 自动枚举 RGB/RGBA 各通道、位平面(0-3)、MSB/LSB 优先、按行/按列等组合，
#       提取最低位比特流并尝试还原为 ASCII/UTF-8 文本，命中 flag 特征直接高亮；
#       同时把位平面图导出为 PNG 便于肉眼观察。
# 用法:
#   python lsb_stego_png.py stego.png
#   python lsb_stego_png.py stego.png --channel R --bit 0 --order msb
#   python lsb_stego_png.py --selftest
# 依赖: pip install pillow
# 参考: https://ctf-wiki.org/misc/lsb/
import argparse
import itertools
import os
import string
from PIL import Image

FLAG_HINTS = ("flag", "ctf", "key", "secret", "FLAG", "CTF")


def bits_to_bytes(bits, msb_first=True):
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        b = bits[i:i + 8]
        v = 0
        if msb_first:
            for x in b:
                v = (v << 1) | x
        else:
            for j, x in enumerate(b):
                v |= x << j
        out.append(v)
    return bytes(out)


def readable_ratio(b):
    if not b:
        return 0
    ok = sum(1 for x in b if 9 <= x <= 13 or 32 <= x < 127)
    return ok / len(b)


def extract(img, channel_idx, bit, msb_first, column=False):
    px = list(img.getdata())
    seq = []
    if column:
        w, h = img.size
        px2 = [img.getpixel((x, y)) for x in range(w) for y in range(h)]
        src = px2
    else:
        src = px
    for p in src:
        if channel_idx < len(p):
            seq.append((p[channel_idx] >> bit) & 1)
    return bits_to_bytes(seq, msb_first)


def analyze(path):
    img = Image.open(path).convert("RGBA")
    names = "RGBA"
    results = []
    for ci, cn in enumerate(names):
        for bit in range(4):
            for msb in (True, False):
                for col in (False, True):
                    data = extract(img, ci, bit, msb, col)
                    score = readable_ratio(data[:2000])
                    results.append((score, cn, bit, "MSB" if msb else "LSB", "列" if col else "行", data))
    results.sort(key=lambda x: x[0], reverse=True)
    print(f"[*] 图像 {img.size}, 共 {len(results)} 种组合，按可读性列前 10：")
    for score, cn, bit, order, direction, data in results[:10]:
        head = data[:120].decode("utf-8", "replace").replace("\n", "\\n")
        flag = ""
        low = data.lower()
        for h in (b"flag", b"ctf", b"key", b"secret"):
            pos = low.find(h)
            if pos >= 0:
                flag = data[pos:pos + 120].decode("utf-8", "replace"); break
        print(f"  通道{cn} 位{bit} {order}优先 按{direction} 可读率{score:.2f}")
        print(f"    头部: {head}")
        if flag:
            print(f"    [!!!] 疑似 flag: {flag}")
    # 导出 R 通道位平面 0 的二值图
    out = os.path.splitext(path)[0] + "_lsb_plane.png"
    gray = Image.new("L", img.size)
    gray.putdata([255 * ((p[0]) & 1) for p in img.getdata()])
    gray.save(out)
    print("[+] 位平面图已导出:", out)
    return results


def selftest():
    img = Image.new("RGBA", (200, 4))
    px = img.load()
    msg = b"flag{lsb_selftest_ok}"
    bits = []
    for byte in msg:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    for i, bit in enumerate(bits):
        x, y = i % 200, i // 200
        r, g, b, a = px[x, y]
        px[x, y] = ((r & ~1) | bit, g, b, a)
    p = os.path.join(os.environ.get("TEMP", "."), "lsb_selftest.png")
    img.save(p)
    res = analyze(p)
    top = res[0][5]
    assert b"flag{lsb_selftest_ok}" in top, top[:50]
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="LSB 隐写提取")
    ap.add_argument("image", nargs="?")
    ap.add_argument("--channel", choices=list("RGBA"))
    ap.add_argument("--bit", type=int, default=0)
    ap.add_argument("--order", choices=["msb", "lsb"], default="msb")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.image:
        print("[!] 用法: python lsb_stego_png.py stego.png"); return
    if a.channel:
        img = Image.open(a.image).convert("RGBA")
        data = extract(img, "RGBA".index(a.channel), a.bit, a.order == "msb")
        print(data[:2000].decode("utf-8", "replace"))
    else:
        analyze(a.image)


if __name__ == "__main__":
    main()
