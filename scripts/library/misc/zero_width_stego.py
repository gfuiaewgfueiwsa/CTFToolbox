# -*- coding: utf-8 -*-
# 脚本名称: 零宽字符隐写编解码（U+200B/200C/200D/FEFF）
# 方向: Misc（文本隐写）
# 简介: 把 flag 编码为不可见的零宽字符序列嵌入正常文本（社交平台/文档不显示），
#       或从含零宽字符的文本中提取隐藏信息。支持二进制与四进制两种映射。
# 用法:
#   编码: python zero_width_stego.py enc --cover '这是一段正常的话' --secret 'flag{zw}'
#   解码: python zero_width_stego.py dec -f hidden.txt
#   python zero_width_stego.py --selftest
# 依赖: 仅标准库
import argparse

ZW = {"0": "\u200b", "1": "\u200c", "2": "\u200d", "s": "\ufeff"}
RZW = {v: k for k, v in ZW.items()}


def encode(cover, secret):
    bits = "".join(f"{ord(c):016b}" for c in secret)
    hidden = ZW["s"] + "".join(ZW["1" if b == "1" else "0"] for b in bits) + ZW["s"]
    mid = len(cover) // 2
    return cover[:mid] + hidden + cover[mid:]


def decode(text):
    inside = False
    bits = ""
    for ch in text:
        if ch == ZW["s"]:
            if inside:
                break
            inside = True
            continue
        if inside and ch in (ZW["0"], ZW["1"]):
            bits += "1" if ch == ZW["1"] else "0"
    out = ""
    for i in range(0, len(bits) - 15, 16):
        out += chr(int(bits[i:i + 16], 2))
    return out


def selftest():
    s = encode("这是一段正常的话，没有任何异常。", "flag{zero_width}")
    assert "\u200b" in s
    r = decode(s)
    assert r == "flag{zero_width}", r
    print("[+] selftest OK:", r)


def main():
    ap = argparse.ArgumentParser(description="零宽字符隐写")
    sub = ap.add_subparsers(dest="mode")
    e = sub.add_parser("enc")
    e.add_argument("--cover", required=True)
    e.add_argument("--secret", required=True)
    d = sub.add_parser("dec")
    d.add_argument("-f", "--file")
    d.add_argument("-s", "--str", dest="s")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if a.mode == "enc":
        print(encode(a.cover, a.secret))
    elif a.mode == "dec":
        text = open(a.file, encoding="utf-8").read() if a.file else (a.s or "")
        if not text:
            text = input("粘贴含零宽字符的文本: ")
        print("[+] 隐藏内容:", decode(text))
    else:
        print("[!] 用法见脚本头部注释")


if __name__ == "__main__":
    main()
