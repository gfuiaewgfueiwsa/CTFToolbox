# -*- coding: utf-8 -*-
# 脚本名称: Base 家族链式解码（16/32/58/64/85/91 + Hex/URL 自动连解）
# 方向: Crypto / Misc（编码）
# 简介: CTF 里编码经常层层嵌套。本脚本自动尝试 Base16/32/58/64/85/91、
#       Hex、URL 编码的任意链式组合，按可读性评分排序输出，直到解出可读文本。
# 用法:
#   python base_family_decode.py                    # 交互粘贴密文
#   echo -n 'xxxx' | python base_family_decode.py   # 管道
#   python base_family_decode.py -s '密文'
#   python base_family_decode.py -f encoded.txt
#   python base_family_decode.py --selftest
# 依赖: 仅标准库（base91 为内置实现）
import argparse
import base64
import string
import sys
import urllib.parse

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B91_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""


def b58_decode(s):
    n = 0
    for ch in s:
        n = n * 58 + B58_ALPHABET.index(ch)
    pad = len(s) - len(s.lstrip("1"))
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * pad + body


def b91_decode(s):
    """base91 解码（Joachim Henke 算法）。"""
    table = {c: i for i, c in enumerate(B91_ALPHABET)}
    b, n, v = 0, 0, -1
    out = bytearray()
    for ch in s:
        if ch not in table:
            continue
        c = table[ch]
        if v < 0:
            v = c
        else:
            v += c * 91
            b |= v << n
            n += 13 if (v & 8191) > 90 else 14
            while True:
                out.append(b & 255)
                b >>= 8
                n -= 8
                if n <= 7:
                    break
            v = -1
    if v >= 0:
        out.append((b | v << n) & 255)
    return bytes(out)


def printable_score(b):
    if not b:
        return -999
    ok = sum(1 for x in b if 9 <= x <= 13 or 32 <= x < 127 or x >= 0x80)
    return ok / len(b)


def candidates(s):
    """返回 [(链名, 字节)]，每个单层解码候选。"""
    res = []
    try:
        res.append(("Base64", base64.b64decode(s + "=" * (-len(s) % 4), validate=False)))
    except Exception:
        pass
    try:
        res.append(("Base32", base64.b32decode(s.upper() + "=" * (-len(s) % 8), casefold=True)))
    except Exception:
        pass
    try:
        res.append(("Base16/Hex", bytes.fromhex(s.replace(" ", "").replace("0x", ""))))
    except Exception:
        pass
    try:
        res.append(("Base85(ascii85)", base64.a85decode(s, adata=False, ignorechars=b" \n\r\t")))
    except Exception:
        pass
    try:
        res.append(("Base85(b85)", base64.b85decode(s)))
    except Exception:
        pass
    try:
        if all(c in B58_ALPHABET for c in s) and len(s) >= 4:
            res.append(("Base58", b58_decode(s)))
    except Exception:
        pass
    try:
        if len(s) >= 8 and all(c in B91_ALPHABET or c in "\r\n" for c in s):
            res.append(("Base91", b91_decode(s)))
    except Exception:
        pass
    try:
        d = urllib.parse.unquote_to_bytes(s)
        if d != s.encode("latin-1", "ignore"):
            res.append(("URL编码", d))
    except Exception:
        pass
    return res


def auto(s, depth=8):
    seen = set()
    results = []

    def rec(cur, chain, d):
        if d <= 0:
            return
        for name, raw in candidates(cur):
            if raw in seen or not raw:
                continue
            seen.add(raw)
            sc = printable_score(raw)
            text = raw.decode("utf-8", "replace")
            results.append((sc, chain + "->" + name, text))
            if sc > 0.95 and all(ch in string.printable or ord(ch) > 127 for ch in text[:200]):
                rec(text, chain + "->" + name, d - 1)
            elif sc > 0.8:
                rec(text, chain + "->" + name, d - 1)
    rec(s.strip(), "原文", depth)
    results.sort(key=lambda x: x[0], reverse=True)
    return results


def selftest():
    import os
    flag = "flag{base_family_chain_2026}"
    s = flag.encode()
    s = base64.b85encode(s).decode()
    s = base64.b32encode(s.encode()).decode().lower().rstrip("=")
    s = base64.b64encode(s.encode()).decode()
    res = auto(s)
    assert any(flag in t for _, _, t in res), "链式解码失败"
    print("[+] selftest OK，最佳链路:", res[0][1])
    print("    ", res[0][2][:80])


def main():
    ap = argparse.ArgumentParser(description="Base 家族链式自动解码")
    ap.add_argument("-s", "--str", dest="s")
    ap.add_argument("-f", "--file")
    ap.add_argument("--depth", type=int, default=8)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if a.file:
        s = open(a.file, encoding="utf-8", errors="replace").read()
    elif a.s:
        s = a.s
    elif not sys.stdin.isatty():
        s = sys.stdin.read()
    else:
        s = input("粘贴密文: ")
    for sc, chain, text in auto(s, a.depth)[:15]:
        print(f"[可读分 {sc:.2f}] {chain}\n{text[:300]}\n{'-'*70}")


if __name__ == "__main__":
    main()
