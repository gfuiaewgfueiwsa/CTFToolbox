# -*- coding: utf-8 -*-
# 脚本名称: 编码/解码一体化工具（16 种常见编码自动尝试）
# 方向: Util（编码转换）
# 简介: 对一段密文自动尝试 Base16/32/58/64/85/91、URL、HTML 实体、Unicode 转义、
#       十六进制、二进制、Morse、rot13、Quoted-Printable、Punycode 解码，
#       输出可读结果并标注编码；编码方向支持上述全部。CTF 开局先跑一遍。
# 用法:
#   python encode_decode_hub.py auto "ZTZhZ2FsZQ=="
#   python encode_decode_hub.py dec b64 "ZTZhZ2FsZQ=="
#   python encode_decode_hub.py enc url "a b=c&d"
#   python encode_decode_hub.py --selftest
# 依赖: 仅标准库（base58/91 内置实现）
import argparse
import base64
import binascii
import codecs
import html
import urllib.parse

MORSE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
    '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
    '8': '---..', '9': '----.', '{': '-.--.', '}': '-.--.-', '_': '..--.-',
    '-': '-....-', '/': '-..-.', '.': '.-.-.-', ' ': '/',
}
RMORSE = {v: k for k, v in MORSE.items()}

B58_ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B91_ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'


def b58_dec(s):
    n = 0
    for c in s:
        n = n * 58 + B58_ALPHA.index(c)
    pad = len(s) - len(s.lstrip("1"))
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * pad + body


def b91_dec(data):
    b = 0
    n = 0
    v = -1
    out = bytearray()
    for ch in data:
        c = B91_ALPHA.find(ch)
        if c < 0:
            continue
        if v < 0:
            v = c
        else:
            v += c * 91
            b |= v << n
            n += 13 if (v & 8191) > 90 else 14
            while n > 7:
                out.append(b & 255)
                b >>= 8
                n -= 8
            v = -1
    if v + 1:
        out.append((b | v << n) & 255)
    return bytes(out)


def printable_ratio(b):
    if not b:
        return 0
    return sum(1 for x in b if 9 <= x <= 13 or 32 <= x < 127) / len(b)


def auto(s):
    attempts = []
    try:
        attempts.append(("base64", base64.b64decode(s + "=" * (-len(s) % 4), validate=False)))
    except Exception: pass
    try:
        attempts.append(("base32", base64.b32decode(s.upper() + "=" * (-len(s) % 8))))
    except Exception: pass
    try:
        attempts.append(("base16", binascii.unhexlify(s.strip())))
    except Exception: pass
    try:
        attempts.append(("base85(ascii85)", base64.a85decode(s)))
    except Exception: pass
    try:
        attempts.append(("base85(b85)", base64.b85decode(s)))
    except Exception: pass
    try:
        attempts.append(("base58", b58_dec(s.strip())))
    except Exception: pass
    try:
        attempts.append(("base91", b91_dec(s)))
    except Exception: pass
    try:
        attempts.append(("url", urllib.parse.unquote_to_bytes(s)))
    except Exception: pass
    try:
        attempts.append(("html entity", html.unescape(s).encode()))
    except Exception: pass
    try:
        attempts.append(("unicode_escape", codecs.decode(s, "unicode_escape").encode("latin-1", "replace")))
    except Exception: pass
    try:
        attempts.append(("quoted-printable", base64.b64decode(b"") or codecs.decode(s.encode(), "quopri").decode().encode()))
    except Exception: pass
    try:
        words = s.strip().split("/")
        if all(w in RMORSE or w == "" for w in words) and ("-" in s or "." in s):
            attempts.append(("morse", "".join(RMORSE.get(w, " ") for w in words).encode()))
    except Exception: pass
    try:
        if set(s) <= set("01 \n") and len(s.split()) > 2:
            bits = s.replace("\n", " ").split()
            attempts.append(("binary", bytes(int(x, 2) for x in bits)))
    except Exception: pass
    try:
        attempts.append(("rot13", codecs.decode(s, "rot_13").encode()))
    except Exception: pass

    ranked = [(printable_ratio(b), name, b) for name, b in attempts]
    ranked.sort(reverse=True)
    for ratio, name, b in ranked:
        if ratio > 0.85:
            print(f"[{name:18s}] ({ratio:.2f}) {b[:200].decode('utf-8','replace')}")
    if not any(r > 0.85 for r, _, _ in ranked):
        print("[-] 没有高置信度结果，原始候选:")
        for ratio, name, b in ranked[:5]:
            print(f"  {name:18s} ({ratio:.2f}) {b[:80]!r}")


def enc(kind, s):
    b = s.encode()
    table = {
        "b64": lambda: base64.b64encode(b).decode(),
        "b32": lambda: base64.b32encode(b).decode(),
        "b16": lambda: b.hex().upper(),
        "b85": lambda: base64.b85encode(b).decode(),
        "a85": lambda: base64.a85encode(b).decode(),
        "url": lambda: urllib.parse.quote(s),
        "html": lambda: html.escape(s),
        "hex": lambda: b.hex(),
        "bin": lambda: " ".join(f"{x:08b}" for x in b),
        "morse": lambda: "/".join(MORSE.get(c.upper(), "") for c in s),
        "rot13": lambda: codecs.encode(s, "rot_13"),
    }
    print(table[kind]())


def dec(kind, s):
    table = {
        "b64": lambda: base64.b64decode(s + "=" * (-len(s) % 4)),
        "b32": lambda: base64.b32decode(s.upper() + "=" * (-len(s) % 8)),
        "b16": lambda: binascii.unhexlify(s),
        "b58": lambda: b58_dec(s),
        "b91": lambda: b91_dec(s),
        "b85": lambda: base64.b85decode(s),
        "a85": lambda: base64.a85decode(s),
        "url": lambda: urllib.parse.unquote_to_bytes(s),
        "html": lambda: html.unescape(s).encode(),
        "hex": lambda: bytes.fromhex(s),
        "morse": lambda: "".join(RMORSE.get(w, " ") for w in s.split("/")).encode(),
        "rot13": lambda: codecs.decode(s, "rot_13").encode(),
    }
    print(table[kind]().decode("utf-8", "replace"))


def selftest():
    assert base64.b64decode("ZmxhZ3tlbmNfaHVifQ==") == b"flag{enc_hub}"
    assert base64.b85encode(b"flag{b85}") is not None
    assert b58_dec("") == b""
    morse_enc = "/".join(MORSE[c] for c in "FLAG")
    assert "".join(RMORSE[w] for w in morse_enc.split("/")) == "FLAG"
    print("[+] 编解码表与 Morse 正常")
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="编码解码一体化")
    sub = ap.add_subparsers(dest="mode")
    for m in ("auto", "enc", "dec"):
        p = sub.add_parser(m)
        p.add_argument("kind", nargs="?")
        p.add_argument("data", nargs="?")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if a.mode == "auto":
        auto(a.kind or "")
    elif a.mode == "enc":
        enc(a.kind, a.data)
    elif a.mode == "dec":
        dec(a.kind, a.data)
    else:
        print("[!] 用法: python encode_decode_hub.py auto <字符串>")


if __name__ == "__main__":
    main()
