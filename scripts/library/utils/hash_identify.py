# -*- coding: utf-8 -*-
# 脚本名称: 哈希类型识别 + 哈希值计算
# 方向: Util（杂项工具）
# 简介: 1) 按长度、字符集与版本特征识别常见哈希（MD5/SHA 系列/NTLM/MySQL/
#       bcrypt/CRC32/Blowfish crypt/Django 等），给出 hashcat/john 模式号；
#       2) 直接对字符串/文件计算常见哈希。
# 用法:
#   python hash_identify.py 5f4dcc3b5aa765d61d8327deb882cf99
#   python hash_identify.py --text password
#   python hash_identify.py --file ./binary
#   python hash_identify.py --selftest
# 依赖: 仅标准库
import argparse
import re

TYPES = [
    (r"^[0-9a-fA-F]{32}$", "MD5 / NTLM / MD4(32hex)", "hashcat -m 0 (MD5) / -m 1000 (NTLM)"),
    (r"^\$1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}$", "MD5 crypt ($1$)", "hashcat -m 500"),
    (r"^\$2[aby]?\$\d{2}\$[./0-9A-Za-z]{53}$", "bcrypt ($2a/$2b/$2y)", "hashcat -m 3200"),
    (r"^\$5\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{43}$", "SHA-256 crypt ($5$)", "hashcat -m 7400"),
    (r"^\$6\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}$", "SHA-512 crypt ($6$)", "hashcat -m 1800"),
    (r"^[0-9a-fA-F]{40}$", "SHA-1", "hashcat -m 100"),
    (r"^[0-9a-fA-F]{56}$", "SHA-224", "hashcat -m 1300"),
    (r"^[0-9a-fA-F]{64}$", "SHA-256 / SHA3-256 / BLAKE2s", "hashcat -m 1400"),
    (r"^[0-9a-fA-F]{96}$", "SHA-384", "hashcat -m 10800"),
    (r"^[0-9a-fA-F]{128}$", "SHA-512 / SHA3-512 / Whirlpool", "hashcat -m 1700"),
    (r"^[0-9a-fA-F]{8}$", "CRC32(8hex)", "无需爆破，可逆校验"),
    (r"^[0-9a-fA-F]{16}$", "MySQL OLD(<4.1) 16hex / 截断MD5", "hashcat -m 200 (MySQL323)"),
    (r"^\*[0-9A-F]{40}$", "MySQL4.1+ (大写带*)", "hashcat -m 300"),
    (r"^[0-9a-f]{32}:[0-9a-f]{32}$", "LM:NT 或 user:hash 组合", "hashcat -m 1000"),
    (r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:[0-9a-fA-F]+$", "NetNTLM / DCC 复合格式", "看上下文"),
    (r"^[A-Fa-f0-9]{32}:[^:]+:\d+:[A-Fa-f0-9]+:[A-Fa-f0-9]+$",
     "NetNTLMv2(user:domain:challenge:proof:blob)", "hashcat -m 5600"),
    (r"^[A-Fa-f0-9]+::[A-Fa-f0-9]+:[A-Fa-f0-9]+$", "NetNTLMv1", "hashcat -m 5500"),
    (r"^pbkdf2_sha256\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$",
     "Django PBKDF2-SHA256", "hashcat -m 10000"),
    (r"^argon2(i|d|id)\$", "Argon2", "hashcat -m 8900(i)"),
    (r"^\$apr1\$", "Apache apr1 MD5", "hashcat -m 1600"),
    (r"^[A-Za-z0-9+/]{4}.*={0,2}$", "可能是 Base64（不是哈希）", "先 base64 解码"),
]


def identify(h):
    h = h.strip()
    hits = []
    for pat, name, mode in TYPES:
        if re.match(pat, h):
            hits.append((name, mode))
    return hits or [("未知格式", "检查是否加盐/编码/截断")]


def calc(text=None, file=None):
    import hashlib
    import zlib
    algos = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]
    if file:
        h = {a: hashlib.new(a) for a in algos}
        for chunk in iter(lambda: open(file, "rb").read(1 << 20), b""):
            for a in algos:
                h[a].update(chunk)
        raw = open(file, "rb").read()
        print("file:", file)
    else:
        raw = text.encode()
        h = {a: hashlib.new(a, raw) for a in algos}
        print("text:", text)
    for a in algos:
        print(f"  {a:7s}: {h[a].hexdigest()}")
    print(f"  crc32  : {zlib.crc32(raw) & 0xffffffff:08x}")


def selftest():
    r = identify("5f4dcc3b5aa765d61d8327deb882cf99")
    assert any("MD5" in x[0] for x in r)
    r2 = identify("$2b$12$" + "a" * 53)
    assert any("bcrypt" in x[0] for x in r2)
    r3 = identify("a" * 64)
    assert any("SHA-256" in x[0] for x in r3)
    print("[+] 识别 MD5/bcrypt/SHA256 正常")
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="哈希识别/计算")
    ap.add_argument("hash", nargs="?")
    ap.add_argument("--text")
    ap.add_argument("--file")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if a.hash:
        for name, mode in identify(a.hash):
            print(f"[+] {name}   {mode}")
    elif a.text or a.file:
        calc(a.text, a.file)
    else:
        print("[!] 用法: python hash_identify.py <hash> | --text pwd | --file f")


if __name__ == "__main__":
    main()
