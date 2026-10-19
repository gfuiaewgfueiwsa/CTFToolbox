# -*- coding: utf-8 -*-
# 脚本名称: 重复密钥 XOR（Vigenere XOR）自动破解
# 方向: Crypto（古典/异或）
# 简介: Cryptopals Set1 Challenge 6 的完整实现：遍历 2~40 全部密钥长度，
#       对每列做单字节 XOR 频率分析，再用英文可打印/词频评分对整段明文排序，
#       直接给出最优密钥与明文，不再依赖短样本下不稳定的汉明距离排序。
# 用法:
#   python xor_repeating_key.py cipher.bin                 # 原始密文文件
#   python xor_repeating_key.py -x 1b3737...               # 十六进制密文
#   python xor_repeating_key.py -b "base64..."             # base64 密文
#   python xor_repeating_key.py --selftest
# 依赖: 仅标准库
import argparse
import base64
import string

COMMON = b"etaoinshrdlu ETAOINSHRDLU"


def hamming(a, b):
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def score_single(col):
    best = None
    for k in range(256):
        pt = bytes(x ^ k for x in col)
        score = sum(2 for c in pt if c in COMMON)
        score += sum(1 for c in pt if 32 <= c < 127)
        score -= sum(5 for c in pt if c < 9 or (13 < c < 32))
        if best is None or score > best[0]:
            best = (score, k, pt)
    return best


def solve_for_length(data, klen):
    key = bytearray(klen)
    cols = [data[i::klen] for i in range(klen)]
    for i, col in enumerate(cols):
        key[i] = score_single(col)[1]
    pt = bytes(data[i] ^ key[i % klen] for i in range(len(data)))
    return bytes(key), pt


def plaintext_score(pt):
    printable = sum(1 for c in pt if 9 <= c <= 13 or 32 <= c < 127) / max(1, len(pt))
    common = sum(pt.lower().count(c) for c in b"etaoinshrdlu ") / max(1, len(pt))
    return printable * 2 + common * 3


def crack(data, maxlen=40):
    cands = []
    for klen in range(2, maxlen + 1):
        key, pt = solve_for_length(data, klen)
        cands.append((plaintext_score(pt), klen, key, pt))
    cands.sort(key=lambda x: -x[0])
    return cands


def selftest():
    pt = (b"Burning 'em, if you ain't quick and nimble "
          b"I go crazy when I hear a cymbal " * 6)[:300]
    key = b"ICEKEY9"
    ct = bytes(b ^ key[i % len(key)] for i, b in enumerate(pt))
    cands = crack(ct, maxlen=20)
    assert cands[0][2] == key, cands[0][2]
    print("[+] 密钥:", cands[0][2])
    print("[+] 明文:", cands[0][3][:80])
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="重复密钥 XOR 破解")
    ap.add_argument("file", nargs="?")
    ap.add_argument("-x", "--hex")
    ap.add_argument("-b", "--b64")
    ap.add_argument("--maxlen", type=int, default=40)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if a.file:
        data = open(a.file, "rb").read()
    elif a.hex:
        data = bytes.fromhex(a.hex)
    elif a.b64:
        data = base64.b64decode(a.b64)
    else:
        print("[!] 用法: python xor_repeating_key.py cipher.bin"); return
    for score, klen, key, pt in crack(data, a.maxlen)[:5]:
        print(f"--- 长度 {klen} 评分 {score:.3f} 密钥 {key!r}")
        print(pt[:200].decode("utf-8", "replace"))
        print()


if __name__ == "__main__":
    main()
