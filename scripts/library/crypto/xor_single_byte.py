# -*- coding: utf-8 -*-
# 脚本名称: 单字节 XOR 爆破（异或密码 / 流量异或 / shellcode 解码）
# 方向: Crypto（密码学 / 异或）
# 简介: 数据被单个字节 key（0x00-0xFF）异或时，枚举 256 个密钥，
#       按英文可打印度/词频打分排序，自动给出最可能的明文与密钥。
#       常用于 Misc 流量、逆向里 0x?? 异或编码的 flag。
# 用法:
#   python xor_single_byte.py -x <十六进制密文>
#   python xor_single_byte.py -f cipher.bin          # 直接读文件
#   python xor_single_byte.py -s 'raw_string'
#   python xor_single_byte.py -x <hex> --top 10      # 显示前 10 个候选
#   python xor_single_byte.py --selftest
# 依赖: 仅标准库
import argparse
import string

# 英文字母频率（含空格），用于打分
FREQ = {
    ' ': 13.0, 'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7,
    's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3, 'l': 4.0, 'c': 2.8, 'u': 2.8,
    'm': 2.4, 'w': 2.4, 'f': 2.2, 'g': 2.0, 'y': 2.0, 'p': 1.9, 'b': 1.5,
    'v': 1.0, 'k': 0.8, 'j': 0.15, 'x': 0.15, 'q': 0.10, 'z': 0.07,
}


def score(bs):
    s = 0.0
    for b in bs:
        ch = chr(b)
        if ch in string.printable and ch not in '\x0b\x0c':
            s += FREQ.get(ch.lower(), 0.3 if ch.isdigit() or ch in '.,;:\'-_!{}[]()' else 0)
        else:
            s -= 8.0       # 不可打印重罚
    return s


def crack(data):
    res = []
    for k in range(256):
        pt = bytes(b ^ k for b in data)
        res.append((score(pt), k, pt))
    res.sort(key=lambda x: x[0], reverse=True)
    return res


def selftest():
    pt = b"flag{single_byte_xor_is_easy_2026}"
    key = 0x5a
    ct = bytes(b ^ key for b in pt)
    r = crack(ct)
    assert r[0][1] == key and r[0][2] == pt
    print(f"[+] selftest OK, key=0x{r[0][1]:02x}, plain={r[0][2].decode()}")


def main():
    ap = argparse.ArgumentParser(description="单字节 XOR 爆破")
    ap.add_argument("-x", "--hex", help="十六进制密文（可带空格/0x）")
    ap.add_argument("-f", "--file", help="密文文件")
    ap.add_argument("-s", "--str", dest="s", help="原始字符串密文")
    ap.add_argument("--top", type=int, default=5)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest()
        return
    if a.file:
        data = open(a.file, "rb").read()
    elif a.hex:
        data = bytes.fromhex(a.hex.replace("0x", "").replace(" ", "").replace(",", ""))
    elif a.s:
        data = a.s.encode("latin-1", "replace")
    else:
        print("[!] 用 -x/-f/-s 提供密文"); return
    for sc, k, pt in crack(data)[:a.top]:
        print(f"key=0x{k:02x} ({k:3d}) score={sc:8.1f}  {pt!r}")


if __name__ == "__main__":
    main()
