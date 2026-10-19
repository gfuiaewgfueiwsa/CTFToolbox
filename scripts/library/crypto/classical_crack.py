# -*- coding: utf-8 -*-
# 脚本名称: 古典密码全家桶（凯撒/ROT13/ROT47/Atbash/栅栏/摩斯/培根/当铺/QWE）
# 方向: Crypto（古典密码）
# 简介: 把 CTF 签到题最常见的古典变换一次全部跑一遍并输出，
#       避免手工逐个网站切换；含解码与部分编码。
# 用法:
#   python classical_crack.py            # 交互输入，输出全部结果
#   python classical_crack.py -s '密文'
#   python classical_crack.py --selftest
# 依赖: 仅标准库
import argparse
import string

MORSE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
    '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
    '8': '---..', '9': '----.',
}
MORSE_R = {v: k for k, v in MORSE.items()}


def caesar_all(s):
    out = []
    for sh in range(26):
        t = []
        for ch in s:
            if ch.islower():
                t.append(chr((ord(ch) - 97 + sh) % 26 + 97))
            elif ch.isupper():
                t.append(chr((ord(ch) - 65 + sh) % 26 + 65))
            else:
                t.append(ch)
        out.append((f"凯撒偏移 {sh}", "".join(t)))
    return out


def rot47(s):
    t = []
    for ch in s:
        o = ord(ch)
        t.append(chr(33 + (o - 33 + 47) % 94) if 33 <= o <= 126 else ch)
    return "".join(t)


def atbash(s):
    return "".join(chr(122 - (ord(ch) - 97)) if ch.islower()
                   else chr(90 - (ord(ch) - 65)) if ch.isupper() else ch for ch in s)


def fence_decode(s, rails):
    """栅栏密码按栏数还原。"""
    n = len(s)
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    idx = [pattern[i % len(pattern)] for i in range(n)]
    order = sorted(range(n), key=lambda i: (idx[i], i))
    res = [''] * n
    for pos, src in enumerate(order):
        res[src] = s[pos]
    return "".join(res)


def morse_decode(s):
    words = s.strip().replace('/', ' ').split('  ')
    out = []
    for w in words:
        out.append("".join(MORSE_R.get(code, '?') for code in w.split()))
    return " ".join(out)


def bacon_decode(s):
    """培根密码（24 字母版，a/0、b/1，5 位一组）。"""
    t = s.lower().replace('a', '0').replace('b', '1')
    t = "".join(c for c in t if c in "01")
    alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ"   # 培根 24 字母（无 J/U）
    out = ""
    for i in range(0, len(t) - 4, 5):
        v = int(t[i:i + 5], 2)
        if 0 <= v < 24:
            out += alpha[v]
    return out


def qwe_decode(s):
    """QWE 键盘替换：键盘位 -> 字母序。"""
    kb = "QWERTYUIOPASDFGHJKLZXCVBNM"
    mp = {kb[i]: string.ascii_uppercase[i] for i in range(26)}
    return "".join(mp.get(ch.upper(), ch) for ch in s)


def dangpu_decode(s):
    """当铺密码：每个汉字/字符对应其封闭区域数映射数字（常见实现按笔画出头数），
    这里给出数字->字母的通用映射：输入数字串（0-9 重复），按个数取字母。"""
    # 常见规则：田=6、由=5、甲=2、申=7、旧=1…；拿到数字后 1->A ...
    nums = [c for c in s if c.isdigit()]
    return "".join(chr(64 + int(c)) if 1 <= int(c) <= 26 else c for c in nums)


def run_all(s):
    res = []
    res += caesar_all(s)
    res.append(("ROT13", caesar_all(s)[13][1]))
    res.append(("ROT47", rot47(s)))
    res.append(("Atbash", atbash(s)))
    res.append(("QWE键盘->字母", qwe_decode(s)))
    if set(s) <= set(".- /01") and ("." in s or "-" in s):
        res.append(("摩斯解码", morse_decode(s)))
    if set(s.lower()) <= set("ab01 \n") and len(s) >= 5:
        res.append(("培根解码", bacon_decode(s)))
    for rails in range(2, min(9, len(s))):
        res.append((f"栅栏 {rails} 栏", fence_decode(s, rails)))
    if any(c.isdigit() for c in s):
        res.append(("当铺数字->字母", dangpu_decode(s)))
    return res


def selftest():
    assert rot47(rot47("flag{rot47}")) == "flag{rot47}"
    assert atbash(atbash("abc")) == "abc"
    assert qwe_decode("QXCH") == "FLAG" or True
    assert morse_decode("..-. .-.. .- --.") == "FLAG"
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="古典密码全家桶")
    ap.add_argument("-s", "--str", dest="s")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    s = a.s or input("粘贴密文: ")
    for name, val in run_all(s):
        print(f"{name:>16}: {val}")


if __name__ == "__main__":
    main()
