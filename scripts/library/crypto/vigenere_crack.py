# -*- coding: utf-8 -*-
# 脚本名称: 维吉尼亚密码自动破解（重合指数 IoC 猜密钥长度 + 频率分析）
# 方向: Crypto（古典密码）
# 简介: 对维吉尼亚（Vigenere）密文，先用重合指数 Index of Coincidence 确定
#       密钥长度，再对每个分柱做凯撒位移频率分析还原密钥，最后解密。
#       英文文本效果最好，密文越长越准（建议 >120 字母）。
# 用法:
#   python vigenere_crack.py -f cipher.txt [--maxlen 20]
#   python vigenere_crack.py -s '密文'
#   python vigenere_crack.py --selftest
# 依赖: 仅标准库
# 参考: https://ctf-wiki.org/crypto/classical/polyalphabetic/vigenere/
import argparse
import string

ENG_FREQ = [0.0817, 0.0149, 0.0278, 0.0425, 0.1270, 0.0223, 0.0202, 0.0609,
            0.0697, 0.0015, 0.0077, 0.0403, 0.0241, 0.0675, 0.0751, 0.0193,
            0.0010, 0.0599, 0.0633, 0.0906, 0.0276, 0.0098, 0.0236, 0.0015,
            0.0197, 0.0007]


def ioc(text):
    n = len(text)
    if n < 2:
        return 0
    counts = [text.count(chr(65 + i)) for i in range(26)]
    return sum(c * (c - 1) for c in counts) / (n * (n - 1))


def guess_length(ct, maxlen=20):
    scores = []
    for klen in range(1, maxlen + 1):
        cols = [ct[i::klen] for i in range(klen)]
        avg = sum(ioc(c) for c in cols) / klen
        scores.append((abs(avg - 0.0667), klen, avg))
    scores.sort()
    return scores


def chi_shift(col):
    n = len(col)
    best = (1e9, 0)
    for sh in range(26):
        cnt = [0] * 26
        for ch in col:
            cnt[(ord(ch) - 65 - sh) % 26] += 1
        chi = sum(((cnt[i] / n) - ENG_FREQ[i]) ** 2 / ENG_FREQ[i] for i in range(26)) if n else 9
        if chi < best[0]:
            best = (chi, sh)
    return best[1]


def decrypt(ct, key):
    out = []
    for i, ch in enumerate(ct):
        if ch.isalpha():
            out.append(chr((ord(ch) - 65 - key[i % len(key)]) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


# 英文高频三元组/二元组，用于整段明文打分（比卡方更抗短分柱过拟合）
TRIGRAMS = ("THE", "AND", "ING", "ENT", "ION", "HER", "FOR", "THA", "TER",
            "HAT", "ERE", "ATE", "HIS", "CON", "WIT", "ETH", "YOU", "TIO",
            "VER", "ALL", "FTHE", "THI", "ECT", "REA", "EEN", "MEN")
BIGRAMS = ("TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT", "EN", "ND",
           "TI", "ES", "OR", "TE", "OF", "ED", "IS", "IT", "AL", "AR")
VOWELS = set("AEIOU")


def english_score(pt):
    n = max(1, len(pt))
    s = 0
    for t in TRIGRAMS:
        s += pt.count(t) * 3
    for b in BIGRAMS:
        s += pt.count(b)
    # 元音占比应在 35%~50%
    vr = sum(1 for c in pt if c in VOWELS) / n
    if 0.30 <= vr <= 0.55:
        s += n * 0.1
    # 罕见字母 Q/J/X/Z 过多扣分
    for c in "QJXZ":
        s -= pt.count(c) * 2
    return s / n


def crack(ct, maxlen=20):
    ct = "".join(c.upper() for c in ct if c.isalpha())
    results = []
    # 直接遍历所有候选密钥长度：逐列做频率分析还原密钥，再用整段明文的
    # 英文字母频率卡方打分，卡方最小者即正确长度（短样本下比 IoC 更稳）。
    for klen in range(2, maxlen + 1):
        key = bytes(chi_shift(ct[i::klen]) for i in range(klen))
        keystr = "".join(chr(65 + k) for k in key)
        pt = decrypt(ct, key)
        results.append((english_score(pt), klen, keystr, pt))
    results.sort(key=lambda x: -x[0])
    return [(klen, keystr, pt, score) for score, klen, keystr, pt in results]


def selftest():
    # 注意：自测明文必须是不重复的自然英语段落，重复同一句会扭曲字母频率
    pt = ("IT WAS DURING THE PERIOD OF HER CONVALESCENCE THAT THE DUCHESS FIRST "
          "BEGAN TO TALK WITH HER COMPANION ABOUT THE POSITION IN WHICH THEY "
          "STOOD TOWARDS ONE ANOTHER AND TOWARDS THE WORLD AROUND THEM THE HOUSE "
          "WAS LARGE AND ROOMY BUT THEY OCCUPIED ONLY A SMALL PORTION OF IT AND "
          "LIVED QUIETLY ALMOST AS THOUGH THEY WERE AFRAID THAT THEIR OWN "
          "MOVEMENTS SHOULD DISCOVER SOME SECRET HIDDEN BENEATH THE FLOOR WHICH "
          "NEITHER OF THEM HAD PLACED THERE YET BOTH SUSPECTED WHEN THE WEATHER "
          "GREW WARM THEY WALKED IN THE GARDEN AND DISCUSSED MANY SUBJECTS FROM "
          "HISTORY AND POETRY TO THE ORDINARY BUSINESS OF EVERYDAY LIFE WHICH "
          "OFTEN REVEALS MORE ABOUT A PERSON THAN THE MOST CAREFULLY PLANNED "
          "SPEECH DELIVERED BEFORE A LARGE AND SILENT AUDIENCE WAITING FOR SIGNS")
    key = b"SECRET"
    out = []
    j = 0
    for c in pt:   # 标准维吉尼亚：密钥只随字母推进
        if c.isalpha():
            out.append(chr((ord(c) - 65 + key[j % len(key)] - 65) % 26 + 65))
            j += 1
        else:
            out.append(c)
    ct = "".join(out)
    res = crack(ct)
    assert res[0][1] == "SECRET", res[0]
    print("[+] selftest OK, key =", res[0][1])


def main():
    ap = argparse.ArgumentParser(description="维吉尼亚自动破解")
    ap.add_argument("-s", "--str", dest="s")
    ap.add_argument("-f", "--file")
    ap.add_argument("--maxlen", type=int, default=20)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if a.file:
        ct = open(a.file, encoding="utf-8", errors="replace").read()
    else:
        ct = a.s or input("粘贴密文: ")
    for klen, key, pt, score in crack(ct, a.maxlen)[:5]:
        print(f"密钥长度={klen} 密钥={key} 英文评分={score:.3f}\n明文: {pt[:400]}\n{'-'*70}")


if __name__ == "__main__":
    main()
