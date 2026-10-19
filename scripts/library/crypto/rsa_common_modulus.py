# -*- coding: utf-8 -*-
# 脚本名称: RSA 共模攻击（Common Modulus）
# 方向: Crypto（密码学 / RSA）
# 简介: 同一段明文用相同模数 n、两个不同公钥指数 e1/e2 分别加密得到 c1/c2，
#       且 gcd(e1,e2)=1 时，无需分解 n 即可还原明文。
# 用法:
#   python rsa_common_modulus.py --n <n> --e1 <e1> --c1 <c1> --e2 <e2> --c2 <c2>
#   不带参数进入交互模式，按提示逐个粘贴
#   python rsa_common_modulus.py --selftest   运行自测
# 依赖: 仅标准库（pycryptodome 仅自测时需要）
# 参考: https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_common_modulus/
import argparse


def egcd(a, b):
    """扩展欧几里得，返回 (g, x, y) 使 a*x + b*y = g = gcd(a,b)。"""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def common_modulus(n, e1, c1, e2, c2):
    g, s1, s2 = egcd(e1, e2)
    if g != 1:
        raise ValueError(f"gcd(e1,e2)={g}，不满足共模攻击条件")
    # m = c1^s1 * c2^s2 mod n；指数为负时先对密文取模逆
    if s1 < 0:
        c1 = pow(c1, -1, n)
        s1 = -s1
    if s2 < 0:
        c2 = pow(c2, -1, n)
        s2 = -s2
    return (pow(c1, s1, n) * pow(c2, s2, n)) % n


def to_bytes(m):
    return m.to_bytes((m.bit_length() + 7) // 8, "big")


def selftest():
    from Crypto.Util.number import getPrime, inverse
    p, q = getPrime(512), getPrime(512)
    n = p * q
    phi = (p - 1) * (q - 1)
    while True:
        e1, e2 = 65537, 257
        if egcd(e1, e2)[0] == 1 and egcd(e1, phi)[0] == 1 and egcd(e2, phi)[0] == 1:
            break
        p, q = getPrime(512), getPrime(512)
        n = p * q
        phi = (p - 1) * (q - 1)
    m = int.from_bytes(b"flag{common_modulus_ok}", "big")
    c1, c2 = pow(m, e1, n), pow(m, e2, n)
    m2 = common_modulus(n, e1, c1, e2, c2)
    assert m2 == m
    print("[+] selftest OK:", to_bytes(m2).decode())


def main():
    ap = argparse.ArgumentParser(description="RSA 共模攻击")
    ap.add_argument("--n", type=int)
    ap.add_argument("--e1", type=int)
    ap.add_argument("--c1", type=int)
    ap.add_argument("--e2", type=int)
    ap.add_argument("--c2", type=int)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest()
        return
    vals = [a.n, a.e1, a.c1, a.e2, a.c2]
    if not all(v is not None for v in vals):
        names = ["n", "e1", "c1", "e2", "c2"]
        got = {}
        for nm in names:
            got[nm] = int(input(f"{nm} = ").strip(), 0)
        n, e1, c1, e2, c2 = (got[x] for x in names)
    else:
        n, e1, c1, e2, c2 = vals
    m = common_modulus(n, e1, c1, e2, c2)
    print("[+] m =", m)
    print("[+] flag =", to_bytes(m).decode("utf-8", "replace"))


if __name__ == "__main__":
    main()
