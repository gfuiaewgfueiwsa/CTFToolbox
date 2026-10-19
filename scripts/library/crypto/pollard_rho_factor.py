# -*- coding: utf-8 -*-
# 脚本名称: Pollard rho 整数分解（Brent 改进版）
# 方向: Crypto（密码学 / RSA / 数学）
# 简介: CTF 中分解合数 n 最常用的快速启发式算法，适合几十位到约 100 位的素因子；
#       Brent 变比经典 Floyd 判环更快。多素因子时递归分解到全素数。
# 用法:
#   python pollard_rho_factor.py <n>                 # 十进制或 0x 十六进制
#   python pollard_rho_factor.py --n <n> --e <e> --c <c>   # 分解后顺便解密
#   python pollard_rho_factor.py --selftest
# 依赖: pip install gmpy2（强烈推荐，速度可差十几倍）
# 参考: https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_factor/
import argparse
import random
import sys

try:
    import gmpy2
    def _is_prime(n):
        return gmpy2.is_prime(n, 25)
    def _inv(a, m):
        return int(gmpy2.invert(a, m))
except Exception:
    def _is_prime(n):
        if n < 2:
            return False
        for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            if n % p == 0:
                return n == p
        d = n - 1
        r = 0
        while d % 2 == 0:
            r += 1
            d //= 2
        for a in (2, 3, 5, 7, 11, 13, 17):
            x = pow(a, d, n)
            if x in (1, n - 1):
                continue
            for _ in range(r - 1):
                x = x * x % n
                if x == n - 1:
                    break
            else:
                return False
        return True
    def _inv(a, m):
        return pow(a, -1, m)


def brent(n):
    """Brent 改进的 Pollard rho，返回 n 的一个非平凡因子。"""
    if n % 2 == 0:
        return 2
    if n % 3 == 0:
        return 3
    while True:
        y = random.randrange(1, n - 1)
        c = random.randrange(1, n - 1)
        m = 128
        g, r, q = 1, 1, 1
        x = ys = 0
        while g == 1:
            x = y
            for _ in range(r):
                y = (y * y + c) % n
            k = 0
            while k < r and g == 1:
                ys = y
                for _ in range(min(m, r - k)):
                    y = (y * y + c) % n
                    q = q * abs(x - y) % n
                g = _gcd(q, n)
                k += m
            r *= 2
        if g == n:
            while True:
                ys = (ys * ys + c) % n
                g = _gcd(abs(x - ys), n)
                if g > 1:
                    break
        if g != n:
            return g


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def factor(n, out=None):
    out = out if out is not None else []
    if n == 1:
        return out
    if _is_prime(n):
        out.append(n)
        return out
    d = brent(n)
    factor(d, out)
    factor(n // d, out)
    return out


def selftest():
    from Crypto.Util.number import getPrime
    p, q = getPrime(40), getPrime(40)
    n = p * q
    fac = sorted(factor(n))
    assert sorted([p, q]) == fac, fac
    print("[+] selftest OK:", fac)


def main():
    ap = argparse.ArgumentParser(description="Pollard rho (Brent) 整数分解")
    ap.add_argument("n_pos", nargs="?", help="合数 n")
    ap.add_argument("--n", dest="n2")
    ap.add_argument("--e", type=int)
    ap.add_argument("--c", type=int)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest()
        return
    ns = a.n_pos or a.n2
    if not ns:
        ns = input("n = ").strip()
    n = int(ns, 0)
    print("[*] 分解中 …（大因子可能需要几分钟）")
    fac = factor(n)
    fac.sort()
    print("[+] 素因子:")
    for p in fac:
        print("   ", p)
    prod = 1
    for p in fac:
        prod *= p
    assert prod == n
    if a.e and a.c and len(fac) == 2:
        p, q = fac
        phi = (p - 1) * (q - 1)
        d = _inv(a.e, phi)
        m = pow(a.c, d, n)
        print("[+] flag =", m.to_bytes((m.bit_length()+7)//8, "big").decode("utf-8", "replace"))


if __name__ == "__main__":
    main()
