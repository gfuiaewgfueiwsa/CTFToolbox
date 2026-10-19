# -*- coding: utf-8 -*-
# 脚本名称: RSA Fermat 费马分解（p、q 相差较小）
# 方向: Crypto（密码学 / RSA）
# 简介: 当 n=p*q 且 p、q 非常接近时，n 可写成 a^2-b^2=(a+b)(a-b)，
#       从 a=ceil(sqrt(n)) 开始枚举，检查 a^2-n 是否为完全平方数即可得到 p、q。
# 用法:
#   python rsa_fermat.py --n <n> [--c <密文> --e <公钥指数>]
#   python rsa_fermat.py --selftest
# 依赖: pip install gmpy2（推荐，纯 Python 也可运行）
# 参考: https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_factor/
import argparse
import time


def isqrt(x):
    try:
        from gmpy2 import iroot, mpz
        r, ok = iroot(mpz(int(x)), 2)
        return int(r), bool(ok)
    except Exception:
        r = int(int(x) ** 0.5)
        while r * r < x:
            r += 1
        while r * r > x:
            r -= 1
        return r, r * r == x


def fermat(n, max_iter=5_000_000):
    """Fermat 分解，返回 (p, q) 或 None。"""
    a, _ = isqrt(n)
    if a * a < n:
        a += 1
    for i in range(max_iter):
        b2 = a * a - n
        b, ok = isqrt(b2)
        if ok:
            p, q = a - b, a + b
            if p > 1 and p * q == n:
                return p, q
        a += 1
    return None


def selftest():
    from Crypto.Util.number import getPrime
    # 人为让 p、q 接近：q 取 p 附近的素数
    base = getPrime(256)
    from Crypto.Util.number import isPrime
    p = base
    q = base + 2
    while not (isPrime(q) and q != p):
        q += 2
    n = p * q
    t0 = time.time()
    r = fermat(n)
    assert r and r[0] * r[1] == n
    print(f"[+] selftest OK，用时 {time.time()-t0:.3f}s")
    print("    p =", r[0])
    print("    q =", r[1])


def main():
    ap = argparse.ArgumentParser(description="RSA Fermat 分解")
    ap.add_argument("--n", type=int)
    ap.add_argument("--e", type=int)
    ap.add_argument("--c", type=int)
    ap.add_argument("--max-iter", type=int, default=5_000_000)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest()
        return
    if not a.n:
        a.n = int(input("n = ").strip(), 0)
    print("[*] 开始 Fermat 分解 …")
    r = fermat(a.n, a.max_iter)
    if not r:
        print("[-] 未在迭代次数内分解成功（p、q 可能相差很大），请换 Pollard rho/yafu")
        return
    p, q = r
    print("[+] p =", p)
    print("[+] q =", q)
    if a.e and a.c:
        phi = (p - 1) * (q - 1)
        d = pow(a.e, -1, phi)
        m = pow(a.c, d, a.n)
        bs = m.to_bytes((m.bit_length() + 7) // 8, "big")
        print("[+] d =", d)
        print("[+] flag =", bs.decode("utf-8", "replace"))


if __name__ == "__main__":
    main()
