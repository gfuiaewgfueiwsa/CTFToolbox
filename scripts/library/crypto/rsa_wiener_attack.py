# -*- coding: utf-8 -*-
# 脚本名称: RSA Wiener 维纳攻击（小私钥指数 d）
# 方向: Crypto（密码学 / RSA）
# 简介: 当 RSA 的私钥指数 d 较小（通常 d < (1/3)*n^0.25，表现为 e 特别大、接近 n）时，
#       利用 e/n 的连分数展开收敛分数可还原 d，进而分解 n 解密密文。
# 用法:
#   1) 命令行直接传参:
#        python rsa_wiener_attack.py --n <模数n> --e <公钥指数e> --c <密文c(可选)>
#   2) 从公钥文件读取（PEM）:
#        python rsa_wiener_attack.py --pub public.pem --c <密文c(可选)>
#   3) 交互模式（不带参数，按提示粘贴 n/e/c）:
#        python rsa_wiener_attack.py
#   4) 自测演示:
#        python rsa_wiener_attack.py --selftest
# 依赖: pip install pycryptodome gmpy2      （gmpy2 没有也能跑，纯 int 兜底）
# 参考: https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_d_low/
#       Wiener, M.J. "Cryptanalysis of Short RSA Secret Exponents" (1990)
import sys
import argparse

try:
    from Crypto.PublicKey import RSA
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False


def continued_fraction(a, b):
    """返回 a/b 的连分数展开系数列表。"""
    cf = []
    while b:
        cf.append(a // b)
        a, b = b, a % b
    return cf


def convergents(cf):
    """由连分数系数逐个生成收敛分数 (分子, 分母)。"""
    n0, n1 = 0, 1
    d0, d1 = 1, 0
    for x in cf:
        n0, n1 = n1, x * n1 + n0
        d0, d1 = d1, x * d1 + d0
        yield n1, d1


def wiener_attack(e, n):
    """Wiener 攻击，成功返回 d，失败返回 None。"""
    for k, d in convergents(continued_fraction(e, n)):
        if k == 0:
            continue
        # e*d - 1 = k*phi(n)
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # x^2 - (n - phi + 1)x + n = 0 的两个根即 p、q
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        t = isqrt(disc)
        if t * t != disc:
            continue
        if (s + t) % 2 != 0:
            continue
        p, q = (s + t) // 2, (s - t) // 2
        if p * q == n and p > 1 and q > 1:
            return d
    return None


def isqrt(x):
    try:
        from gmpy2 import iroot
        r, exact = iroot(int(x), 2)
        return int(r)
    except Exception:
        r = int(int(x) ** 0.5)
        while (r + 1) ** 2 <= x:
            r += 1
        while r * r > x:
            r -= 1
        return r


def load_pub(path):
    with open(path, "rb") as f:
        k = RSA.import_key(f.read())
    return k.n, k.e


def selftest():
    # 故意构造 d 很小的 RSA（p、q 取大素数，d 取小值反推 e）
    from Crypto.Util.number import getPrime, inverse
    p, q = getPrime(512), getPrime(512)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = 0x10001  # 很小的 d
    e = inverse(d, phi)
    m = 123456789
    c = pow(m, e, n)
    d2 = wiener_attack(e, n)
    assert d2 == d, "Wiener 自测失败"
    assert pow(c, d2, n) == m
    print(f"[+] selftest OK, d = {hex(d2)}")


def main():
    ap = argparse.ArgumentParser(description="RSA Wiener 小 d 攻击")
    ap.add_argument("--n", type=int)
    ap.add_argument("--e", type=int)
    ap.add_argument("--c", type=int, help="密文整数，可选")
    ap.add_argument("--pub", help="PEM 公钥文件，可选")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        selftest()
        return

    n, e, c = a.n, a.e, a.c
    if a.pub:
        if not HAVE_CRYPTO:
            print("[!] 需要 pip install pycryptodome")
            return
        n, e = load_pub(a.pub)
    if not (n and e):
        try:
            n = int(input("n = ").strip(), 0)
            e = int(input("e = ").strip(), 0)
            cs = input("c = (可直接回车跳过) ").strip()
            c = int(cs, 0) if cs else None
        except Exception as ex:
            print("[!] 输入无效:", ex)
            return

    print(f"[*] n = {n}")
    print(f"[*] e = {e}")
    d = wiener_attack(e, n)
    if d is None:
        print("[-] Wiener 攻击未成功（d 可能不够小），可尝试 Fermat/Coppersmith/分解 n")
        return
    print(f"[+] 还原私钥指数 d = {d}")
    print(f"    hex: {hex(d)}")
    if c is not None:
        m = pow(c, d, n)
        print(f"[+] m = {m}")
        try:
            b = m.to_bytes((m.bit_length() + 7) // 8, "big")
            print(f"[+] flag = {b.decode('utf-8', 'replace')}")
        except Exception:
            pass


if __name__ == "__main__":
    main()
