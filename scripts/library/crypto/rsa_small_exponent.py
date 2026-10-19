# -*- coding: utf-8 -*-
# 脚本名称: RSA 低加密指数攻击（e 很小 / 未填充开方）
# 方向: Crypto（密码学 / RSA）
# 简介: e=3、e=5、e=7 等很小且明文未做填充时，密文 c = m^e mod n，
#       若 m^e < n 则直接对 c 开 e 次方；即使 m^e = c + k*n（k 较小），
#       枚举 k 后开方也可还原明文。Hastad 广播攻击（同一明文、相同小 e、多组 n）
#       本质是 CRT 后开方，本脚本也一并支持。
# 用法:
#   单组: python rsa_small_exponent.py --e 3 --n <n> --c <c> [--kmax 100000]
#   广播: python rsa_small_exponent.py --e 3 --pairs n1,c1,n2,c2,n3,c3
#   自测: python rsa_small_exponent.py --selftest
# 依赖: pip install gmpy2（无则使用整数开方兜底，速度较慢）
# 参考: https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_e_attack/
import argparse


def iroot(x, k):
    """对 x 开 k 次整数方，返回 (root, exact)。"""
    try:
        from gmpy2 import iroot as _ir
        r, ok = _ir(int(x), k)
        return int(r), bool(ok)
    except Exception:
        lo, hi = 0, 1
        while hi ** k < x:
            hi *= 2
        while lo <= hi:
            mid = (lo + hi) // 2
            v = mid ** k
            if v == x:
                return mid, True
            if v < x:
                lo = mid + 1
            else:
                hi = mid - 1
        return hi, False


def small_e_single(e, n, c, kmax=200000):
    """枚举 m^e = c + k*n，开方还原。"""
    for k in range(kmax + 1):
        r, exact = iroot(c + k * n, e)
        if exact:
            return r, k
    return None, None


def crt(pairs):
    """中国剩余定理，pairs=[(余数, 模数), ...]，返回 (x, N)。"""
    from functools import reduce
    N = reduce(lambda a, b: a * b, [m for _, m in pairs])
    x = 0
    for r, m in pairs:
        Mi = N // m
        x += r * Mi * pow(Mi, -1, m)
    return x % N, N


def to_bytes(m):
    return m.to_bytes((m.bit_length() + 7) // 8, "big")


def selftest():
    from Crypto.Util.number import getPrime
    # 情形1：m^3 < n，直接开立方
    p, q = getPrime(1024), getPrime(1024)
    n = p * q
    e = 3
    m = int.from_bytes(b"flag{small_e_direct}", "big")
    assert m ** 3 < n
    c = pow(m, e, n)
    r, k = small_e_single(e, n, c)
    assert r == m, "单组开方失败"
    print("[+] 单组低指数 OK:", to_bytes(r).decode())
    # 情形2：三组广播 CRT
    ns, cs = [], []
    mm = int.from_bytes(b"flag{hastad_crt}", "big")
    for _ in range(3):
        n3 = getPrime(1024) * getPrime(1024)
        ns.append(n3)
        cs.append(pow(mm, 3, n3))
    pairs = list(zip(cs, ns))
    x, N = crt(pairs)
    r2, exact = iroot(x, 3)
    assert exact and r2 == mm
    print("[+] Hastad 广播 CRT OK:", to_bytes(r2).decode())
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="RSA 低指数 / Hastad 广播攻击")
    ap.add_argument("--e", type=int)
    ap.add_argument("--n", type=int)
    ap.add_argument("--c", type=int)
    ap.add_argument("--kmax", type=int, default=200000)
    ap.add_argument("--pairs", type=int, nargs="*",
                    help="广播攻击: n1 c1 n2 c2 n3 c3 ...（偶数个整数）")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest()
        return

    if a.pairs:
        assert len(a.pairs) % 2 == 0 and a.e, "广播攻击需要 --e 与偶数个 --pairs 参数"
        vals = a.pairs
        pairs = [(vals[i + 1], vals[i]) for i in range(0, len(vals), 2)]  # (c,n)
        x, N = crt(pairs)
        r, exact = iroot(x, a.e)
        if exact:
            print("[+] CRT 开方成功:", to_bytes(r).decode("utf-8", "replace"))
        else:
            print("[-] CRT 后开方不整，可能存在填充或 e 与组数不符")
        return

    if not (a.e and a.n and a.c):
        a.e = int(input("e = ").strip(), 0)
        a.n = int(input("n = ").strip(), 0)
        a.c = int(input("c = ").strip(), 0)
    m, k = small_e_single(a.e, a.n, a.c, a.kmax)
    if m is None:
        print(f"[-] k 枚举到 {a.kmax} 仍未开方成功，可加大 --kmax 或换思路")
        return
    print(f"[+] 命中 k={k}")
    print("[+] flag =", to_bytes(m).decode("utf-8", "replace"))


if __name__ == "__main__":
    main()
