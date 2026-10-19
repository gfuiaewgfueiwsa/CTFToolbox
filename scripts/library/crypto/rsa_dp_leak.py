# -*- coding: utf-8 -*-
# 脚本名称: RSA dp/dq 泄露恢复（低 16 位 / CRT 参数泄露）
# 方向: Crypto（密码学 / RSA）
# 简介: 题目给出 n、e、c 以及 CRT 参数 dp = d mod (p-1)（或 dq）时，
#       枚举 kp∈[1,e-1]：若 (e*dp-1) 能被 kp 整除，则 p=(e*dp-1)/kp+1，
#       进而得到 q、d 并解密。e=65537 时枚举量极小，瞬间完成。
# 用法:
#   python rsa_dp_leak.py --n <n> --e <e> --dp <dp> --c <c>
#   若泄露的是 dq，加 --dq <dq>
#   python rsa_dp_leak.py --selftest
# 依赖: 仅标准库（自测需 pycryptodome）
# 参考: https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_crt/
import argparse


def recover_p_from_dp(n, e, dp):
    """由 dp 枚举恢复 p，返回 p 或 None。"""
    for kp in range(1, e):
        num = e * dp - 1
        if num % kp:
            continue
        p = num // kp + 1
        if p > 1 and n % p == 0:
            return p
    return None


def recover_q_from_dq(n, e, dq):
    """由 dq 枚举恢复 q。"""
    for kq in range(1, e):
        num = e * dq - 1
        if num % kq:
            continue
        q = num // kq + 1
        if q > 1 and n % q == 0:
            return q
    return None


def attack(n, e, c, dp=None, dq=None):
    p = q = None
    if dp is not None:
        p = recover_p_from_dp(n, e, dp)
        if p:
            q = n // p
    if dq is not None:
        q = q or recover_q_from_dq(n, e, dq)
        if q and not p:
            p = n // q
    if not p or not q or p * q != n:
        return None
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    return p, q, d, m


def selftest():
    from Crypto.Util.number import getPrime
    p, q = getPrime(512), getPrime(512)
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    dp, dq = d % (p - 1), d % (q - 1)
    m = int.from_bytes(b"flag{dp_leak_ok}", "big")
    c = pow(m, e, n)
    r = attack(n, e, c, dp=dp)
    assert r and r[3] == m
    print("[+] dp 路径 OK:", r[3].to_bytes((r[3].bit_length()+7)//8, "big").decode())
    r2 = attack(n, e, c, dq=dq)
    assert r2 and r2[3] == m
    print("[+] dq 路径 OK")
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="RSA dp/dq 泄露恢复")
    ap.add_argument("--n", type=int)
    ap.add_argument("--e", type=int, default=65537)
    ap.add_argument("--c", type=int)
    ap.add_argument("--dp", type=int)
    ap.add_argument("--dq", type=int)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest()
        return
    if not a.n:
        a.n = int(input("n = ").strip(), 0)
        a.e = int(input("e = ").strip(), 0)
        a.c = int(input("c = ").strip(), 0)
        v = input("dp = (没有就回车) ").strip()
        a.dp = int(v, 0) if v else None
        v = input("dq = (没有就回车) ").strip()
        a.dq = int(v, 0) if v else None
    r = attack(a.n, a.e, a.c, a.dp, a.dq)
    if not r:
        print("[-] 恢复失败，请确认 dp/dq 数值与 n、e 对应")
        return
    p, q, d, m = r
    print("[+] p =", p)
    print("[+] q =", q)
    print("[+] d =", d)
    print("[+] flag =", m.to_bytes((m.bit_length()+7)//8, "big").decode("utf-8", "replace"))


if __name__ == "__main__":
    main()
