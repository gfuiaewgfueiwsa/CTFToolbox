# -*- coding: utf-8 -*-
# 脚本名称: ECDSA 随机数 k 复用恢复私钥
# 方向: Crypto（密码学 / 椭圆曲线）
# 简介: ECDSA 两次签名复用了相同随机数 k（索尼 PS3 经典漏洞）时，
#       由两组 (r, s, z) 可直接求 k，再反解私钥 d。脚本内置 secp256k1 / P-256
#       曲线参数，纯 Python 实现；两次签名 r 相同即说明 k 复用。
# 用法:
#   python ecdsa_nonce_reuse.py
#       交互输入两组签名 (r,s) 与消息哈希 z（十六进制）
#   python ecdsa_nonce_reuse.py --curve p256
#   python ecdsa_nonce_reuse.py --selftest
# 依赖: 仅标准库
# 参考: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
import argparse

P256K1 = dict(
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a=0, b=7,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    G=(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
       0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8))

P256 = dict(
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    a=-3,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    G=(0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
       0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5))


def ec_mul(curve, d, P=None):
    p, a = curve["p"], curve["a"]
    if P is None:
        P = curve["G"]

    def add(P1, P2):
        if P1 is None:
            return P2
        if P2 is None:
            return P1
        x1, y1 = P1
        x2, y2 = P2
        if x1 == x2 and (y1 + y2) % p == 0:
            return None
        if P1 == P2:
            lam = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
        else:
            lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
        x3 = (lam * lam - x1 - x2) % p
        return x3, (lam * (x1 - x3) - y1) % p

    R = None
    Q = P
    while d:
        if d & 1:
            R = add(R, Q)
        Q = add(Q, Q)
        d >>= 1
    return R


def sign_with_k(curve, d, k, z):
    n = curve["n"]
    r = ec_mul(curve, k)[0] % n
    s = pow(k, -1, n) * (z + r * d) % n
    return r, s


def recover_k_and_d(n, r, s1, s2, z1, z2):
    k = (z1 - z2) * pow(s1 - s2, -1, n) % n
    d = (s1 * k - z1) * pow(r, -1, n) % n
    return k, d


def selftest():
    cv = P256K1
    d, k = 0x1234567890abcdef, 0xdeadbeefcafe
    z1, z2 = 111111, 222222
    r1, s1 = sign_with_k(cv, d, k, z1)
    r2, s2 = sign_with_k(cv, d, k, z2)
    assert r1 == r2
    kk, dd = recover_k_and_d(cv["n"], r1, s1, s2, z1, z2)
    assert kk == k and dd == d, (hex(kk), hex(dd))
    print("[+] selftest OK")
    print("    恢复 k =", hex(k))
    print("    私钥 d =", hex(d))


def main():
    ap = argparse.ArgumentParser(description="ECDSA k 复用恢复私钥")
    ap.add_argument("--curve", choices=["secp256k1", "p256"], default="secp256k1")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    cv = P256K1 if a.curve == "secp256k1" else P256
    print("全部输入十六进制（不带 0x 也可），两次签名 r 相同才说明 k 复用")
    r = int(input("r  (两次签名相同) = ").strip(), 16)
    s1 = int(input("s1 = ").strip(), 16)
    s2 = int(input("s2 = ").strip(), 16)
    z1 = int(input("z1 (消息1哈希整数) = ").strip(), 16)
    z2 = int(input("z2 (消息2哈希整数) = ").strip(), 16)
    k, d = recover_k_and_d(cv["n"], r, s1, s2, z1, z2)
    print("[+] k =", hex(k))
    print("[+] 私钥 d =", hex(d))
    Q = ec_mul(cv, d)
    print("[+] 公钥 Qx =", hex(Q[0]))
    print("    Qy =", hex(Q[1]))


if __name__ == "__main__":
    main()
