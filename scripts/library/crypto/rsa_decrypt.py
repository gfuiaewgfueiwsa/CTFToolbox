# -*- coding: utf-8 -*-
# 脚本名称: RSA 常规解密（已知 d，或已知 p/q，或 PEM 私钥）
# 方向: Crypto（密码学 / RSA）
# 简介: 拿到 n、e、c 后，只要再知道 d、或 p/q 分解、或私钥 PEM 文件，
#       本脚本完成最后的解密并输出 flag 文本；支持十六进制/十进制整数。
# 用法:
#   已知 d:       python rsa_decrypt.py --n <n> --e <e> --d <d> --c <c>
#   已知 p、q:    python rsa_decrypt.py --n <n> --e <e> --p <p> --q <q> --c <c>
#   有私钥文件:   python rsa_decrypt.py --key private.pem --c <c(整数)>  或 --cf cipher.bin
#   密文文件:     --cf 直接读取原始二进制密文（大端整数）
#   python rsa_decrypt.py --selftest
# 依赖: pip install pycryptodome
# 参考: https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_theory/
import argparse


def dec_with_factors(n, e, c, p, q):
    assert p * q == n, "p*q != n"
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return pow(c, d, n), d


def main():
    ap = argparse.ArgumentParser(description="RSA 常规解密")
    ap.add_argument("--n", type=lambda x: int(x, 0))
    ap.add_argument("--e", type=lambda x: int(x, 0))
    ap.add_argument("--d", type=lambda x: int(x, 0))
    ap.add_argument("--p", type=lambda x: int(x, 0))
    ap.add_argument("--q", type=lambda x: int(x, 0))
    ap.add_argument("--c", type=lambda x: int(x, 0))
    ap.add_argument("--cf", help="密文二进制文件（大端）")
    ap.add_argument("--key", help="PEM 私钥文件")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        from Crypto.PublicKey import RSA
        from Crypto.Util.number import getPrime
        p, q = getPrime(512), getPrime(512)
        k = RSA.construct((p * q, 65537, pow(65537, -1, (p-1)*(q-1)), p, q))
        m = int.from_bytes(b"flag{rsa_decrypt_ok}", "big")
        c = pow(m, k.e, k.n)
        m2, d2 = dec_with_factors(k.n, k.e, c, p, q)
        assert m2 == m
        print("[+] selftest OK")
        return

    if a.key:
        from Crypto.PublicKey import RSA
        k = RSA.import_key(open(a.key, "rb").read())
        if a.cf:
            c = int.from_bytes(open(a.cf, "rb").read(), "big")
        else:
            c = a.c
        m = pow(c, k.d, k.n)
    else:
        if a.cf:
            c = int.from_bytes(open(a.cf, "rb").read(), "big")
        else:
            c = a.c
        if a.d:
            m = pow(c, a.d, a.n)
        elif a.p and a.q:
            m, d = dec_with_factors(a.n, a.e or 65537, c, a.p, a.q)
            print("[+] d =", d)
        else:
            print("[!] 需要 --d 或 --p/--q 或 --key")
            return
    bs = m.to_bytes((m.bit_length() + 7) // 8, "big")
    print("[+] m =", m)
    print("[+] flag =", bs.decode("utf-8", "replace"))


if __name__ == "__main__":
    main()
