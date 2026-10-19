# -*- coding: utf-8 -*-
# 脚本名称: RSA 多模数批量 GCD（公约数攻击 / 心脏出血式公钥碰撞）
# 方向: Crypto（密码学 / RSA）
# 简介: 一批 RSA 公钥中若有任意两对共享素数（错误地复用了随机数），
#       gcd(n1,n2) 即给出共同素因子。支持两种输入：
#       1) 文本文件，每行一个十进制/0x 十六进制 n；
#       2) 多个 PEM 公钥文件（--pub a.pem b.pem ...）。
# 用法:
#   python rsa_batch_gcd.py --ns ns.txt
#   python rsa_batch_gcd.py --pub a.pem b.pem c.pem
#   python rsa_batch_gcd.py --selftest
# 依赖: 仅标准库（读 PEM 需要 pip install pycryptodome）
# 参考: https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_brainpool/  （批量 GCD 思想）
import argparse
from math import gcd


def batch_gcd(ns):
    """O(k^2) 两两求 GCD，返回 [(i, j, p, q_i, q_j), ...] 命中列表。"""
    hits = []
    k = len(ns)
    for i in range(k):
        for j in range(i + 1, k):
            g = gcd(ns[i], ns[j])
            if g not in (1, ns[i], ns[j]):
                hits.append((i, j, g, ns[i] // g, ns[j] // g))
    return hits


def load_ns_file(path):
    ns = []
    for line in open(path, "r", encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ns.append(int(line, 0))
    return ns


def load_pubs(paths):
    from Crypto.PublicKey import RSA
    out = []
    for p in paths:
        k = RSA.import_key(open(p, "rb").read())
        out.append(k.n)
    return out


def selftest():
    from Crypto.Util.number import getPrime
    shared, other1, other2 = getPrime(512), getPrime(512), getPrime(512)
    ns = [shared * other1, getPrime(512) * getPrime(512), shared * other2]
    hits = batch_gcd(ns)
    assert len(hits) == 1 and hits[0][0] == 0 and hits[0][1] == 2
    print("[+] selftest OK: n0 与 n2 共享素数", hex(hits[0][2])[:34], "...")


def main():
    ap = argparse.ArgumentParser(description="RSA 批量 GCD")
    ap.add_argument("--ns", help="每行一个 n 的文本文件")
    ap.add_argument("--pub", nargs="*", help="PEM 公钥文件列表")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest()
        return
    if a.pub:
        ns = load_pubs(a.pub)
    elif a.ns:
        ns = load_ns_file(a.ns)
    else:
        print("[!] 用法见脚本头部注释：--ns 文件 或 --pub 公钥列表")
        return
    print(f"[*] 共 {len(ns)} 个模数，开始两两 GCD …")
    hits = batch_gcd(ns)
    if not hits:
        print("[-] 未发现共享素数")
        return
    for i, j, g, qi, qj in hits:
        print(f"[+] n[{i}] 与 n[{j}] 共享因子:")
        print(f"    p = {g}")
        print(f"    n[{i}] 的另一个因子 = {qi}")
        print(f"    n[{j}] 的另一个因子 = {qj}")
        print("    随后可用 rsa_decrypt.py 配合各自 e、c 解密")


if __name__ == "__main__":
    main()
