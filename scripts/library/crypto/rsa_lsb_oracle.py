# -*- coding: utf-8 -*-
# 脚本名称: RSA LSB 奇偶预言机攻击（Padding Oracle / Parity Oracle）
# 方向: Crypto（密码学 / RSA / 选择密文）
# 简介: 题目提供一个解密预言机，输入密文返回解密结果的奇偶性（最低位）
#       或大小关系（M^3 比较）时，可通过不断把密文乘 2^e 二分逼近明文，
#       逐位还原明文。典型场景：RSA 智能卡、Web 解密接口、题目给了 oracle 脚本。
# 用法:
#   1) 本文件是【利用模板】，先在脚本中按题目情况实现 oracle(c)->0/1；
#   2) python rsa_lsb_oracle.py          会用内置自测 RSA 演示完整攻击；
#      实战时把 DemoOracle 替换为与题目交互的逻辑（pwntools remote / requests）。
# 依赖: pip install pwntools（仅实战联网时；自测仅需 pycryptodome）
# 参考: https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_chosen_plain_cipher/
import sys


class DemoOracle:
    """自测用：本地持有私钥的奇偶预言机。实战时替换掉这个类。

    实战模板（pwntools）:
        from pwn import *
        context.log_level = 'warning'
        io = remote('10.10.10.10', 9999)
        def oracle(c_int):
            io.sendlineafter('c = ', str(c_int).encode())
            return int(io.recvline().strip())   # 题目返回明文奇偶 0/1
    """
    def __init__(self, n, d):
        self.n, self.d = n, d

    def parity(self, c):
        return pow(c, self.d, self.n) & 1


def lsb_attack(c, e, n, oracle, bits=None, log_every=64):
    """奇偶预言机二分攻击，返回明文整数。"""
    bits = bits or n.bit_length()
    lo, hi = 0, n
    mul = pow(2, e, n)
    cc = c
    for i in range(bits):
        cc = (cc * mul) % n
        if oracle(cc) == 1:           # 2^(i+1) * m mod n 为奇数 => 越过了 n 的奇数倍
            lo = (lo + hi) // 2
        else:
            hi = (lo + hi) // 2
        if i % log_every == 0:
            sys.stdout.write(f"\r[*] 已恢复 {i+1}/{bits} bit")
            sys.stdout.flush()
    print()
    return hi


def selftest():
    from Crypto.Util.number import getPrime
    p, q = getPrime(512), getPrime(512)
    n = p * q
    e = 65537
    d = pow(e, -1, (p - 1) * (q - 1))
    flag = b"flag{lsb_oracle_ok_2026}"
    m = int.from_bytes(flag, "big")
    c = pow(m, e, n)
    rec = lsb_attack(c, e, n, DemoOracle(n, d).parity)
    # 二分量化存在小幅累计误差，在 ±4096 邻域内按 flag{...} 形态搜索真实明文
    import re
    pat = re.compile(rb"flag\{[ -~]{1,100}\}")
    for delta in range(0, 4097):
        for cand in ((rec + delta) if delta == 0 else rec + delta, rec - delta):
            if cand <= 0:
                continue
            b = cand.to_bytes((cand.bit_length() + 7) // 8, "big")
            mobj = pat.search(b)
            if mobj and mobj.group() == flag:
                print("[+] selftest OK (delta=%d):" % delta, mobj.group())
                return
    bs = rec.to_bytes((rec.bit_length() + 7) // 8, "big")
    raise AssertionError("攻击结果未命中 flag: %r" % bs)


if __name__ == "__main__":
    selftest()
