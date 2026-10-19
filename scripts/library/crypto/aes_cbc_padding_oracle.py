# -*- coding: utf-8 -*-
# 脚本名称: AES-CBC Padding Oracle 攻击（填充错误预言机）
# 方向: Crypto（密码学 / 分组密码 / 选择密文）
# 简介: 当服务器对 CBC 密文解密后是否发生 PKCS7 填充错误给出不同响应
#       （报错/状态码/耗时差异）时，无需密钥即可逐字节还原明文，
#       也可伪造任意明文的密文（加密预言机）。脚本内置本地演示靶场，
#       实战时把 request_oracle 替换为与题目交互的函数即可。
# 用法:
#   python aes_cbc_padding_oracle.py --selftest     # 本地靶场自测（16字节）
#   实战：修改 TARGET 部分的 request_oracle(cipher_bytes)->bool，
#         再 python aes_cbc_padding_oracle.py --hex <密文hex(含IV)>
# 依赖: pip install pycryptodome
# 参考: https://ctf-wiki.org/crypto/blockcipher/padding-oracle/
import argparse
import sys

BLOCK = 16


# ---------------- 本地演示靶场（实战时删除/替换） ----------------
def demo_server(key: bytes, iv: bytes, cookie: bytes):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad

    def encrypt():
        c = AES.new(key, AES.MODE_CBC, iv)
        return iv + c.encrypt(pad(cookie, BLOCK))

    def oracle(ct: bytes):
        """返回 True=填充合法，False=填充错误（题目侧信道）。"""
        try:
            c = AES.new(key, AES.MODE_CBC, ct[:BLOCK])
            unpad(c.decrypt(ct[BLOCK:]), BLOCK)
            return True
        except Exception:
            return False
    return encrypt, oracle


def padding_oracle_decrypt(ct: bytes, oracle, block=BLOCK, log=True):
    """对 CBC 密文（IV+C）做 padding oracle 解密，返回明文（已去填充）。"""
    blocks = [ct[i:i + block] for i in range(0, len(ct), block)]
    plain = b""
    for bi in range(1, len(blocks)):
        prev, cur = blocks[bi - 1], blocks[bi]
        recovered = bytearray(block)
        for padlen in range(1, block + 1):
            pos = block - padlen
            # 关键：C'[k] = P[k] XOR padlen XOR C_prev[k]
            # （P[k]=recovered[k] 为已恢复明文，C_prev 为原密文前一块/IV）
            prefix = bytearray(block)
            for k in range(pos + 1, block):
                prefix[k] = recovered[k] ^ padlen ^ prev[k]
            found = False
            for g in range(256):
                prefix[pos] = g
                if oracle(bytes(prefix) + cur):
                    # 处理 padlen=1 时的歧义：翻转前一字节再验一次
                    if padlen == 1 and pos > 0:
                        t = bytearray(prefix)
                        t[pos - 1] ^= 0xff
                        if not oracle(bytes(t) + cur):
                            continue
                    recovered[pos] = g ^ padlen ^ prev[pos]
                    found = True
                    break
            if not found:
                raise RuntimeError(f"第 {bi} 块第 {pos} 字节未爆破成功，预言机可能不稳定")
        plain += bytes(recovered)
        if log:
            sys.stdout.write(f"\r[*] 已解 {bi}/{len(blocks)-1} 块: {plain[:40]!r}")
            sys.stdout.flush()
    if log:
        print()
    # 去 PKCS7
    padn = plain[-1]
    if 1 <= padn <= block and plain[-padn:] == bytes([padn]) * padn:
        plain = plain[:-padn]
    return plain


def selftest():
    import os
    from Crypto.Cipher import AES
    key = os.urandom(16)
    iv = os.urandom(16)
    secret = b"flag{pad_oracle"   # 16 字节，自测快
    enc, oracle = demo_server(key, iv, secret)
    ct = enc()
    pt = padding_oracle_decrypt(ct, oracle)
    assert pt == secret, (pt, secret)
    print("[+] selftest OK:", pt.decode())


def main():
    ap = argparse.ArgumentParser(description="AES-CBC Padding Oracle")
    ap.add_argument("--hex", help="IV+密文 的十六进制字符串")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest or not a.hex:
        selftest()
        return
    ct = bytes.fromhex(a.hex.replace(" ", ""))

    # ====== 实战：把下面函数改成与题目交互 ======
    # 示例（HTTP）:
    # import requests
    # def request_oracle(data: bytes) -> bool:
    #     r = requests.get("http://target/decrypt",
    #                      params={"c": data.hex()}, timeout=10)
    #     return "padding error" not in r.text
    def request_oracle(data: bytes) -> bool:
        raise NotImplementedError("请按题目实现 request_oracle（返回 True 表示填充正确）")

    pt = padding_oracle_decrypt(ct, request_oracle)
    print("[+] 明文:", pt)


if __name__ == "__main__":
    main()
