# -*- coding: utf-8 -*-
# 脚本名称: RC4 加解密（同一函数加解密互逆）
# 方向: Crypto（密码学 / 流密码）
# 简介: RC4 是 CTF 高频流密码，KSA 初始化 256 字节状态盒、PRGA 生成密钥流，
#       加密与解密是同一个异或过程。支持字符串/十六进制输入输出。
# 用法:
#   加密（输出 hex）: python rc4.py --key 'passw0rd' --enc --text 'hello'
#   解密（hex 入）:  python rc4.py --key 'passw0rd' --dec -x a1b2c3...
#   解密文件:        python rc4.py --key 'k' -f cipher.bin -o plain.bin
#   python rc4.py --selftest
# 依赖: 仅标准库
def rc4(key: bytes, data: bytes) -> bytes:
    """标准 RC4，返回密钥流异或后的字节（加解密同一函数）。"""
    # ---- KSA ----
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    # ---- PRGA ----
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) & 0xff])
    return bytes(out)


def selftest():
    # RFC 6229 标准测试向量: key=Key, plaintext=Plaintext, 期望密文前缀 BBF316E8D940AF0AD3
    ct = rc4(b"Key", b"Plaintext")
    assert ct.hex().upper().startswith("BBF316E8D940AF0AD3"), ct.hex()
    assert rc4(b"Key", ct) == b"Plaintext"
    print("[+] selftest OK (RFC6229 向量通过):", ct.hex())


def main():
    import argparse
    ap = argparse.ArgumentParser(description="RC4 加解密")
    ap.add_argument("--key")
    ap.add_argument("--text")
    ap.add_argument("-x", "--hex")
    ap.add_argument("-f", "--file")
    ap.add_argument("-o", "--out")
    ap.add_argument("--enc", action="store_true")
    ap.add_argument("--dec", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.key:
        ap.print_help(); return
    key = a.key.encode()
    if a.file:
        data = open(a.file, "rb").read()
    elif a.hex:
        data = bytes.fromhex(a.hex.replace(" ", ""))
    elif a.text:
        data = a.text.encode()
    else:
        print("[!] 需要 --text/-x/-f"); return
    res = rc4(key, data)
    if a.out:
        open(a.out, "wb").write(res)
        print("[+] 已写入", a.out)
    else:
        try:
            print("[+] 文本:", res.decode("utf-8"))
        except Exception:
            pass
        print("[+] HEX :", res.hex())
        import base64
        print("[+] B64 :", base64.b64encode(res).decode())


if __name__ == "__main__":
    main()
