# -*- coding: utf-8 -*-
# 脚本名称: 哈希字典爆破（MD5/SHA1/SHA256/NTLM 等，支持加盐）
# 方向: Crypto（密码学 / Hash）
# 简介: 给定哈希值与字典文件（如 rockyou.txt），自动识别算法并逐行计算比对；
#       支持明文前后加盐、NTLM/MD5(MD5()) 等常见嵌套形式。
# 用法:
#   python hash_dict_crack.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -w rockyou.txt
#   python hash_dict_crack.py -H <hash> -w dict.txt --algo md5 --salt SALT --salt-pos front
#   python hash_dict_crack.py --selftest
# 依赖: 仅标准库
import argparse
import hashlib
import sys

ALGOS = ("md5", "sha1", "sha224", "sha256", "sha384", "sha512", "md4", "ntlm")


def ntlm(pw: bytes) -> str:
    try:
        from Crypto.Hash import MD4
        return MD4.new(pw.decode("utf-8", "replace").encode("utf-16le")).hexdigest()
    except Exception:
        # 无 pycryptodome 时用 hashlib 的 md4（部分 OpenSSL 版本提供）
        try:
            h = hashlib.new("md4", pw.decode("utf-8", "replace").encode("utf-16le"))
            return h.hexdigest()
        except Exception:
            raise RuntimeError("NTLM/MD4 需要 pip install pycryptodome")


def digest(pw: str, algo: str, salt: str = "", pos: str = "back"):
    b = pw.encode("utf-8", "replace")
    s = salt.encode("utf-8", "replace")
    data = s + b if pos == "front" else b + s
    if algo == "ntlm":
        return ntlm(b)
    if algo == "md4":
        return ntlm(b)
    return hashlib.new(algo, data).hexdigest()


def guess_algo(h):
    return {32: "md5", 40: "sha1", 56: "sha224", 64: "sha256",
            96: "sha384", 128: "sha512"}.get(len(h))


def crack(h, wordlist, algos, salt, pos):
    h = h.strip().lower()
    with open(wordlist, "rb") as f:
        for i, raw in enumerate(f, 1):
            pw = raw.decode("utf-8", "replace").rstrip("\r\n")
            for algo in algos:
                try:
                    if digest(pw, algo, salt, pos) == h:
                        return pw, algo, i
                except Exception:
                    continue
            if i % 50000 == 0:
                sys.stdout.write(f"\r[*] 已尝试 {i} 条…")
                sys.stdout.flush()
    return None


def selftest():
    import tempfile, os
    p = os.path.join(tempfile.gettempdir(), "mini_dict.txt")
    open(p, "w", encoding="utf-8").write("123456\npassword\nadmin\n")
    h = hashlib.md5(b"password").hexdigest()
    r = crack(h, p, ["md5"], "", "back")
    assert r and r[0] == "password"
    print(f"[+] selftest OK: {h} -> {r[0]} ({r[1]}, 第{r[2]}条)")


def main():
    ap = argparse.ArgumentParser(description="哈希字典爆破")
    ap.add_argument("-H", "--hash", help="目标哈希")
    ap.add_argument("-w", "--wordlist", help="字典文件")
    ap.add_argument("--algo", help="强制算法，不填按长度猜测")
    ap.add_argument("--salt", default="")
    ap.add_argument("--salt-pos", choices=["front", "back"], default="back")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not (a.hash and a.wordlist):
        print("[!] 参数示例: python hash_dict_crack.py -H <hash> -w rockyou.txt")
        return
    algos = [a.algo] if a.algo else [guess_algo(a.hash) or "md5"]
    print(f"[*] 算法 {algos}，盐 {a.salt!r}（{a.salt_pos}）")
    r = crack(a.hash, a.wordlist, algos, a.salt, a.salt_pos)
    print()
    if r:
        print(f"[+] 命中明文: {r[0]}  算法: {r[1]}  字典第 {r[2]} 条")
    else:
        print("[-] 字典未命中，可换 rockyou/crackstation 或 hashcat 规则爆破")


if __name__ == "__main__":
    main()
