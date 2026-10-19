# -*- coding: utf-8 -*-
"""编码 / 解码 / 古典密码 / 哈希 全家桶。"""
import re
import base64
import hashlib
import codecs
import html
import urllib.parse
from string import ascii_lowercase, ascii_uppercase, ascii_letters, digits

# ----------------------------------------------------------------------------
# 可读性评分（用于自动判断哪一种解码是“对的”）
# ----------------------------------------------------------------------------
COMMON_WORDS = ["flag", "the", "key", "ctf", "you", "and", "for", "are",
                "http", "www", "com", "pass", "secret", "admin", "is", "in",
                "to", "of", "that", "this", "成功", "密码", " flag"]

def readable_score(s: str) -> float:
    if not s:
        return -999
    score = 0.0
    low = s.lower()
    for w in COMMON_WORDS:
        if w in low:
            score += 5
    if re.search(r"[a-zA-Z0-9_]{1,15}\{[^\}]{2,}\}", s):
        score += 50          # 形如 xxx{...}
    cn = len(re.findall(r"[\u4e00-\u9fff]", s))
    printable = sum(1 for c in s if c in "\r\n\t" or 32 <= ord(c) < 127 or 0x4e00 <= ord(c) <= 0x9fff)
    ratio = printable / max(1, len(s))
    score += ratio * 3
    score += min(cn, 20) * 0.5
    # 惩罚乱码
    weird = sum(1 for c in s if ord(c) > 0xffff)
    score -= weird * 2
    return score


def is_readable(s: str) -> bool:
    return readable_score(s) >= 6 and len(s) >= 2

# ----------------------------------------------------------------------------
# 基础编码
# ----------------------------------------------------------------------------
B58_ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B91_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""
B92_ALPHA = "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_abcdefghijklmnopqrstuvwxyz{|}~"

def b58_decode(s: str) -> bytes:
    n = 0
    for c in s.strip():
        if c not in B58_ALPHA:
            raise ValueError("bad char")
        n = n * 58 + B58_ALPHA.index(c)
    pad = len(s) - len(s.lstrip("1"))
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * pad + body

def b91_decode(s: str) -> bytes:
    b, n, v = 0, 0, -1
    out = bytearray()
    for c in s:
        if c not in B91_ALPHA:
            continue
        c = B91_ALPHA.index(c)
        if v < 0:
            v = c
        else:
            v += c * 91
            b |= v << n
            n += 13 if (v & 8191) > 90 else 14
            while True:
                out.append(b & 255)
                b >>= 8
                n -= 8
                if n <= 7:
                    break
            v = -1
    if v >= 0:
        out.append((b | v << n) & 255)
    return bytes(out)

def b92_decode(s: str) -> bytes:
    bitstr = ""
    table = {c: i for i, c in enumerate(B92_ALPHA)}
    i = 0
    while i + 1 < len(s):
        n = table.get(s[i], -1) * 91 + table.get(s[i + 1], -1)
        if n < 0:
            i += 2
            continue
        bitstr += format(n, "013b")
        i += 2
    out = bytearray()
    for j in range(0, len(bitstr) - 7, 8):
        out.append(int(bitstr[j:j + 8], 2))
    return bytes(out)


def _hex_clean(s: str) -> str:
    t = s.strip()
    t = re.sub(r"\\x", "", t)
    t = re.sub(r"0x", "", t, flags=re.I)
    t = t.replace("%", "").replace(",", " ").replace(":", " ")
    t = re.sub(r"\s+", "", t)
    return t

def hex_decode(s: str) -> bytes:
    t = _hex_clean(s)
    if len(t) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", t):
        raise ValueError
    return bytes.fromhex(t)

def binary_decode(s: str, width=8) -> bytes:
    t = re.sub(r"[^01]", "", s)
    if len(t) % width:
        t = t.ljust(len(t) + (width - len(t) % width), "0")
    return bytes(int(t[i:i + width], 2) for i in range(0, len(t), width))

def octal_decode(s: str) -> bytes:
    nums = re.findall(r"\d{1,3}", s)
    return bytes(int(n, 8) for n in nums if int(n, 8) < 256)

def dec_decode(s: str) -> bytes:
    nums = re.findall(r"\d{1,3}", s)
    return bytes(int(n) for n in nums if int(n) < 256)

# ----------------------------------------------------------------------------
# 古典密码
# ----------------------------------------------------------------------------
def caesar(s: str, shift: int) -> str:
    out = []
    for c in s:
        o = ord(c)
        if 97 <= o <= 122:
            out.append(chr((o - 97 + shift) % 26 + 97))
        elif 65 <= o <= 90:
            out.append(chr((o - 65 + shift) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)

def rot47(s: str) -> str:
    out = []
    for c in s:
        o = ord(c)
        if 33 <= o <= 126:
            out.append(chr(33 + (o - 33 + 47) % 94))
        else:
            out.append(c)
    return "".join(out)

def atbash(s: str) -> str:
    out = []
    for c in s:
        o = ord(c)
        if 97 <= o <= 122:
            out.append(chr(122 - (o - 97)))
        elif 65 <= o <= 90:
            out.append(chr(90 - (o - 65)))
        else:
            out.append(c)
    return "".join(out)

MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9",
    ".-.-.-": ".", "--..--": ",", "..--..": "?", "-.-.--": "!",
    "-....-": "-", "-..-.": "/", ".--.-.": "@", "-.--.": "(", "-.--.-": ")",
    "---...": ":", "-.-.-.": ";", ".-...": "&", ".-..-.": '"', "...-..-": "$",
    "..--.-": "_", ".----.": "'", "-...-": "=", ".-.-.": "+",
}
def morse_decode(s: str) -> str:
    t = s.replace("_", "-").replace("，", ",").replace("．", ".")
    words = re.split(r"\s{2,}|/|｜", t)
    res = []
    for w in words:
        chars = w.strip().split()
        res.append("".join(MORSE.get(c, "�") for c in chars if c))
    return " ".join(res)

def fence_decode(s: str, rails: int) -> str:
    n = len(s)
    fence = [[] for _ in range(rails)]
    rail, direction = 0, 1
    for i in range(n):
        fence[rail].append(i)
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1
    order = [i for r in fence for i in r]
    out = [""] * n
    for idx, ch in zip(order, s):
        out[idx] = ch
    return "".join(out)

def vigenere_decode(s: str, key: str) -> str:
    key = key.lower()
    out, ki = [], 0
    for c in s:
        if c.isalpha():
            k = ord(key[ki % len(key)]) - 97
            base = 65 if c.isupper() else 97
            out.append(chr((ord(c) - base - k) % 26 + base))
            ki += 1
        else:
            out.append(c)
    return "".join(out)

def bacon_decode(s: str) -> str:
    t = re.sub(r"[^abAB01]", "", s)
    t = t.replace("A", "a").replace("B", "b").replace("0", "a").replace("1", "b")
    alpha = ascii_uppercase
    out = ""
    for i in range(0, len(t) - 4, 5):
        v = int(t[i:i + 5].replace("a", "0").replace("b", "1"), 2)
        if v < 24:
            out += alpha[v]
        elif v == 24:
            out += "(I/J)"
        elif v == 25:
            out += "(U/V)"
    return out

def brainfuck(s: str) -> str:
    tape = [0] * 30000
    p = 0
    out = []
    stack = []
    pairs = {}
    for i, c in enumerate(s):
        if c == "[":
            stack.append(i)
        elif c == "]":
            j = stack.pop()
            pairs[j] = i
            pairs[i] = j
    i = 0
    while i < len(s):
        c = s[i]
        if c == ">": p += 1
        elif c == "<": p -= 1
        elif c == "+": tape[p] = (tape[p] + 1) % 256
        elif c == "-": tape[p] = (tape[p] - 1) % 256
        elif c == ".": out.append(chr(tape[p]))
        elif c == ",": pass
        elif c == "[":
            if tape[p] == 0:
                i = pairs[i]
        elif c == "]":
            if tape[p] != 0:
                i = pairs[i]
        i += 1
    return "".join(out)

def jwt_decode(s: str) -> str:
    parts = s.strip().split(".")
    if len(parts) < 2:
        raise ValueError
    def dec(p):
        p += "=" * (-len(p) % 4)
        return base64.urlsafe_b64decode(p).decode("utf-8", errors="replace")
    return f"Header: {dec(parts[0])}\nPayload: {dec(parts[1])}\nSignature: {parts[2] if len(parts)>2 else '(none)'}"

# ----------------------------------------------------------------------------
# 统一自动解码：对输入文本把所有合理方式跑一遍，按可读性排序
# ----------------------------------------------------------------------------
def _bytes_to_text(b: bytes) -> str:
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return b.decode(enc)
        except Exception:
            continue
    return b.decode("utf-8", errors="replace")

def auto_decode(text: str, depth: int = 3):
    """返回 [(方法名, 结果, 分数)]，递归链式解码，自动找出最像答案的链路。"""
    results = []
    seen = set()

    def one_pass(t):
        cands = []
        # hex
        try:
            h = _hex_clean(t)
            if len(h) >= 4 and len(h) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", h):
                cands.append(("HEX", _bytes_to_text(hex_decode(t))))
        except Exception:
            pass
        # 01 二进制
        nb = re.sub(r"[^01]", "", t)
        if len(nb) >= 8 and len(nb) / max(1, len(t.strip())) > 0.7:
            try:
                cands.append(("二进制", _bytes_to_text(binary_decode(t))))
            except Exception:
                pass
        # 八进制序列
        if re.fullmatch(r"[\\0-7\s,]{6,}", t.strip()):
            try:
                cands.append(("八进制", _bytes_to_text(octal_decode(t))))
            except Exception:
                pass
        # 十进制序列
        nums = re.findall(r"\d{1,3}", t)
        if len(nums) >= 3 and all(int(x) < 256 for x in nums) and len(", ".join(nums)) > len(t.strip()) * 0.7:
            cands.append(("十进制ASCII", _bytes_to_text(dec_decode(t))))
        # base 系列
        for name, fn in (
            ("Base16", lambda x: base64.b16decode(x.strip().upper())),
            ("Base32", lambda x: base64.b32decode(x.strip().upper() + "=" * (-len(x.strip()) % 8))),
            ("Base64", lambda x: base64.b64decode(x.strip() + "=" * (-len(x.strip()) % 4), validate=False)),
            ("Base64URL", lambda x: base64.urlsafe_b64decode(x.strip() + "=" * (-len(x.strip()) % 4))),
            ("Base85(ascii85)", lambda x: base64.a85decode(x.strip(), adobe=False)),
            ("Base85(b85)", lambda x: base64.b85decode(x.strip())),
            ("Base58", lambda x: b58_decode(x)),
            ("Base91", lambda x: b91_decode(x)),
            ("Base92", lambda x: b92_decode(x)),
        ):
            try:
                b = fn(t)
                if b:
                    cands.append((name, _bytes_to_text(b)))
            except Exception:
                pass
        # URL
        try:
            if "%" in t:
                d = urllib.parse.unquote(t)
                if d != t:
                    cands.append(("URL编码", d))
        except Exception:
            pass
        # unicode / html
        try:
            if re.search(r"\\u[0-9a-fA-F]{4}|&#x?[0-9a-fA-F]+;", t):
                d = codecs.decode(t, "unicode_escape")
                d2 = html.unescape(t)
                cands.append(("Unicode转义", d))
                if d2 != t:
                    cands.append(("HTML实体", d2))
        except Exception:
            pass
        try:
            d = html.unescape(t)
            if d != t and re.search(r"&\w+;|&#\d+;", t):
                cands.append(("HTML实体", d))
        except Exception:
            pass
        # quoted-printable
        try:
            if "=" in t and re.search(r"=[0-9A-F]{2}", t):
                import quopri
                cands.append(("QuotedPrintable", quopri.decodestring(t.encode()).decode("utf-8", "replace")))
        except Exception:
            pass
        # rot/凯撒
        cands.append(("ROT13", caesar(t, 13)))
        cands.append(("ROT47", rot47(t)))
        cands.append(("Atbash", atbash(t)))
        for sh in range(1, 26):
            r = caesar(t, sh)
            if re.search(r"flag|ctf|the|key|you", r, re.I):
                cands.append((f"凯撒偏移{sh}", r))
        # 栅栏
        tt = re.sub(r"\s", "", t)
        if 6 <= len(tt) <= 200:
            for rails in range(2, min(8, len(tt))):
                r = fence_decode(tt, rails)
                if re.search(r"flag|ctf", r, re.I):
                    cands.append((f"栅栏{rails}栏", r))
        # 摩斯
        if re.fullmatch(r"[\.\-\s/_，．]{4,}", t.strip()):
            try:
                cands.append(("摩斯密码", morse_decode(t)))
            except Exception:
                pass
        # brainfuck / ook
        if set(t.strip()) <= set("<>+-.,[] \r\n\t") and len(set(t.strip()) & set("+-<>[].,")) >= 3:
            try:
                cands.append(("Brainfuck", brainfuck(t)))
            except Exception:
                pass
        if "Ook" in t:
            try:
                words = re.findall(r"Ook[.?!]", t)
                # 标准 Ook! -> Brainfuck（. = Ook.  ? = Ook?  ! = Ook!）
                pairmap = {(".", "?"): ">", ("?", "."): "<", (".", "."): "+",
                           ("!", "!"): "-", ("!", "."): ".", (".", "!"): ",",
                           ("!", "?"): "[", ("?", "!"): "]"}
                bf = ""
                for i in range(0, len(words) - 1, 2):
                    bf += pairmap.get((words[i][-1], words[i + 1][-1]), "")
                if bf and any(c in bf for c in "+-<>[]"):
                    cands.append(("Ook!", brainfuck(bf)))
            except Exception:
                pass
        # JWT
        if re.fullmatch(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*", t.strip()):
            try:
                cands.append(("JWT", jwt_decode(t)))
            except Exception:
                pass
        # 培根
        if re.fullmatch(r"[abAB\s]{10,}", t.strip()):
            cands.append(("培根密码", bacon_decode(t)))
        # UUencode / XXencode（收藏夹 chacuo 在线工具离线化）
        try:
            from . import modules_morecode as mm
            if re.search(r"^begin\s+\d{3}\s", t, re.M):
                if re.search(r"(?m)^\s*\+\s*$", t):
                    x = mm.xx_decode(t)
                    if x:
                        cands.append(("XXencode", _bytes_to_text(x)))
                if re.search(r"(?m)^\s*`\s*$", t):
                    u = mm.uu_decode(t)
                    if u:
                        cands.append(("UUencode", _bytes_to_text(u)))
            if mm.looks_like_jother(t):
                from .modules_codes import js_obfuscation_decode
                cands.append(("Jother", js_obfuscation_decode(t)))
        except Exception:
            pass
        return cands

    # 逐层递归
    frontier = [("", text)]
    for d in range(depth):
        nxt = []
        for prefix, t in frontier:
            for name, val in one_pass(t):
                chain = f"{prefix} -> {name}" if prefix else name
                key = (chain, val[:200])
                if key in seen:
                    continue
                seen.add(key)
                sc = readable_score(val)
                results.append((chain, val, sc))
                if sc < 20:
                    nxt.append((chain, val.strip()))
        frontier = nxt
        if not frontier:
            break

    results.sort(key=lambda x: -x[2])
    return results

# ----------------------------------------------------------------------------
# 哈希
# ----------------------------------------------------------------------------
HASH_RULES = [
    (r"^[a-f0-9]{32}$", "MD5 / NTLM / MySQL5(32位hex)"),
    (r"^[a-f0-9]{16}$", "MySQL323 / 部分16位MD5"),
    (r"^[a-f0-9]{40}$", "SHA-1 / MySQL5(SHA1)"),
    (r"^[a-f0-9]{56}$", "SHA-224"),
    (r"^[a-f0-9]{64}$", "SHA-256"),
    (r"^[a-f0-9]{96}$", "SHA-384"),
    (r"^[a-f0-9]{128}$", "SHA-512"),
    (r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$", "bcrypt($2a$/$2b$/$2y$)"),
    (r"^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$", "MD5crypt($1$)"),
    (r"^\$5\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$", "SHA-256crypt($5$)"),
    (r"^\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$", "SHA-512crypt($6$)"),
    (r"^\$apr1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$", "Apache apr1"),
    (r"^\$P\$[./A-Za-z0-9]{31}$", "phpass/WordPress($P$)"),
    (r"^\$S\$[./A-Za-z0-9]{52}$", "Drupal $S$"),
    (r"^[a-f0-9]{8}$", "CRC32 / 短哈希"),
    (r"^[A-F0-9]{32}$", "MD5(大写)"),
    (r"^[A-F0-9]{40}$", "SHA-1(大写)"),
    (r"^[A-F0-9]{64}$", "SHA-256(大写)"),
    (r"^0x[a-f0-9]{8}$", "MySQL 旧密码hash"),
]

def identify_hash(h: str):
    h = h.strip()
    out = []
    for pat, name in HASH_RULES:
        if re.fullmatch(pat, h):
            out.append(name)
    return out or ["未识别的哈希格式"]

def _md4_pure(message: bytes) -> str:
    """纯 Python MD4（RFC 1320），OpenSSL 3 默认禁用 md4 时的兜底。"""
    import struct as _struct
    MASK = 0xffffffff

    def lrot(x, n):
        return ((x << n) | (x >> (32 - n))) & MASK

    def F(x, y, z):
        return (x & y) | ((~x) & z)

    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def H(x, y, z):
        return x ^ y ^ z

    bit_len = len(message) * 8
    message += b"\x80"
    message += b"\x00" * ((56 - len(message) % 64) % 64)
    message += _struct.pack("<Q", bit_len)
    h0, h1, h2, h3 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    for off in range(0, len(message), 64):
        X = list(_struct.unpack("<16I", message[off:off + 64]))
        A, B, C, D = h0, h1, h2, h3
        # Round 1
        for i in (0, 4, 8, 12):
            A = lrot((A + F(B, C, D) + X[i]) & MASK, 3)
            D = lrot((D + F(A, B, C) + X[i + 1]) & MASK, 7)
            C = lrot((C + F(D, A, B) + X[i + 2]) & MASK, 11)
            B = lrot((B + F(C, D, A) + X[i + 3]) & MASK, 19)
        # Round 2
        for i in (0, 1, 2, 3):
            A = lrot((A + G(B, C, D) + X[i] + 0x5A827999) & MASK, 3)
            D = lrot((D + G(A, B, C) + X[i + 4] + 0x5A827999) & MASK, 5)
            C = lrot((C + G(D, A, B) + X[i + 8] + 0x5A827999) & MASK, 9)
            B = lrot((B + G(C, D, A) + X[i + 12] + 0x5A827999) & MASK, 13)
        # Round 3
        for i, j in ((0, 8), (2, 10), (1, 9), (3, 11)):
            A = lrot((A + H(B, C, D) + X[i] + 0x6ED9EBA1) & MASK, 3)
            D = lrot((D + H(A, B, C) + X[j] + 0x6ED9EBA1) & MASK, 9)
            C = lrot((C + H(D, A, B) + X[i + 4] + 0x6ED9EBA1) & MASK, 11)
            B = lrot((B + H(C, D, A) + X[j + 4] + 0x6ED9EBA1) & MASK, 15)
        h0 = (h0 + A) & MASK
        h1 = (h1 + B) & MASK
        h2 = (h2 + C) & MASK
        h3 = (h3 + D) & MASK
    return _struct.pack("<4I", h0, h1, h2, h3).hex()


def md4_hex(data: bytes) -> str:
    """计算 MD4 摘要；OpenSSL 3 不可用时走纯 Python 实现。"""
    try:
        return hashlib.new("md4", data, usedforsecurity=False).hexdigest()
    except (ValueError, TypeError):
        return _md4_pure(data)

def hash_text(s: str, encodings=("utf-8", "gbk")):
    out = {}
    for enc in encodings:
        b = s.encode(enc, errors="replace")
        for algo in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512"):
            out[f"{algo}({enc})"] = hashlib.new(algo, b).hexdigest()
    out["NTLM(MD4)"] = md4_hex(s.encode("utf-16-le"))
    return out

# 内置弱口令（精简高频表，用户可在工具中心挂载大字典）
WEAK_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
    "111111", "1234567", "dragon", "123123", "baseball", "iloveyou", "trustno1",
    "sunshine", "princess", "admin", "welcome", "shadow", "superman", "michael",
    "ninja", "abc123", "passw0rd", "1234567890", "000000", "123321", "654321",
    "qwer1234", "1q2w3e4r", "123qwe", "qazwsx", "password1", "root", "toor",
    "test", "guest", "ctf", "flag", "hack", "hacker", "p@ssw0rd", "P@ssw0rd",
    "admin123", "root123", "pass123", "123abc", "letmein", "master", "hello",
    "love", "killer", "zaq12wsx", "!@#$%^&*", "changeme", "secret",
]

def crack_hash(h: str, wordlist=None):
    """对常见快速哈希做字典爆破。返回 (明文, 算法) 或 None。"""
    h = h.strip().lower()
    words = list(WEAK_PASSWORDS)
    if wordlist:
        try:
            with open(wordlist, "r", errors="ignore") as f:
                words += [w.strip() for w in f if w.strip()]
        except Exception:
            pass
    algos = ("md5", "sha1", "sha224", "sha256", "sha384", "sha512")
    for w in words:
        for alg in algos:
            if hashlib.new(alg, w.encode()).hexdigest() == h:
                return w, alg
        if md4_hex(w.encode("utf-16-le")) == h:
            return w, "NTLM"
    return None

# ----------------------------------------------------------------------------
# 国内 CTF 特色编码：社会主义核心价值观 / 与佛论禅(TudouCode)
# ----------------------------------------------------------------------------
CV_WORDS = ["富强", "民主", "文明", "和谐", "自由", "平等",
            "公正", "法治", "爱国", "敬业", "诚信", "友善"]
CV_MAP = {w: i for i, w in enumerate(CV_WORDS)}

def core_values_decode(s: str) -> str:
    """社会主义核心价值观解码：12 词对应 0-11，10/11 为 a-f 的前缀。"""
    toks = re.findall("|".join(CV_WORDS), s)
    if len(toks) < 2:
        raise ValueError("非核心价值观编码")
    vals = [CV_MAP[t] for t in toks]
    hexs, i = [], 0
    while i < len(vals):
        v = vals[i]
        if v in (10, 11):
            if i + 1 >= len(vals):
                raise ValueError("核心价值观序列不完整")
            hexs.append(v + vals[i + 1] if v == 10 else 6 + vals[i + 1])
            i += 2
        else:
            hexs.append(v)
            i += 1
    hexstr = "".join(format(h, "x") for h in hexs)
    if len(hexstr) % 2:
        hexstr = "0" + hexstr
    return bytes.fromhex(hexstr).decode("utf-8", errors="replace")

def core_values_encode(s: str) -> str:
    import random
    out = []
    for ch in s.encode("utf-8").hex():
        v = int(ch, 16)
        if v < 10:
            out.append(CV_WORDS[v])
        elif random.random() < 0.5:
            out += [CV_WORDS[10], CV_WORDS[v - 10]]
        else:
            out += [CV_WORDS[11], CV_WORDS[v - 6]]
    return "".join(out)

# TudouCode（与佛论禅）固定参数，来源：官方 KeyFansClub TudouCode 的公开 Python3 移植
_TUDOU_KEY = b"XDXDtudou@KeyFansClub^_^Encode!!"
_TUDOU_IV = b"Potato@Key@_@=_="
_TUDOU_CHARS = [
    '滅','苦','婆','娑','耶','陀','跋','多','漫','都','殿','悉','夜','爍','帝','吉',
    '利','阿','無','南','那','怛','喝','羯','勝','摩','伽','謹','波','者','穆','僧',
    '室','藝','尼','瑟','地','彌','菩','提','蘇','醯','盧','呼','舍','佛','參','沙',
    '伊','隸','麼','遮','闍','度','蒙','孕','薩','夷','迦','他','姪','豆','特','逝',
    '朋','輸','楞','栗','寫','數','曳','諦','羅','曰','咒','即','密','若','般','故',
    '不','實','真','訶','切','一','除','能','等','是','上','明','大','神','知','三',
    '藐','耨','得','依','諸','世','槃','涅','竟','究','想','夢','倒','顛','離','遠',
    '怖','恐','有','礙','心','所','以','亦','智','道','。','集','盡','死','老','至']
_TUDOU_MARK = ['冥','奢','梵','呐','俱','哆','怯','諳','罰','侄','缽','皤']
_TUDOU_INDEX = {c: i for i, c in enumerate(_TUDOU_CHARS)}
_TUDOU_MARKSET = set(_TUDOU_MARK)

def tudou_decode(s: str) -> str:
    """与佛论禅解码，兼容旧版(佛曰)与新版(如是我闻，含 deflate 压缩)。"""
    body = s
    # 密文可能嵌在正常文字中，定位前缀（注意正文里的汉字可能与佛文字母表重合，必须先截取）
    idxs = [(s.find(h), len(h)) for h in ("如是我闻：", "如是我闻:", "佛曰：", "佛曰:")]
    idxs = [x for x in idxs if x[0] >= 0]
    if idxs:
        pos, ln = min(idxs)
        body = s[pos + ln:]
    else:
        # 无前缀时仅保留字母表内字符，剔除一切正文
        body = "".join(c for c in s if c in _TUDOU_INDEX or c in _TUDOU_MARKSET)
    data = bytearray()
    i = 0
    while i < len(body):
        c = body[i]
        if c in _TUDOU_MARKSET and i + 1 < len(body):
            i += 1
            data.append(_TUDOU_INDEX[body[i]] + 128)
        elif c in _TUDOU_INDEX:
            data.append(_TUDOU_INDEX[c])
        i += 1
    if not data or len(data) % 16:
        raise ValueError("非与佛论禅密文或数据损坏")
    from Crypto.Cipher import AES
    dec = AES.new(_TUDOU_KEY, AES.MODE_CBC, _TUDOU_IV).decrypt(bytes(data))
    pad = dec[-1]
    if 0 < pad <= 16 and dec[-pad] == pad:
        dec = dec[:-pad]
    import zlib

    def try_utf16(b):
        try:
            t = b.decode("utf-16-le")
            if t and sum(1 for ch in t if ch.isprintable() or ch in "\r\n\t") / len(t) > 0.9:
                return t
        except Exception:
            return None

    cands = [dec]
    for wbits in (-15, 15, 31):
        try:
            cands.append(zlib.decompress(dec, wbits))
        except Exception:
            pass
        try:
            cands.append(zlib.decompress(dec[1:], wbits))   # 新版首字节压缩标志
        except Exception:
            pass
    for c in cands:
        t = try_utf16(c)
        if t:
            return t
    raise ValueError("与佛论禅解密失败")

def tudou_encode(s: str) -> str:
    """旧版(佛曰)加密，用于自测/工具页。"""
    import random
    from Crypto.Cipher import AES
    data = s.encode("utf-16-le")
    pads = (-len(data)) % 16
    data = data + bytes([pads]) * pads
    enc = AES.new(_TUDOU_KEY, AES.MODE_CBC, _TUDOU_IV).encrypt(data)
    out = []
    for b in enc:
        if b < 128:
            out.append(_TUDOU_CHARS[b])
        else:
            out.append(random.choice(_TUDOU_MARK) + _TUDOU_CHARS[b - 128])
    return "佛曰：" + "".join(out)
