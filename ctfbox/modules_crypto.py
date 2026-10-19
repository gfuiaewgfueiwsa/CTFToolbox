# -*- coding: utf-8 -*-
"""RSA/密钥分析：PEM/证书/SSH 公钥解析、小因子/Fermat 分解、私钥恢复与弱参数提示。"""
import re
import base64
import struct
from .common import Report

def _is_prime_simple(n, k=16):
    import random
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True

def factor_fermat(n, limit=200000):
    """p、q 相邻时 Fermat 分解，返回 (p, q) 或 None。"""
    import math
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(limit):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            if p > 1 and p * q == n:
                return p, q
        a += 1
    return None

def factor_trial(n):
    """小素数试除（覆盖弱随机/重复素数）。"""
    x = n
    for p in range(2, 200000):
        if p * p > x:
            break
        if x % p == 0:
            factors = []
            while x % p == 0:
                factors.append(p)
                x //= p
            if x > 1:
                factors.append(x)
            return factors
    return None

def factor_n(n):
    """返回因子列表（至少两个），无法分解返回 None。"""
    import math
    r = math.isqrt(n)
    if r * r == n and r > 1:
        return [r, r]
    f = factor_trial(n)
    if f and len(f) >= 2:
        return f
    fe = factor_fermat(n)
    if fe:
        return [fe[0], fe[1]]
    return None

def _parse_ssh_rsa(raw: bytes):
    m = re.search(rb"ssh-rsa\s+([A-Za-z0-9+/=]+)", raw)
    if not m:
        return None
    try:
        buf = base64.b64decode(m.group(1))
    except Exception:
        return None
    def rd(b, o):
        (ln,) = struct.unpack(">I", b[o:o + 4])
        return b[o + 4:o + 4 + ln], o + 4 + ln
    try:
        tag, o = rd(buf, 0)
        if tag != b"ssh-rsa":
            return None
        e_b, o = rd(buf, o)
        n_b, o = rd(buf, o)
        e = int.from_bytes(e_b, "big")
        n = int.from_bytes(n_b, "big")
        return n, e
    except Exception:
        return None

def analyze_rsa(raw: bytes, report: Report):
    """raw 为文件字节；自动识别 PEM 私钥/证书/公钥、ssh-rsa、裸 n/e。"""
    found = False
    n = e = d = p = q = None

    # PEM 私钥
    if b"PRIVATE KEY" in raw[:200] or b"PRIVATE KEY" in raw[:2000]:
        found = True
        try:
            from cryptography.hazmat.primitives import serialization
            for pwd in (None, b""):
                try:
                    k = serialization.load_pem_private_key(raw, password=pwd)
                    break
                except TypeError:
                    k = None
                    continue
            if k is not None:
                priv = getattr(k, "private_numbers", lambda: None)()
                pub = priv.public_numbers
                n, e, d = pub.n, pub.e, priv.d
                p, q = priv.p, priv.q
                def cut(x):
                    s = str(x)
                    return s if len(s) <= 120 else s[:120] + "…"
                report.add("ok", "RSA 私钥已解析",
                           f"n={cut(n)}\ne={e}\nd={cut(d)}\np={cut(p)}\nq={cut(q)}")
                report.add("info", "密钥长度", f"{n.bit_length()} bit")
        except Exception as ex:
            report.add("warn", "私钥可能有口令保护",
                       f"{str(ex)[:150]}\n提示: ssh2john/ssh2john.py + john 爆破口令")

    # PEM 证书 / 公钥
    if n is None and (b"CERTIFICATE" in raw[:500] or b"PUBLIC KEY" in raw[:500]):
        found = True
        try:
            from cryptography.hazmat.primitives import serialization
            if b"CERTIFICATE" in raw:
                from cryptography import x509
                cert = x509.load_pem_x509_certificate(raw)
                report.add("info", "证书信息",
                           f"主体: {cert.subject.rfc4514_string()}\n签发: {cert.issuer.rfc4514_string()}\n"
                           f"有效期: {cert.not_valid_before_utc} ~ {cert.not_valid_after_utc}")
                pn = cert.public_key().public_numbers()
            else:
                pk = serialization.load_pem_public_key(raw)
                pn = pk.public_numbers()
            n, e = pn.n, pn.e
            report.add("info", "RSA 公钥参数",
                       f"e={e}\nn={n}"[:1500] + f"\n密钥长度: {n.bit_length()} bit")
        except Exception as ex:
            report.add("warn", "证书/公钥解析失败", str(ex)[:150])

    # ssh-rsa
    if n is None:
        ssh = _parse_ssh_rsa(raw)
        if ssh:
            found = True
            n, e = ssh
            report.add("ok", "ssh-rsa 公钥已解析", f"e={e}\nn={n}"[:1500] + f"\n密钥长度: {n.bit_length()} bit")

    # 裸 n / e（题目常见 n = 0x... / n = 123...）
    if n is None:
        txt = raw.decode("latin-1", errors="replace")
        mn = re.search(r"n\s*=\s*(0x[0-9a-fA-F]+|\d+)", txt)
        me = re.search(r"e\s*=\s*(0x[0-9a-fA-F]+|\d+)", txt)
        if mn:
            found = True
            n = int(mn.group(1), 0)
            e = int(me.group(1), 0) if me else 65537
            report.add("ok", "从文本解析出 RSA 参数", f"n 长度 {n.bit_length()} bit, e={e}")

    if not found or not n:
        return

    # 弱参数与分解
    hints = []
    if e == 3:
        hints.append("e=3：小公钥指数，关注低加密指数攻击（相同消息多站发送用 Hastad/中国剩余定理）、明文很小时直接开三次方")
    elif e and e < 65537:
        hints.append(f"e={e} 较小，关注 Wiener/DMF 连分数攻击（d 较小时）")
    if n.bit_length() < 1024:
        hints.append(f"n 仅 {n.bit_length()} bit，可在线/本地直接分解（factordb、yafu、msieve）")
    if n % 2 == 0 or n % 3 == 0 or n % 5 == 0:
        hints.append("n 含极小因子")
    for h in hints:
        report.add("warn", "RSA 弱点提示", h)

    factors = factor_n(n)
    if factors and len(factors) >= 2:
        p, q = factors[0], factors[1] if len(factors) > 1 else n // factors[0]
        report.add("ok", "n 已成功分解", f"p={p}\nq={q}")
        phi = (p - 1) * (q - 1)
        if e:
            try:
                d = pow(e, -1, phi)
                report.add("ok", "私钥指数 d 已恢复", f"d={d}"[:1000])
                report.add("info", "解密方法", "m = pow(c, d, n)；或用 p/q 构造 PEM 私钥")
            except Exception:
                report.add("info", "提示", "e 与 phi 不互质，检查因子是否完整")
    else:
        report.add("info", "n 自动分解未成功",
                   "可尝试：factordb.com 查询、多公钥求 gcd（共享素数）、Fermat（已试20万轮）、"
                   "Wiener（d 小）、Coppersmith、RsaCtfTool")


# ============================================================================
# RSA 进阶攻击（纯 Python 实现，CTF 高频题型）
# ============================================================================
def _continued_fraction(n: int, d: int):
    """求 n/d 的连分数展开，返回渐近分数列表 [(p, q), ...]。"""
    cf = []
    while d:
        q, r = divmod(n, d)
        cf.append(q)
        n, d = d, r
    # 渐近分数
    convergents = []
    p0, p1 = 0, 1
    q0, q1 = 1, 0
    for a in cf:
        p2 = a * p1 + p0
        q2 = a * q1 + q0
        convergents.append((p2, q2))
        p0, p1 = p1, p2
        q0, q1 = q1, q2
    return convergents


def rsa_wiener_attack(e: int, n: int):
    """Wiener 攻击：当 d < n^(1/4)/3 时，用连分数求 d。
    返回 (d, p, q) 或 None。"""
    if e >= n:
        return None
    for k, d in _continued_fraction(e, n):
        if k == 0:
            continue
        # e*d ≡ 1 mod phi(n) => k*phi(n) = e*d - 1
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # p+q = n - phi + 1
        s = n - phi + 1
        # p, q 是 x^2 - s*x + n = 0 的根
        disc = s * s - 4 * n
        if disc < 0:
            continue
        sq = int(disc ** 0.5)
        if sq * sq == disc:
            p = (s + sq) // 2
            q = (s - sq) // 2
            if p * q == n:
                return d, p, q
    return None


def rsa_dp_leak_attack(dp: int, n: int, e: int):
    """dp 泄露攻击：已知 dp = d mod (p-1)，求 p。
    dp * e ≡ 1 mod (p-1) => e*dp - 1 = k*(p-1), 其中 1 <= k < e
    返回 (p, q, d) 或 None。"""
    for k in range(1, e):
        if (e * dp - 1) % k != 0:
            continue
        p = (e * dp - 1) // k + 1
        if p <= 0 or n % p != 0:
            continue
        q = n // p
        phi = (p - 1) * (q - 1)
        try:
            d = pow(e, -1, phi)
            return p, q, d
        except ValueError:
            continue
    return None


def rsa_common_modulus_attack(c1: int, c2: int, e1: int, e2: int, n: int):
    """共模攻击：同一明文 m 用不同 e1/e2 加密，且 gcd(e1,e2)=1。
    返回明文 m 或 None。"""
    from math import gcd
    if gcd(e1, e2) != 1:
        return None
    # 扩展欧几里得算法求 a, b 使 a*e1 + b*e2 = 1
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x, y = egcd(b % a, a)
        return g, y - (b // a) * x, x
    g, a, b = egcd(e1, e2)
    if g != 1:
        return None
    # m = c1^a * c2^b mod n
    if a < 0:
        c1 = pow(c1, -1, n)  # c1 模逆
        a = -a
    if b < 0:
        c2 = pow(c2, -1, n)
        b = -b
    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return m


def rsa_hastad_attack(ciphertexts: list, e: int, ns: list):
    """Hastad 广播攻击：e 个不同的 n，同一明文 m 用相同 e 加密。
    用中国剩余定理求 m^e，再开 e 次方根得 m。
    返回明文字节 或 None。"""
    if len(ciphertexts) < e:
        return None
    cs = ciphertexts[:e]
    moduli = ns[:e]
    # CRT
    N = 1
    for n in moduli:
        N *= n
    result = 0
    for c, n in zip(cs, moduli):
        Ni = N // n
        inv = pow(Ni, -1, n)
        result = (result + c * Ni * inv) % N
    # 开 e 次方根
    m = _iroot(result, e)
    if m is None:
        return None
    # 转为字节
    length = (m.bit_length() + 7) // 8 if m else 0
    return m.to_bytes(length, "big") if m else b""


def _iroot(n: int, k: int):
    """求 n 的 k 次方根（整数，精确）。不存在返回 None。"""
    if n < 0:
        return None
    if n == 0:
        return 0
    # 二分法
    lo, hi = 1, n
    while lo <= hi:
        mid = (lo + hi) // 2
        p = mid ** k
        if p == n:
            return mid
        elif p < n:
            lo = mid + 1
        else:
            hi = mid - 1
    return None
