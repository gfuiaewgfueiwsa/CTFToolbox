# -*- coding: utf-8 -*-
# 脚本名称: RSA 一键综合利用脚本（自动尝试常见攻击）
# 方向: Crypto（密码学 / RSA）
# 简介: 把单文件里能拿到的 n/e/c/p/q/d/dp/dq 等参数填好后，脚本按顺序自动尝试：
#       直接解密 → 低指数开方 → Fermat 分解 → Wiener 小 d → dp/dq 泄露 →
#       Pollard rho 分解；任何一步成功即输出 flag。适合签到/套路题快速收尾。
# 用法:
#   方式 A：修改下方 PARAMS 字典后直接 python rsa_all_in_one.py
#   方式 B：python rsa_all_in_one.py --params params.txt
#           params.txt 每行形如  n = 0x.....  /  e = 65537 / c = 123456
#   方式 C：python rsa_all_in_one.py --selftest
# 依赖: pip install pycryptodome gmpy2
# 参考: https://ctf-wiki.org/crypto/asymmetric/rsa/
import argparse

# ============== 方式 A：把题目参数粘贴到这里（整数，支持 0x 十六进制）==============
PARAMS = {
    "n":  None,
    "e":  65537,
    "c":  None,
    "p":  None,
    "q":  None,
    "d":  None,
    "dp": None,
    "dq": None,
}
# ==============================================================================


def iroot(x, k):
    try:
        from gmpy2 import iroot as ir
        r, ok = ir(int(x), k)
        return int(r), bool(ok)
    except Exception:
        r = int(int(x) ** (1.0 / k))
        for cand in range(max(0, r - 2), r + 3):
            if cand ** k == x:
                return cand, True
        return r, False


def m_to_flag(m):
    return m.to_bytes((m.bit_length() + 7) // 8, "big").decode("utf-8", "replace")


def try_solve(P):
    n, e, c = P.get("n"), P.get("e"), P.get("c")
    log = []
    if not n or c is None:
        return None, ["缺少 n 或 c"]
    e = e or 65537

    # 0) 已知 d
    if P.get("d"):
        m = pow(c, P["d"], n)
        return m, log + ["[+] 使用已知 d 直接解密"]

    # 1) 已知 p、q
    if P.get("p") and P.get("q") and P["p"] * P["q"] == n:
        d = pow(e, -1, (P["p"] - 1) * (P["q"] - 1))
        return pow(c, d, n), log + [f"[+] 已知 p/q，d={d}"]

    # 2) 低加密指数
    if e <= 65537 and e in (2, 3, 5, 7, 11, 17, 257, 65537):
        for k in range(0, 100000):
            r, ok = iroot(c + k * n, e)
            if ok:
                return r, log + [f"[+] 低指数开方命中 k={k}"]

    # 3) dp / dq 泄露
    for key, name in (("dp", "p"), ("dq", "q")):
        v = P.get(key)
        if v:
            for kp in range(1, e):
                num = e * v - 1
                if num % kp == 0:
                    f = num // kp + 1
                    if f > 1 and n % f == 0:
                        p, q = (f, n // f) if name == "p" else (n // f, f)
                        d = pow(e, -1, (p - 1) * (q - 1))
                        return pow(c, d, n), log + [f"[+] {key} 泄露恢复因子"]
    # 4) Fermat（p、q 接近）
    a, _ = iroot(n, 2)
    a = max(a, 1)
    if a * a < n:
        a += 1
    for _ in range(200000):
        b, ok = iroot(a * a - n, 2)
        if ok and (a - b) * (a + b) == n and a - b > 1:
            p, q = a - b, a + b
            d = pow(e, -1, (p - 1) * (q - 1))
            return pow(c, d, n), log + ["[+] Fermat 分解成功"]
        a += 1
    log.append("[-] Fermat 未成功")

    # 5) Wiener（小 d）
    cf = []
    x, y = e, n
    while y:
        cf.append(x // y)
        x, y = y, x % y
    h0, h1, k0, k1 = 0, 1, 1, 0
    for qv in cf:
        h0, h1 = h1, qv * h1 + h0
        k0, k1 = k1, qv * k1 + k0
        if h0 and (e * h1 - 1) % h0 == 0:
            phi = (e * h1 - 1) // h0
            s = n - phi + 1
            disc = s * s - 4 * n
            if disc >= 0:
                t, ok = iroot(disc, 2)
                if ok and (s + t) % 2 == 0:
                    p, q = (s + t) // 2, (s - t) // 2
                    if p * q == n:
                        return pow(c, h1, n), log + ["[+] Wiener 小 d 成功"]
    log.append("[-] Wiener 未成功")

    # 6) Pollard rho 兜底（适合较小因子）
    import random
    from math import gcd

    def brent(nn):
        if nn % 2 == 0:
            return 2
        while True:
            y = random.randrange(1, nn - 1)
            c = random.randrange(1, nn - 1)
            m = 128
            g, r, qq = 1, 1, 1
            xx = ys = 0
            while g == 1:
                xx = y
                for _ in range(r):
                    y = (y * y + c) % nn
                k = 0
                while k < r and g == 1:
                    ys = y
                    for _ in range(min(m, r - k)):
                        y = (y * y + c) % nn
                        qq = qq * abs(xx - y) % nn
                    g = gcd(qq, nn)
                    k += m
                r *= 2
            if g == nn:
                while True:
                    ys = (ys * ys + c) % nn
                    g = gcd(abs(xx - ys), nn)
                    if g > 1:
                        break
            if g != nn:
                return g
    try:
        p = brent(n)
        q = n // p
        d = pow(e, -1, (p - 1) * (q - 1))
        return pow(c, d, n), log + [f"[+] Pollard rho 分解: {p}"]
    except Exception as ex:
        log.append(f"[-] Pollard rho 失败: {ex}")
    return None, log


def load_params_file(path):
    P = dict(PARAMS)
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.split("#", 1)[0].strip()
        if "=" in line:
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip()
            if v and v.lower() != "none":
                P[k] = int(v, 0)
    return P


def selftest():
    from Crypto.Util.number import getPrime, isPrime
    p, q = getPrime(200), getPrime(200)
    # 让 p、q 接近以走 Fermat 分支
    q = p + 2
    while not isPrime(q):
        q += 2
    n = p * q
    m = int.from_bytes(b"flag{aio_fermat}", "big")
    c = pow(m, 65537, n)
    mm, log = try_solve({"n": n, "e": 65537, "c": c})
    print("\n".join(log))
    assert mm == m
    print("[+] selftest OK:", m_to_flag(mm))


def main():
    ap = argparse.ArgumentParser(description="RSA 一键综合利用")
    ap.add_argument("--params")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest()
        return
    P = load_params_file(a.params) if a.params else dict(PARAMS)
    if not P.get("n"):
        print("[!] 请先在脚本顶部 PARAMS 填入参数，或用 --params 文件")
        return
    m, log = try_solve(P)
    print("\n".join(log))
    if m is None:
        print("[-] 常规攻击均失败，请上 yafu/MSIEVE/在线分解库 factordb.com")
    else:
        print("[+] flag =", m_to_flag(m))


if __name__ == "__main__":
    main()
