# -*- coding: utf-8 -*-
# 脚本名称: 通用 XOR 混淆还原（单字节/多字节/滚动密钥/已知明文）
# 方向: Reverse（去混淆）
# 简介: Reverse 题大量使用异或隐藏 flag/字符串。脚本支持：
#       1) 已知单字节/多字节密钥直接解；2) 已知明文头（如 flag{）反推密钥；
#       3) 单字节 0~255 爆破按可打印率筛选；4) 滚动/自增密钥（key+i、key^i）；
#       5) 输出全部候选并高亮 flag 形态。
# 用法:
#   python xor_obfuscation_decrypt.py data.bin --key 0x66
#   python xor_obfuscation_decrypt.py data.bin -x 1a2b3c --multikey 9f
#   python xor_obfuscation_decrypt.py data.bin --known flag{
#   python xor_obfuscation_decrypt.py data.bin --brute
#   python xor_obfuscation_decrypt.py --selftest
# 依赖: 仅标准库
import argparse
import re
import string

FLAG_RE = re.compile(rb"flag\{[ -~]{1,100}\}|[A-Za-z0-9_]{2,12}\{[ -~]{1,100}\}")
PRINTABLE = set(bytes(string.printable, "ascii"))


def xor_fixed(data, key):
    if isinstance(key, int):
        return bytes(b ^ key for b in data)
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def known_plaintext_key(data, known):
    """已知明文头反推循环密钥（取前 len(known) 字节）。"""
    return bytes(c ^ p for c, p in zip(data[:len(known)], known))


def rolling_xor(data, key0, step=1):
    out = bytearray()
    k = key0
    for b in data:
        out.append(b ^ (k & 0xff))
        k = (k + step) & 0xffffffff
    return bytes(out)


def rolling_xor_rev(data, key0, step=1):
    return rolling_xor(data, key0, step)  # 异或对称，同一函数


def brute_single(data):
    res = []
    for k in range(256):
        out = xor_fixed(data, k)
        ratio = sum(c in PRINTABLE for c in out) / max(1, len(out))
        # 常见英文字符/flag 形态加权，避免多个全可打印候选并列
        common = sum(chr(c).lower() in "etaoinshrdlu {}_-" for c in out) / max(1, len(out))
        bonus = 2 if FLAG_RE.search(out) else 0
        res.append((ratio + common + bonus, k, out))
    res.sort(reverse=True)
    return res


def show(name, out):
    head = out[:120].decode("utf-8", "replace")
    m = FLAG_RE.search(out)
    print(f"[{name}] {head}")
    if m:
        print("    [!!!] flag:", m.group().decode("utf-8", "replace"))


def selftest():
    raw = b"flag{xor_obfuscation_ok_12345}"
    enc = xor_fixed(raw, 0x66)
    assert xor_fixed(enc, 0x66) == raw
    # 已知明文反推
    k = known_plaintext_key(enc, b"flag{")
    assert xor_fixed(enc, k).startswith(b"flag{"), k
    # 多字节
    mk = b"\x9f\x3a"
    enc2 = xor_fixed(raw, mk)
    assert xor_fixed(enc2, mk) == raw
    # 滚动
    enc3 = rolling_xor(raw, 0x10, 7)
    assert rolling_xor_rev(enc3, 0x10, 7) == raw
    # 爆破：在全部 256 个候选中找到还原出 flag 的密钥
    hits = [k for _, k, out in brute_single(enc) if b"flag{xor_obfuscation_ok" in out]
    assert 0x66 in hits, hits
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="XOR 混淆还原")
    ap.add_argument("file", nargs="?")
    ap.add_argument("-x", "--hex", help="直接给十六进制密文")
    ap.add_argument("--key", type=lambda x: int(x, 16), help="单字节密钥")
    ap.add_argument("--multikey", type=lambda x: bytes.fromhex(x), help="多字节密钥 hex")
    ap.add_argument("--known", help="已知明文头，如 flag{")
    ap.add_argument("--brute", action="store_true", help="单字节全爆破")
    ap.add_argument("--roll", type=lambda x: int(x, 16), help="滚动密钥初值")
    ap.add_argument("--step", type=int, default=1)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if a.file:
        data = open(a.file, "rb").read()
    elif a.hex:
        data = bytes.fromhex(a.hex.replace(" ", ""))
    else:
        print("[!] 用法见脚本头部注释"); return
    if a.key is not None:
        show(f"key=0x{a.key:02x}", xor_fixed(data, a.key))
    if a.multikey:
        show("multikey", xor_fixed(data, a.multikey))
    if a.known:
        k = known_plaintext_key(data, a.known.encode())
        show("known->key=" + k.hex(), xor_fixed(data, k))
    if a.roll is not None:
        show(f"roll 0x{a.roll:x}", rolling_xor(data, a.roll, a.step))
    if a.brute or not any([a.key is not None, a.multikey, a.known, a.roll is not None]):
        for ratio, k, out in brute_single(data)[:8]:
            show(f"brute 0x{k:02x} ratio={ratio:.2f}", out)


if __name__ == "__main__":
    main()
