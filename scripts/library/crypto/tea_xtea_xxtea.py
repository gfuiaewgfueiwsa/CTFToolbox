# -*- coding: utf-8 -*-
# 脚本名称: TEA / XTEA / XXTEA 加解密（逆向题高频分组算法）
# 方向: Crypto / Reverse（轻量分组密码）
# 简介: TEA、XTEA、XXTEA 是国产题/固件/恶意样本里极常见的轻量加密，
#       本脚本提供三种算法的标准加解密，数据按 32 位小端处理，
#       逆向时把 IDA 里的常量/轮数对号入座即可解出 flag。
# 用法:
#   python tea_xtea_xxtea.py tea   --key 0102030405060708090a0b0c0d0e0f10 -x <密文hex>
#   python tea_xtea_xxtea.py xtea  --key <16字节hex> -x <hex>
#   python tea_xtea_xxtea.py xxtea --key <16字节hex> -x <hex>
#   python tea_xtea_xxtea.py --selftest
# 依赖: 仅标准库
import argparse
import struct

DELTA = 0x9E3779B9
MASK = 0xFFFFFFFF


def u32(x):
    return x & MASK


# ---------------- TEA（8 字节块，64bit Feistel） ----------------
def tea_encrypt_block(v, k):
    v0, v1 = v[0], v[1]
    s = 0
    for _ in range(32):
        s = u32(s + DELTA)
        v0 = u32(v0 + (u32(u32(v1 << 4) + k[0]) ^ u32(v1 + s) ^ u32((v1 >> 5) + k[1])))
        v1 = u32(v1 + (u32(u32(v0 << 4) + k[2]) ^ u32(v0 + s) ^ u32((v0 >> 5) + k[3])))
    return [v0, v1]


def tea_decrypt_block(v, k):
    v0, v1 = v[0], v[1]
    s = u32(DELTA * 32)
    for _ in range(32):
        v1 = u32(v1 - (u32(u32(v0 << 4) + k[2]) ^ u32(v0 + s) ^ u32((v0 >> 5) + k[3])))
        v0 = u32(v0 - (u32(u32(v1 << 4) + k[0]) ^ u32(v1 + s) ^ u32((v1 >> 5) + k[1])))
        s = u32(s - DELTA)
    return [v0, v1]


# ---------------- XTEA（8 字节块） ----------------
def xtea_encrypt_block(v, k, rounds=32):
    v0, v1 = v
    s = 0
    for _ in range(rounds):
        v0 = u32(v0 + u32(u32(u32(v1 << 4 ^ v1 >> 5) + v1) ^ u32(s + k[s & 3])))
        s = u32(s + DELTA)
        v1 = u32(v1 + u32(u32(u32(v0 << 4 ^ v0 >> 5) + v0) ^ u32(s + k[u32(s >> 11) & 3])))
    return [v0, v1]


def xtea_decrypt_block(v, k, rounds=32):
    v0, v1 = v
    s = u32(DELTA * rounds)
    for _ in range(rounds):
        v1 = u32(v1 - u32(u32(u32(v0 << 4 ^ v0 >> 5) + v0) ^ u32(s + k[u32(s >> 11) & 3])))
        s = u32(s - DELTA)
        v0 = u32(v0 - u32(u32(u32(v1 << 4 ^ v1 >> 5) + v1) ^ u32(s + k[s & 3])))
    return [v0, v1]


# ---------------- XXTEA（变长 32 位字数组） ----------------
def xxtea_encrypt_words(v, k):
    n = len(v)
    q = 6 + 52 // n
    s = 0
    z = v[n - 1]
    for _ in range(q):
        s = u32(s + DELTA)
        e = u32(s >> 2) & 3
        for i in range(n):
            y = v[(i + 1) % n]
            mx = u32(((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((s ^ y) + (k[(i & 3) ^ e] ^ z)))
            v[i] = u32(v[i] + mx)
            z = v[i]
    return v


def xxtea_decrypt_words(v, k):
    n = len(v)
    q = 6 + 52 // n
    s = u32(q * DELTA)
    y = v[0]
    while s:
        e = u32(s >> 2) & 3
        for i in range(n - 1, 0, -1):
            z = v[i - 1]
            mx = u32(((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((s ^ y) + (k[(i & 3) ^ e] ^ z)))
            v[i] = u32(v[i] - mx)
            y = v[i]
        z = v[n - 1]
        mx = u32(((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((s ^ y) + (k[e] ^ z)))
        v[0] = u32(v[0] - mx)
        y = v[0]
        s = u32(s - DELTA)
    return v


def key_to_u32s(h):
    kb = bytes.fromhex(h)
    kb = (kb + b"\x00" * 16)[:16]
    return list(struct.unpack("<4I", kb))


def blocks(data, size=8):
    out = []
    for i in range(0, len(data), size):
        out.append(data[i:i + size])
    return out


def run(algo, key_hex, data_hex, decrypt=True):
    k = key_to_u32s(key_hex)
    data = bytes.fromhex(data_hex)
    if algo == "xxtea":
        assert len(data) % 4 == 0, "XXTEA 数据长度须为 4 的倍数"
        words = list(struct.unpack("<%dI" % (len(data) // 4), data))
        words = xxtea_decrypt_words(words, k) if decrypt else xxtea_encrypt_words(words, k)
        return struct.pack("<%dI" % len(words), *words)
    fn_d, fn_e = (tea_decrypt_block, tea_encrypt_block) if algo == "tea" else (xtea_decrypt_block, xtea_encrypt_block)
    out = b""
    for blk in blocks(data):
        blk = blk + b"\x00" * (8 - len(blk))
        words = list(struct.unpack("<2I", blk))
        words = fn_d(words, k) if decrypt else fn_e(words, k)
        out += struct.pack("<2I", *words)
    return out


def selftest():
    key = "0102030405060708090a0b0c0d0e0f10"
    pt = b"flag{tea_xtea_xx"   # 16 字节
    for algo in ("tea", "xtea", "xxtea"):
        ct = run(algo, key, pt.hex(), decrypt=False)
        back = run(algo, key, ct.hex(), decrypt=True)
        assert back.startswith(pt), (algo, back)
        print(f"[+] {algo} 往返 OK: {back!r}")
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="TEA/XTEA/XXTEA 加解密")
    ap.add_argument("algo", choices=["tea", "xtea", "xxtea"], nargs="?")
    ap.add_argument("--key", help="16 字节密钥 hex")
    ap.add_argument("-x", "--hex", help="数据 hex")
    ap.add_argument("--enc", action="store_true", help="加密（默认解密）")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest or not a.algo:
        selftest(); return
    r = run(a.algo, a.key, a.hex, decrypt=not a.enc)
    print("[+] HEX :", r.hex())
    print("[+] 文本:", r.decode("utf-8", "replace"))


if __name__ == "__main__":
    main()
