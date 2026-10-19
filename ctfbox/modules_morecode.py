# -*- coding: utf-8 -*-
"""补充编码/密码（收藏夹在线工具离线化）：
UUencode、XXencode、Jother、Rabbit 流密码、文本/十六进制倒序、猪圈密码(尽力)、子网计算。

只依赖标准库；Jother 复用系统/便携 Node 求值。
"""
import os
import re
import struct
import binascii
import shutil
import subprocess
import ipaddress


# ============================================================================
# UUencode
# ============================================================================
def uu_encode(data: bytes, name: str = "file") -> str:
    """编码为标准 uuencode 文本（begin 644 ... end）。"""
    lines = [f"begin 644 {name}"]
    for i in range(0, len(data), 45):
        chunk = data[i:i + 45]
        lines.append(binascii.b2a_uu(chunk).decode("ascii").rstrip("\n"))
    lines.append("`")
    lines.append("end")
    return "\n".join(lines)


def uu_decode(text: str) -> bytes:
    """解码 uuencode 文本（自动忽略 begin/end 头尾，也支持只有数据行）。"""
    out = bytearray()
    started = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.lower().startswith("begin"):
            started = True
            continue
        if started and line.lower() == "end":
            break
        if line == "`":
            break
        # 数据行首字符为长度字符；非法行直接跳过
        if not started and not (32 <= ord(line[0]) <= 96):
            continue
        try:
            # binascii.a2b_uu 需要恰好(含)正确长度，补齐到 4 字符倍数
            pad = (-len(line)) % 4
            out += binascii.a2b_uu(line + " " * pad)
        except Exception:
            continue
    return bytes(out)


# ============================================================================
# XXencode  字母表 +-0-9A-Za-z
# ============================================================================
XX_ALPHA = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_XX_MAP = {c: i for i, c in enumerate(XX_ALPHA)}


def _xx_sextets(chunk: bytes):
    b = chunk + b"\x00" * (3 - len(chunk))
    return [
        (b[0] >> 2) & 0x3F,
        ((b[0] << 4) | (b[1] >> 4)) & 0x3F,
        ((b[1] << 2) | (b[2] >> 6)) & 0x3F,
        b[2] & 0x3F,
    ]


def xx_encode(data: bytes, name: str = "file") -> str:
    lines = [f"begin 644 {name}"]
    for i in range(0, len(data), 45):
        chunk = data[i:i + 45]
        row = XX_ALPHA[len(chunk)]
        n = len(chunk)
        for j in range(0, n, 3):
            grp = chunk[j:j + 3]
            sx = _xx_sextets(grp)
            valid = len(grp) + 1   # 1字节->2字符, 2字节->3字符, 3字节->4字符
            for k in range(4):
                if k < valid:
                    row += XX_ALPHA[sx[k]]
                else:
                    row += "-"   # xxencode 用 '-' 填充
        lines.append(row)
    lines.append("+")
    lines.append("end")
    return "\n".join(lines)


def xx_decode(text: str) -> bytes:
    out = bytearray()
    started = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.lower().startswith("begin"):
            started = True
            continue
        if started and line.lower() == "end":
            break
        if not line or line[0] not in _XX_MAP:
            continue
        count = _XX_MAP[line[0]]
        if count == 0:
            break
        body = line[1:]
        got = 0
        for j in range(0, len(body) - 3, 4):
            grp = body[j:j + 4]
            if any(c not in _XX_MAP for c in grp):
                continue
            v = [_XX_MAP[c] for c in grp]
            b0 = (v[0] << 2 | v[1] >> 4) & 0xFF
            b1 = ((v[1] & 0x0F) << 4 | v[2] >> 2) & 0xFF
            b2 = ((v[2] & 0x03) << 6 | v[3]) & 0xFF
            for b in (b0, b1, b2):
                if got < count:
                    out.append(b)
                    got += 1
    return bytes(out)


# ============================================================================
# Jother（JS 符号编码，交给 Node 求值）
# ============================================================================
def _node_available():
    return shutil.which("node") is not None


def jother_decode(text: str) -> str:
    text = (text or "").strip()
    node = shutil.which("node")
    if not node:
        raise RuntimeError("需要 Node.js（工具中心可一键下载便携版到 tools/runtime）")
    js = (
        "const vm=require('vm');\n"
        "const src=process.argv[1];\n"
        "try{const r=vm.runInNewContext(src,{},{timeout:3000});"
        "process.stdout.write(r==null?'':String(r));}\n"
        "catch(e){process.stdout.write('');}\n"
    )
    r = subprocess.run([node, "-e", js, text], capture_output=True, timeout=20)
    out = r.stdout.decode("utf-8", "replace")
    if not out:
        raise ValueError("Jother 求值无结果（可能不是合法 Jother 表达式）")
    return out


def looks_like_jother(t: str) -> bool:
    if not t or len(t) < 6:
        return False
    if re.fullmatch(r"[\[\]\(\)!\+\{\}~\$_\s,.'\":\\#=]+", t) and re.search(r"[~$_]", t):
        return True
    return False


# ============================================================================
# 文本 / 十六进制倒序
# ============================================================================
def reverse_text(t: str) -> str:
    return t[::-1]


def reverse_hex(t: str) -> str:
    """把十六进制串按字节倒序（支持空格/0x/换行分隔）。"""
    hx = re.sub(r"0x|[^0-9a-fA-F]", "", t)
    if len(hx) % 2:
        hx = "0" + hx
    raw = bytes.fromhex(hx)
    return raw[::-1].hex()


# ============================================================================
# Rabbit 流密码（eSTREAM 标准实现；Key 128bit，可选 IV 64bit）
# ============================================================================
def _rotl32(x, v):
    x &= 0xFFFFFFFF
    return ((x << v) | (x >> (32 - v))) & 0xFFFFFFFF


_RABBIT_A = [
    0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D,
    0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3,
]


class _Rabbit:
    """Rabbit 流密码（按 RFC 4503 的大端字约定实现，128bit Key，可选 64bit IV）。"""
    _A = (0x4D34D34D, 0xD34D34D3, 0x34D34D34)

    def __init__(self, key: bytes, iv: bytes = None):
        if len(key) != 16:
            raise ValueError("Rabbit 密钥必须为 16 字节(128bit)")
        # RFC 4503 / CryptoJS(sojson) 为大端约定；内部小端核心以反转密钥进入
        k = list(struct.unpack("<IIII", bytes(key[::-1])))
        k0, k1, k2, k3 = k
        self.x = [0] * 8
        self.c = [0] * 8
        x, c = self.x, self.c
        x[0], x[2], x[4], x[6] = k0, k1, k2, k3
        x[1] = ((k3 << 16) | (k2 >> 16)) & 0xFFFFFFFF
        x[3] = ((k0 << 16) | (k3 >> 16)) & 0xFFFFFFFF
        x[5] = ((k1 << 16) | (k0 >> 16)) & 0xFFFFFFFF
        x[7] = ((k2 << 16) | (k1 >> 16)) & 0xFFFFFFFF
        c[0], c[2], c[4], c[6] = _rotl32(k2, 16), _rotl32(k3, 16), _rotl32(k0, 16), _rotl32(k1, 16)
        c[1] = (k0 & 0xFFFF0000) | (k1 & 0x0000FFFF)
        c[3] = (k1 & 0xFFFF0000) | (k2 & 0x0000FFFF)
        c[5] = (k2 & 0xFFFF0000) | (k3 & 0x0000FFFF)
        c[7] = (k3 & 0xFFFF0000) | (k0 & 0x0000FFFF)
        self.carry = 0
        for _ in range(4):
            self._next()
        for i in range(8):
            c[i] ^= x[(i + 4) & 7]
        if iv:
            self._set_iv(iv)

    @staticmethod
    def _g(v):
        v &= 0xFFFFFFFF
        sq = v * v
        return ((sq >> 32) ^ (sq & 0xFFFFFFFF)) & 0xFFFFFFFF

    def _next(self):
        x, c = self.x, self.c
        for i in range(8):
            tmp = c[i]
            c[i] = (c[i] + self._A[i % 3] + self.carry) & 0xFFFFFFFF
            self.carry = 1 if c[i] < tmp else 0
        g = [self._g(x[i] + c[i]) for i in range(8)]
        j = 7
        for i in range(0, 8, 2):
            x[i] = (g[i] + _rotl32(g[j], 16) + _rotl32(g[j - 1], 16)) & 0xFFFFFFFF
            j = (j + 1) & 7
            x[i + 1] = (g[i + 1] + _rotl32(g[j], 8) + g[j - 1]) & 0xFFFFFFFF
            j = (j + 1) & 7

    def _set_iv(self, iv: bytes):
        if len(iv) != 8:
            raise ValueError("Rabbit IV 必须为 8 字节(64bit)")
        v0, v2 = struct.unpack("<II", bytes(iv[::-1]))
        v = [0] * 4
        v[0], v[2] = v0, v2
        v[1] = ((v0 >> 16) | (v2 & 0xFFFF0000)) & 0xFFFFFFFF
        v[3] = ((v2 << 16) | (v0 & 0x0000FFFF)) & 0xFFFFFFFF
        for i in range(8):
            self.c[i] ^= v[i & 3]
        for _ in range(4):
            self._next()

    def block(self):
        self._next()
        x = self.x
        z = [
            x[0] ^ ((x[5] >> 16) | (x[3] << 16)),
            x[2] ^ ((x[7] >> 16) | (x[5] << 16)),
            x[4] ^ ((x[1] >> 16) | (x[7] << 16)),
            x[6] ^ ((x[3] >> 16) | (x[1] << 16)),
        ]
        # 小端核心输出按 16 字节反转 => RFC 4503 大端字节序
        return struct.pack("<IIII", *[int(w & 0xFFFFFFFF) for w in z])[::-1]

    def keystream(self, n):
        ks = b""
        while len(ks) < n:
            ks += self.block()
        return ks[:n]


def rabbit_crypt(data: bytes, key: bytes, iv: bytes = None) -> bytes:
    r = _Rabbit(key, iv)
    ks = r.keystream(len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


# ============================================================================
# 猪圈密码（Pigpen，常用 Unicode 字形；图像题请用媒体中心查看）
# 网格 A-I / 点网格 J-R / X 格 S-V / 点 X 格 W-Z
# ============================================================================
_PIGPEN = {
    # 无点九宫格 A-I
    "⌈": "A", "⊓": "B", "⌉": "C",
    "⊣": "D", "□": "E", "⊢": "F",
    "⌊": "G", "⊔": "H", "⌋": "I",
    # 带点九宫格 J-R（字形后加·）
    "⌈·": "J", "⊓·": "K", "⌉·": "L",
    "⊣·": "M", "□·": "N", "⊢·": "O",
    "⌊·": "P", "⊔·": "Q", "⌋·": "R",
    # X 形 S-V
    "ᐸ": "S", "ᐱ": "T", "ᐳ": "U", "ᐯ": "V",
    "ᐸ·": "W", "ᐱ·": "X", "ᐳ·": "Y", "ᐯ·": "Z",
}
_PIGPEN_REV = {v: k for k, v in _PIGPEN.items()}


def pigpen_decode(t: str) -> str:
    out = []
    i = 0
    chars = list(t)
    while i < len(chars):
        two = chars[i] + (chars[i + 1] if i + 1 < len(chars) else "")
        if two in _PIGPEN:
            out.append(_PIGPEN[two]); i += 2; continue
        one = chars[i]
        if one in _PIGPEN:
            out.append(_PIGPEN[one]); i += 1; continue
        i += 1
    return "".join(out)


def pigpen_encode(t: str) -> str:
    return "".join(_PIGPEN_REV.get(c.upper(), c) for c in t)


# ============================================================================
# 子网 / IP 计算
# ============================================================================
def subnet_calc(cidr: str) -> str:
    cidr = cidr.strip()
    if "/" not in cidr:
        cidr += "/24"
    net = ipaddress.ip_network(cidr, strict=False)
    is_v6 = net.version == 6
    lines = [
        f"CIDR      : {net.with_prefixlen}",
        f"网络地址  : {net.network_address}",
        f"广播地址  : {net.broadcast_address if not is_v6 else '(IPv6无广播)'}",
        f"子网掩码  : {net.netmask}",
        f"通配掩码  : {net.hostmask}",
        f"地址总数  : {net.num_addresses}",
    ]
    if not is_v6:
        hosts = list(net.hosts())
        if hosts:
            lines.append(f"可用主机数: {len(hosts)}")
            lines.append(f"可用范围  : {hosts[0]} ~ {hosts[-1]}")
        else:
            lines.append("可用主机数: 0（点对点/32 位掩码）")
    lines.append(f"IP 版本   : IPv{net.version}")
    return "\n".join(lines)
