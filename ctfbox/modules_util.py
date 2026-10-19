# -*- coding: utf-8 -*-
"""万能实用工具函数集：时间戳全家桶、进制/IEEE754/大小端、JSON、
密码字典生成、文本编码探测、正则批量提取等。全部为纯函数，供 UI 调用。"""
import os
import re
import json
import struct
import datetime
import itertools

from .common import save_text, WORKSPACE


# ============================================================================
# 时间戳
# ============================================================================
EPOCH_UNIX = datetime.datetime(1970, 1, 1)
EPOCH_OLE = datetime.datetime(1899, 12, 30)
EPOCH_FILETIME = datetime.datetime(1601, 1, 1)
EPOCH_COCOA = datetime.datetime(2001, 1, 1)
EPOCH_CHROME = datetime.datetime(1601, 1, 1)   # 微秒
EPOCH_WEBKIT = datetime.datetime(1601, 1, 1)   # 微秒
EPOCH_FAT = datetime.datetime(1980, 1, 1)


def _dt(t):
    if isinstance(t, (int, float)):
        return datetime.datetime.utcfromtimestamp(t)
    return t


def convert_timestamp(value: str):
    """自动识别时间戳格式并返回所有解释结果 [(名称, 时间字符串)]。"""
    value = value.strip().strip('"').strip("'")
    # 日期字符串 -> 各种时间戳
    out = []
    num = None
    try:
        num = float(value)
    except ValueError:
        m = re.fullmatch(r"0x[0-9a-fA-F]+", value)
        if m:
            num = float(int(value, 16))
    if num is not None:
        n = num
        # Unix 秒（10 位）/毫秒（13）/微秒（16）/纳秒（19）
        if 1_000_000_000 <= abs(n) < 10_000_000_000:
            out.append(("Unix 秒(UTC)", _dt(n).strftime("%Y-%m-%d %H:%M:%S")))
            out.append(("Unix 秒(北京)", (_dt(n) + datetime.timedelta(hours=8))
                        .strftime("%Y-%m-%d %H:%M:%S")))
        if 1_000_000_000_000 <= abs(n) < 10_000_000_000_000:
            out.append(("Unix 毫秒(UTC)", _dt(n / 1e3).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]))
        if 1_000_000_000_000_000 <= abs(n) < 10_000_000_000_000_000:
            out.append(("Unix 微秒 / Chrome / WebKit(UTC)",
                        (EPOCH_CHROME + datetime.timedelta(microseconds=n))
                        .strftime("%Y-%m-%d %H:%M:%S")))
        if 10_000_000_000_000_000 <= abs(n) < 300_000_000_000_000_000:
            out.append(("Windows FILETIME(100ns, UTC)",
                        (EPOCH_FILETIME + datetime.timedelta(microseconds=n / 10))
                        .strftime("%Y-%m-%d %H:%M:%S.%f")))
        # OLE 日期（浮点，4xxxx 区间）
        if 20000 < abs(n) < 80000:
            out.append(("OLE/Office 日期",
                        (EPOCH_OLE + datetime.timedelta(days=n))
                        .strftime("%Y-%m-%d %H:%M:%S")))
        # Cocoa（2001 起秒）
        if -600_000_000 < n < 600_000_000 and abs(n) < 5_000_000_000:
            out.append(("Apple Cocoa(2001起秒, UTC)",
                        (EPOCH_COCOA + datetime.timedelta(seconds=n))
                        .strftime("%Y-%m-%d %H:%M:%S")))
        if not out:
            out.append(("Unix 秒(UTC)", _dt(n).strftime("%Y-%m-%d %H:%M:%S")))
        return out

    # 日期字符串 -> 时间戳
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d",
                "%Y/%m/%d", "%Y年%m月%d日 %H:%M:%S", "%Y年%m月%d日"):
        try:
            dt = datetime.datetime.strptime(value, fmt)
            sec = (dt - EPOCH_UNIX).total_seconds()
            ft = (dt - EPOCH_FILETIME).total_seconds() * 1e7
            ole = (dt - EPOCH_OLE).total_seconds() / 86400
            cocoa = (dt - EPOCH_COCOA).total_seconds()
            out.append(("Unix 秒", str(int(sec))))
            out.append(("Unix 毫秒", str(int(sec * 1000))))
            out.append(("FILETIME", str(int(ft))))
            out.append(("OLE 日期", f"{ole:.6f}"))
            out.append(("Cocoa 秒", f"{cocoa:.0f}"))
            return out
        except ValueError:
            continue
    raise ValueError("无法识别的时间戳/日期格式")


# ============================================================================
# 进制 / IEEE754 / 大小端
# ============================================================================
def convert_number(text: str):
    """返回该数值的二/八/十/十六进制、ASCII、字节解释。"""
    t = text.strip().replace(",", "").replace(" ", "")
    val = None
    if re.fullmatch(r"0x[0-9a-fA-F]+", t):
        val = int(t, 16)
    elif re.fullmatch(r"0b[01]+", t):
        val = int(t, 2)
    elif re.fullmatch(r"0o[0-7]+", t):
        val = int(t, 8)
    elif re.fullmatch(r"\d+", t):
        val = int(t)
    elif re.fullmatch(r"[01]{4,}", t):
        val = int(t, 2)
    if val is None:
        raise ValueError("请输入十进制/0x十六进制/0b二进制/0o八进制整数")
    out = [
        ("十进制", str(val)),
        ("十六进制", hex(val)),
        ("二进制", bin(val)),
        ("八进制", oct(val)),
        ("ASCII(大端字节)", "".join(chr(b) if 32 <= b < 127 else f"\\x{b:02x}"
                                    for b in val.to_bytes(max(1, (val.bit_length() + 7) // 8), "big"))),
    ]
    return out


def float_to_hex(text: str, bits=64):
    v = float(text.strip())
    if bits == 32:
        b = struct.pack(">f", v)
        return {"大端": b.hex(), "小端": b[::-1].hex(), "十进制": v}
    b = struct.pack(">d", v)
    return {"大端": b.hex(), "小端": b[::-1].hex(), "十进制": v}


def hex_to_float(text: str, bits=64):
    h = text.strip().replace(" ", "").replace("0x", "")
    b = bytes.fromhex(h)
    out = {}
    for label, raw in (("大端", b), ("小端", b[::-1])):
        try:
            if bits == 32 and len(raw) >= 4:
                out[label] = struct.unpack(">f", raw[:4])[0]
            elif bits == 64 and len(raw) >= 8:
                out[label] = struct.unpack(">d", raw[:8])[0]
        except Exception:
            pass
    return out


def endian_swap(text: str):
    h = text.strip().replace(" ", "").replace("0x", "")
    if len(h) % 2:
        h = "0" + h
    b = bytes.fromhex(h)
    return {"交换后hex": b[::-1].hex(), "按字(16bit)交换": b"".join(
        b[i:i + 2][::-1] for i in range(0, len(b), 2)).hex()}


# ============================================================================
# JSON 美化 / 校验
# ============================================================================
def json_format(text: str, indent=2):
    obj = json.loads(text.strip())
    return json.dumps(obj, ensure_ascii=False, indent=indent)


# ============================================================================
# 正则批量提取
# ============================================================================
def regex_extract(pattern: str, text: str, flags=0, replace=None):
    if replace is not None:
        return re.sub(pattern, replace, text, flags=flags)
    m = re.findall(pattern, text, flags=flags)
    return m


# ============================================================================
# 密码字典生成（基于个人信息组合，CTF 弱口令/压缩包口令常用）
# ============================================================================
def generate_passwords(words, leet=True, years=True, suffixes=("!", "@123", "123", "123456",
                                                               "@", "#", "666", "888", "00")):
    """words: 关键词列表（姓名拼音、生日、手机号、域名、常用词）。"""
    base = set()
    for w in words:
        w = w.strip()
        if not w:
            continue
        base.add(w)
        base.add(w.lower())
        base.add(w.capitalize())
        base.add(w.upper())
        if len(w) >= 4:
            base.add(w[:1].upper() + w[1:])
    extra = set(base)
    common_years = [str(y) for y in range(1980, 2028)] if years else []
    tail = [""] + list(suffixes) + common_years
    out = set()
    for w in base:
        for t in tail:
            out.add(w + t)
            if t:
                out.add(t + w)
    # 两个关键词组合
    bl = list(base)
    for a in bl[:12]:
        for b in bl[:12]:
            if a != b and len(a) + len(b) <= 24:
                out.add(a + b)
    if leet:
        table = str.maketrans({"a": "@", "o": "0", "i": "1", "e": "3", "s": "$"})
        for w in list(out):
            if re.search(r"[aoies]", w):
                out.add(w.translate(table))
    # 内置高频弱口令
    out.update(["123456", "password", "admin", "admin123", "root", "toor",
                "12345678", "qwerty", "abc123", "111111", "000000", "123123",
                "666666", "888888", "iloveyou", "p@ssw0rd", "P@ssw0rd"])
    return sorted(out, key=lambda x: (len(x), x))


def save_wordlist(words, out_path: str = None):
    pws = generate_passwords(words)
    out_path = out_path or os.path.join(WORKSPACE, "custom_wordlist.txt")
    save_text(out_path, "\n".join(pws))
    return out_path, len(pws)


# ============================================================================
# 文本编码探测/转换
# ============================================================================
def detect_encoding(data: bytes):
    import codecs
    candidates = ["utf-8-sig", "utf-8", "gb18030", "big5", "shift_jis",
                  "euc-kr", "utf-16", "latin-1"]
    best = None
    for enc in candidates:
        try:
            txt = data.decode(enc)
            bad = txt.count("\ufffd") + txt.count("\x00") * 2
            score = 100 - bad
            if best is None or score > best[0]:
                best = (score, enc, txt)
        except Exception:
            continue
    return best[1], best[2]


# ============================================================================
# 文本统计（词频/字符频率）
# ============================================================================
def char_frequency(text: str, top=30):
    from collections import Counter
    c = Counter(text)
    return c.most_common(top)
