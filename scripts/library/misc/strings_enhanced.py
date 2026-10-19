# -*- coding: utf-8 -*-
# 脚本名称: strings 增强版（ASCII/UTF-16LE/中文GBK，最小长度可调，flag 高亮）
# 方向: Misc / 通用（静态分析）
# 简介: 比 Sysinternals strings 更适合 CTF：同时提取 ASCII、UTF-16LE、
#       GBK/UTF-8 中文串，按长度过滤，自动高亮 flag 形态与 URL/IP/邮箱，
#       可直接对内存镜像/固件/任意二进制使用。
# 用法:
#   python strings_enhanced.py suspect.bin
#   python strings_enhanced.py suspect.bin -n 6 --enc ascii,utf16,gbk -o out.txt
#   python strings_enhanced.py --selftest
# 依赖: 仅标准库
import argparse
import os
import re

FLAG_RE = re.compile(r"(?i)(?:flag|ctf|key|secret|password)\{[^}]{1,200}\}|[A-Za-z0-9_]{2,16}\{[ -~]{3,200}?\}")
URL_RE = re.compile(r"https?://[^\s'\"<>]+|[\w.]+@[\w.]+\.\w+|\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_ascii(raw, n):
    return [m.group().decode("ascii") for m in re.finditer(rb"[\x20-\x7e]{%d,}" % n, raw)]


def extract_utf16le(raw, n):
    out = []
    pat = (rb"(?:[\x20-\x7e]\x00){%d,}" % n)
    for m in re.finditer(pat, raw):
        out.append(m.group().decode("utf-16-le", "replace"))
    return out


def extract_gbk(raw, n):
    out = []
    # 连续的可打印 ASCII/GBK 双字节
    cur = bytearray()

    def flush():
        if len(cur) >= n:
            try:
                t = bytes(cur).decode("gbk", errors="strict")
                if any('\u4e00' <= c <= '\u9fff' for c in t) or sum(c.isalnum() for c in t) >= n:
                    out.append(t)
            except Exception:
                pass
        cur.clear()

    i = 0
    while i < len(raw) - 1:
        b1, b2 = raw[i], raw[i + 1]
        if 0x81 <= b1 <= 0xFE and 0x40 <= b2 <= 0xFE:
            cur += bytes([b1, b2]); i += 2
        elif 0x20 <= b1 < 0x7f:
            cur.append(b1); i += 1
        else:
            flush(); i += 1
    flush()
    return out


def run(path, n, encs, out=None):
    raw = open(path, "rb").read()
    res = []
    if "ascii" in encs:
        res += extract_ascii(raw, n)
    if "utf16" in encs:
        res += extract_utf16le(raw, n)
    if "gbk" in encs:
        res += extract_gbk(raw, n)
    text = "\n".join(res)
    print(f"[*] 共 {len(res)} 条字符串")
    for m in FLAG_RE.findall(text):
        print("[!!!]", m)
    for m in URL_RE.findall(text)[:50]:
        print("[net]", m)
    if out:
        open(out, "w", encoding="utf-8").write(text)
        print("[+] 全部字符串已写入", out)
    else:
        print("-" * 70)
        print("\n".join(res[:500]))
        if len(res) > 500:
            print(f"... 其余 {len(res)-500} 条用 -o 导出查看")


def selftest():
    d = os.path.join(os.environ.get("TEMP", "."), "str_self")
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "t.bin")
    payload = b"junk\x00\x00flag{strings_found_ok}\x00more"
    payload += "中文隐藏测试".encode("gbk")
    open(p, "wb").write(payload)
    run(p, 4, "ascii,gbk")
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="strings 增强版")
    ap.add_argument("file", nargs="?")
    ap.add_argument("-n", type=int, default=5, help="最小长度")
    ap.add_argument("--enc", default="ascii,utf16,gbk")
    ap.add_argument("-o", "--out")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.file:
        print("[!] 用法: python strings_enhanced.py suspect.bin"); return
    run(a.file, a.n, a.enc.split(","), a.out)


if __name__ == "__main__":
    main()
