# -*- coding: utf-8 -*-
# 脚本名称: 二进制/文本差异对比（按字节偏移定位，含滑动重同步）
# 方向: Util（差异分析）
# 简介: 对比两个文件的差异，输出首个差异偏移、差异块数量、十六进制上下文；
#       对“插入/删除少量字节导致整体错位”的情况用 LCS 滑动重同步，
#       适合对比补丁前后二进制、配置、流量、内存转储。
# 用法:
#   python binary_diff.py a.bin b.bin
#   python binary_diff.py a.bin b.bin --window 64 --max 20
#   python binary_diff.py a.txt b.txt --text
#   python binary_diff.py --selftest
# 依赖: 仅标准库（difflib）
import argparse
import difflib
import os


def diff_binary(a, b, window=32, maxshow=20):
    if a == b:
        print("[=] 两文件完全一致，大小", len(a))
        return 0
    print(f"[*] 大小 A={len(a)} B={len(b)}")
    first = next((i for i in range(min(len(a), len(b))) if a[i] != b[i]),
                 min(len(a), len(b)))
    print(f"[!] 首个差异偏移: 0x{first:x} ({first})")
    print("    A:", a[max(0, first - 16):first + window].hex(" "))
    print("    B:", b[max(0, first - 16):first + window].hex(" "))
    # 块级 LCS 差异（块大小 16，兼顾性能与定位）
    BS = 16
    blocks_a = [a[i:i + BS] for i in range(0, len(a), BS)]
    blocks_b = [b[i:i + BS] for i in range(0, len(b), BS)]
    sm = difflib.SequenceMatcher(None, blocks_a, blocks_b, autojunk=False)
    changes = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag != "equal":
            changes.append((tag, i1 * BS, i2 * BS, j1 * BS, j2 * BS))
    print(f"[*] 差异块（16 字节粒度）: {len(changes)} 处")
    for tag, a1, a2, b1, b2 in changes[:maxshow]:
        print(f"  {tag:7s} A[0x{a1:x}-0x{a2:x}] -> B[0x{b1:x}-0x{b2:x}]")
        if tag in ("replace", "delete"):
            print("    A:", a[a1:min(a2, a1 + 48)].hex(" "))
        if tag in ("replace", "insert"):
            print("    B:", b[b1:min(b2, b1 + 48)].hex(" "))
    if len(changes) > maxshow:
        print(f"  ... 其余 {len(changes)-maxshow} 处用 --max 查看")
    return len(changes)


def diff_text(a, b):
    ta = a.decode("utf-8", "replace").splitlines()
    tb = b.decode("utf-8", "replace").splitlines()
    diff = difflib.unified_diff(ta, tb, fromfile="A", tofile="B", lineterm="")
    out = list(diff)
    if not out:
        print("[=] 文本一致")
        return 0
    print("\n".join(out))
    return len([x for x in out if x.startswith(("+", "-")) and not x.startswith(("+++", "---"))])


def selftest():
    a = bytes(range(256)) * 4
    b = bytearray(a)
    b[100] = 0xEE
    b[300:300] = b"\x00\x01\x02"   # 插入 3 字节
    n = diff_binary(bytes(a), bytes(b), maxshow=5)
    assert n >= 1
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="二进制/文本差异对比")
    ap.add_argument("a", nargs="?")
    ap.add_argument("b", nargs="?")
    ap.add_argument("--window", type=int, default=32)
    ap.add_argument("--max", type=int, default=20)
    ap.add_argument("--text", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.a or not a.b:
        print("[!] 用法: python binary_diff.py fileA fileB"); return
    da, db = open(a.a, "rb").read(), open(a.b, "rb").read()
    if a.text:
        diff_text(da, db)
    else:
        diff_binary(da, db, a.window, a.max)


if __name__ == "__main__":
    main()
