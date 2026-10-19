# -*- coding: utf-8 -*-
# 脚本名称: 文件熵分析（分块熵值定位加密/压缩/隐藏区域）
# 方向: Misc / 取证
# 简介: 对文件按固定块大小计算香农熵并输出文本热力分布，帮助快速判断：
#       高熵(>7.5)多为压缩/加密/媒体数据，低熵中夹高熵块往往是追加的隐藏 payload；
#       同时给出整体熵、各熵区间占比与可疑高熵区间偏移。
# 用法:
#   python entropy_map.py suspect.bin
#   python entropy_map.py suspect.bin --block 4096 --csv out.csv
#   python entropy_map.py --selftest
# 依赖: 仅标准库（matplotlib 可选，用于出图）
import argparse
import math
import os


def shannon(b):
    if not b:
        return 0.0
    cnt = [0] * 256
    for x in b:
        cnt[x] += 1
    e = 0.0
    n = len(b)
    for c in cnt:
        if c:
            p = c / n
            e -= p * math.log2(p)
    return e


def run(path, block, csv_out=None, png_out=None):
    raw = open(path, "rb").read()
    size = len(raw)
    print(f"[*] 文件 {os.path.basename(path)} 大小 {size} 字节，整体熵 {shannon(raw):.4f}")
    rows = []
    for off in range(0, size, block):
        chunk = raw[off:off + block]
        e = shannon(chunk)
        rows.append((off, e))
    # 文本热力条：每块一个字符
    bar = "".join(" " if e < 4 else ("." if e < 6 else ("-" if e < 7 else ("#" if e < 7.5 else "X")))
                  for _, e in rows)
    line = 64
    for i in range(0, len(bar), line):
        seg = rows[i:i + line]
        print(f"0x{seg[0][0]:08x} |{bar[i:i+line]}|")
    print("图例: ' '<4.0  '.'<6.0  '-'<7.0  '#'<7.5  'X'>=7.5(高熵)")
    high = [(o, e) for o, e in rows if e >= 7.5]
    if high:
        print(f"[!] 高熵块 {len(high)}/{len(rows)}，首个高熵偏移 0x{high[0][0]:x}")
        # 连续高熵区间
        start = prev = high[0][0]
        zones = []
        for o, _ in high[1:]:
            if o - prev > block:
                zones.append((start, prev + block))
                start = o
            prev = o
        zones.append((start, prev + block))
        for s, e2 in zones[:20]:
            print(f"    高熵区间 0x{s:x} - 0x{e2:x} ({e2-s} 字节)")
    if csv_out:
        with open(csv_out, "w") as f:
            f.write("offset,entropy\n")
            for o, e in rows:
                f.write(f"0x{o:x},{e:.4f}\n")
        print("[+] CSV:", csv_out)
    if png_out:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        plt.figure(figsize=(14, 4))
        plt.plot([o for o, _ in rows], [e for _, e in rows], lw=0.7)
        plt.ylim(0, 8); plt.xlabel("offset"); plt.ylabel("entropy")
        plt.savefig(png_out, dpi=120); print("[+] PNG:", png_out)


def selftest():
    d = os.path.join(os.environ.get("TEMP", "."), "ent_self")
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "t.bin")
    import os as _os
    open(p, "wb").write(b"A" * 8192 + _os.urandom(8192) + b"A" * 4096)
    run(p, 1024)
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="文件分块熵分析")
    ap.add_argument("file", nargs="?")
    ap.add_argument("--block", type=int, default=4096)
    ap.add_argument("--csv")
    ap.add_argument("--png")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.file:
        print("[!] 用法: python entropy_map.py suspect.bin"); return
    run(a.file, a.block, a.csv, a.png)


if __name__ == "__main__":
    main()
