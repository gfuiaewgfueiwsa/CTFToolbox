# -*- coding: utf-8 -*-
# 脚本名称: 0/1（或黑白）像素矩阵还原二维码
# 方向: Misc（图片隐写 / 编码）
# 简介: 题目给出一个由 0/1、0/255、黑白方块组成的矩阵文本（txt/csv），
#       本脚本把它渲染成标准黑白 PNG 二维码图片，再调用 pyzbar/OpenCV 解码；
#       支持任意两种符号（如 █/空格、■/□、X/.），自动识别。
# 用法:
#   python pixel_matrix_qr.py matrix.txt --cell 10
#   python pixel_matrix_qr.py matrix.txt --sym '01'      # 指定两个符号
#   python pixel_matrix_qr.py --selftest
# 依赖: pip install pillow opencv-python   （pyzbar 可选，没有也能用 cv2 解）
import argparse
import os
import re
import numpy as np
from PIL import Image


def parse_matrix(text, sym=None):
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if sym:
        a, b = sym[0], sym[1]
    else:
        # 自动挑出现最多的两个非空白符号
        from collections import Counter
        c = Counter(ch for line in lines for ch in line if not ch.isspace())
        common = [x for x, _ in c.most_common(2)]
        if len(common) < 2:   # 纯 0/1 数字矩阵
            common = ["0", "1"]
        a, b = common[0], common[1]
    rows = []
    for line in lines:
        row = []
        for ch in line:
            if ch == a:
                row.append(0)
            elif ch == b:
                row.append(255)
        if row:
            rows.append(row)
    w = max(len(r) for r in rows)
    for r in rows:
        r += [255] * (w - len(r))
    return np.array(rows, dtype=np.uint8), (a, b)


def render(arr, cell, quiet=4):
    h, w = arr.shape
    canvas = np.full(((h + 2 * quiet) * cell, (w + 2 * quiet) * cell), 255, np.uint8)
    for y in range(h):
        for x in range(w):
            if arr[y, x] == 0:
                canvas[(y + quiet) * cell:(y + quiet + 1) * cell,
                       (x + quiet) * cell:(x + quiet + 1) * cell] = 0
    return Image.fromarray(canvas, mode="L")


def decode_qr(path):
    try:
        import cv2
        img = cv2.imread(path)
        d = cv2.QRCodeDetector()
        data, pts, _ = d.detectAndDecode(img)
        if data:
            return data
    except Exception:
        pass
    try:
        from pyzbar.pyzbar import decode
        for r in decode(Image.open(path)):
            return r.data.decode()
    except Exception:
        pass
    return None


def main_run(path, cell=10, sym=None):
    text = open(path, encoding="utf-8", errors="replace").read()
    arr, used = parse_matrix(text, sym)
    print(f"[*] 识别矩阵 {arr.shape}, 符号 {used}")
    img = render(arr, cell)
    out = os.path.splitext(path)[0] + "_qr.png"
    img.save(out)
    print("[+] 二维码图片:", out)
    data = decode_qr(out)
    print("[+] 解码内容:", data if data else "(未自动解出，请用手机/在线 QR 识别打开图片)")
    return out, data


def selftest():
    try:
        import qrcode
    except Exception:
        print("[-] selftest 需要 pip install qrcode，跳过")
        return
    # 直接取模块级布尔矩阵（True=黑模块），模拟题目给出的 0/1 文本
    q = qrcode.QRCode(border=4)
    q.add_data("flag{matrix_qr_ok}")
    q.make(fit=True)
    txt = "\n".join("".join("0" if dark else "1" for dark in row)
                    for row in q.modules)
    p = os.path.join(os.environ.get("TEMP", "."), "matrix.txt")
    open(p, "w").write(txt)
    out, data = main_run(p, cell=10)
    assert data and "matrix_qr_ok" in data, data
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="像素矩阵还原二维码")
    ap.add_argument("txt", nargs="?")
    ap.add_argument("--cell", type=int, default=10)
    ap.add_argument("--sym", help="两个字符，分别代表黑、白，如 01 或 '█ '")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.txt:
        print("[!] 用法: python pixel_matrix_qr.py matrix.txt"); return
    main_run(a.txt, a.cell, a.sym)


if __name__ == "__main__":
    main()
