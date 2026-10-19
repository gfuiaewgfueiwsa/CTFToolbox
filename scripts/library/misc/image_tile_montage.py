# -*- coding: utf-8 -*-
# 脚本名称: 图片碎片拼接（网格拼图还原 / 长图切片合并）
# 方向: Misc（图片隐写）
# 简介: 题目给出被切成行列网格的一堆碎片（000.png、001.png… 命名规则），
#       本脚本按文件名中的数字自动按网格拼回整图；也支持把目录中所有等尺寸
#       小图按指定行列数强制网格拼接。
# 用法:
#   python image_tile_montage.py tiles_dir --cols 10 --rows 10
#   python image_tile_montage.py tiles_dir --auto        # 自动按文件名行列号
#   python image_tile_montage.py --selftest
# 依赖: pip install pillow
import argparse
import os
import re
from PIL import Image


def natural_key(name):
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", name)]


def montage(folder, cols=None, rows=None, auto=False, out=None):
    files = [f for f in os.listdir(folder) if f.lower().endswith((".png", ".jpg", ".jpeg", ".bmp", ".gif"))]
    files.sort(key=natural_key)
    imgs = [Image.open(os.path.join(folder, f)).convert("RGBA") for f in files]
    n = len(imgs)
    if auto:
        # 文件名形如 r0c3 / 0_5 / row1_col2 时解析行列
        rc = []
        for f in files:
            nums = [int(x) for x in re.findall(r"\d+", f)]
            rc.append(nums[-2:] if len(nums) >= 2 else (0, nums[0] if nums else 0))
        rows = max(r for r, c in rc) + 1
        cols = max(c for r, c in rc) + 1
        grid = {}
        for (r, c), im in zip(rc, imgs):
            grid[(r, c)] = im
        tw, th = imgs[0].size
        canvas = Image.new("RGBA", (cols * tw, rows * th), (0, 0, 0, 255))
        for (r, c), im in grid.items():
            canvas.paste(im, (c * tw, r * th))
    else:
        cols = cols or int(n ** 0.5) or 1
        rows = rows or (n + cols - 1) // cols
        tw, th = imgs[0].size
        canvas = Image.new("RGBA", (cols * tw, rows * th), (0, 0, 0, 255))
        for i, im in enumerate(imgs):
            r, c = divmod(i, cols)
            canvas.paste(im, (c * tw, r * th))
    out = out or os.path.join(folder, "..", "montage_restored.png")
    out = os.path.abspath(out)
    canvas.save(out)
    print(f"[+] {n} 张碎片按 {cols}x{rows} 拼接 -> {out}")


def selftest():
    d = os.path.join(os.environ.get("TEMP", "."), "tiles_self")
    os.makedirs(d, exist_ok=True)
    for i, color in enumerate([(255, 0, 0), (0, 255, 0), (0, 0, 255), (255, 255, 0)]):
        Image.new("RGBA", (16, 16), color).save(os.path.join(d, f"{i:03d}.png"))
    montage(d, cols=2, rows=2, out=os.path.join(d, "m.png"))
    assert os.path.exists(os.path.join(d, "m.png"))
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="图片碎片拼接")
    ap.add_argument("folder", nargs="?")
    ap.add_argument("--cols", type=int)
    ap.add_argument("--rows", type=int)
    ap.add_argument("--auto", action="store_true")
    ap.add_argument("-o", "--out")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.folder:
        print("[!] 用法: python image_tile_montage.py tiles_dir --cols 10 --rows 10"); return
    montage(a.folder, a.cols, a.rows, a.auto, a.out)


if __name__ == "__main__":
    main()
