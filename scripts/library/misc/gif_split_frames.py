# -*- coding: utf-8 -*-
# 脚本名称: GIF 帧拆分与帧差分析（逐帧隐写/二维码闪图）
# 方向: Misc（图片隐写）
# 简介: 把 GIF/APNG 每一帧导出为 PNG，并额外生成：
#       1) 帧拼接长图（横向/纵向）；2) 相邻帧差异图（黑白闪烁藏 flag 时一眼可见）。
# 用法:
#   python gif_split_frames.py anim.gif
#   python gif_split_frames.py anim.gif --dir frames_out --montage v
#   python gif_split_frames.py --selftest
# 依赖: pip install pillow numpy
import argparse
import os
import numpy as np
from PIL import Image, ImageSequence


def split(path, outdir=None, montage="h"):
    im = Image.open(path)
    outdir = outdir or os.path.splitext(path)[0] + "_frames"
    os.makedirs(outdir, exist_ok=True)
    frames = []
    for i, fr in enumerate(ImageSequence.Iterator(im)):
        rgba = fr.convert("RGBA")
        fp = os.path.join(outdir, f"frame_{i:03d}.png")
        rgba.save(fp)
        frames.append(rgba)
    print(f"[+] 导出 {len(frames)} 帧到 {outdir}")

    # 拼接图
    if montage == "h":
        W = sum(f.width for f in frames)
        H = max(f.height for f in frames)
        canvas = Image.new("RGBA", (W, H), (0, 0, 0, 255))
        x = 0
        for f in frames:
            canvas.paste(f, (x, 0)); x += f.width
    else:
        W = max(f.width for f in frames)
        H = sum(f.height for f in frames)
        canvas = Image.new("RGBA", (W, H), (0, 0, 0, 255))
        y = 0
        for f in frames:
            canvas.paste(f, (0, y)); y += f.height
    mp = os.path.join(outdir, "montage.png")
    canvas.save(mp)
    print("[+] 拼接图:", mp)

    # 帧差图（第 i 帧与首帧差异），黑白闪烁题直接显字
    if len(frames) >= 2:
        base = np.array(frames[0].convert("RGB"), dtype=np.int16)
        for i in range(1, len(frames)):
            cur = np.array(frames[i].convert("RGB").resize(frames[0].size), dtype=np.int16)
            if cur.shape == base.shape:
                diff = np.abs(cur - base).sum(axis=2)
                mask = (diff > 30).astype(np.uint8) * 255
                Image.fromarray(mask).save(os.path.join(outdir, f"diff_{i:03d}.png"))
        print("[+] 帧差图已生成 diff_*.png")


def selftest():
    frames = []
    for color in ((255, 0, 0), (0, 255, 0), (0, 0, 255)):
        frames.append(Image.new("P", (32, 32)))
        frames[-1].putpalette([*color, *([0] * 765)])
    p = os.path.join(os.environ.get("TEMP", "."), "gif_selftest.gif")
    frames[0].save(p, save_all=True, append_images=frames[1:], duration=100, loop=0)
    split(p)
    assert os.path.exists(os.path.join(os.path.splitext(p)[0] + "_frames", "montage.png"))
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="GIF 拆帧/帧差")
    ap.add_argument("gif", nargs="?")
    ap.add_argument("--dir")
    ap.add_argument("--montage", choices=["h", "v"], default="h")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.gif:
        print("[!] 用法: python gif_split_frames.py anim.gif"); return
    split(a.gif, a.dir, a.montage)


if __name__ == "__main__":
    main()
