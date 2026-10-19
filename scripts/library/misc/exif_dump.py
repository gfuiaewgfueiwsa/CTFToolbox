# -*- coding: utf-8 -*-
# 脚本名称: EXIF/元数据深度提取（图片/GPS/缩略图/注释）
# 方向: Misc（图片隐写 / 取证）
# 简介: 用 Pillow 提取 EXIF 全字段（含 GPS 经纬度换算）、XMP、PNG 文本块、
#       JPEG 注释段 COM、内嵌缩略图；并自动扫描元数据里的 flag 形态字符串。
# 用法:
#   python exif_dump.py photo.jpg
#   python exif_dump.py *.png
#   python exif_dump.py --selftest
# 依赖: pip install pillow
import argparse
import glob
import os
import re
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

FLAG_RE = re.compile(r"(?i)(?:flag|ctf|key|secret)\{[^}]{1,200}\}|[A-Za-z0-9_]{2,16}\{[^\}]{1,200}\}")


def gps_to_deg(val, ref):
    d, m, s = val
    deg = d + m / 60.0 + s / 3600.0
    return -deg if ref in ("S", "W") else deg


def dump(path):
    print(f"===== {path}")
    img = Image.open(path)
    print("格式/尺寸:", img.format, img.size, img.mode)
    # 通用 info（PNG text / GIF comment / JPEG comment）
    for k, v in img.info.items():
        if isinstance(v, bytes):
            try:
                v = v.decode("utf-8", "replace")
            except Exception:
                v = f"<bytes {len(v)}>"
        print(f"[info] {k}: {str(v)[:500]}")
    exif = getattr(img, "_getexif", lambda: None)()
    if exif:
        gps = {}
        for tag, val in exif.items():
            name = TAGS.get(tag, tag)
            if name == "GPSInfo":
                for t2, v2 in val.items():
                    gps[GPSTAGS.get(t2, t2)] = v2
                continue
            print(f"[exif] {name}: {val}")
        if gps:
            print("[gps] ", gps)
            try:
                lat = gps_to_deg(gps["GPSLatitude"], gps["GPSLatitudeRef"])
                lon = gps_to_deg(gps["GPSLongitude"], gps["GPSLongitudeRef"])
                print(f"[+] GPS 坐标: {lat:.6f}, {lon:.6f}")
                print(f"    地图: https://www.openstreetmap.org/?mlat={lat}&mlon={lon}")
            except Exception:
                pass
    # 原始字节兜底扫 flag/注释段
    raw = open(path, "rb").read()
    for m in FLAG_RE.findall(raw.decode("latin-1", "replace")):
        print("[!!!] 原始数据中疑似 flag:", m)
    # JPEG COM 段 (FFFE)
    i = 0
    while True:
        j = raw.find(b"\xff\xfe", i)
        if j < 0:
            break
        ln = int.from_bytes(raw[j + 2:j + 4], "big")
        print("[com]", raw[j + 4:j + 2 + ln].decode("utf-8", "replace")[:300])
        i = j + 2


def selftest():
    # 用 Pillow 写 PNG 文本块
    p = os.path.join(os.environ.get("TEMP", "."), "exif_self.png")
    img = Image.new("RGB", (8, 8), (0, 255, 0))
    img.save(p, pnginfo=None)
    from PIL.PngImagePlugin import PngInfo
    meta = PngInfo()
    meta.add_text("Comment", "flag{exif_in_png_text}")
    img.save(p, pnginfo=meta)
    dump(p)
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="EXIF 提取")
    ap.add_argument("images", nargs="*")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    files = []
    for pat in a.images:
        files += glob.glob(pat)
    if not files:
        print("[!] 用法: python exif_dump.py photo.jpg"); return
    for f in files:
        try:
            dump(f)
        except Exception as e:
            print(f"[-] {f} 失败: {e}")


if __name__ == "__main__":
    main()
