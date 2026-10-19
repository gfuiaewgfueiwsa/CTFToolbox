# -*- coding: utf-8 -*-
# 脚本名称: 二维码/条形码本地识别（含旋转、透视、多码）
# 方向: Misc（图片隐写 / 编码）
# 简介: 调用 OpenCV 对图片中的 QRCode / 条形码做本地识别，自动尝试旋转 90/180/270
#       与灰度增强；支持一张图多个二维码。离线运行，不上传图片。
# 用法:
#   python qrcode_decode.py image.png
#   python qrcode_decode.py *.png            # 批量（shell 展开）
#   python qrcode_decode.py --selftest
# 依赖: pip install opencv-python pillow qrcode
import argparse
import glob
import os
import numpy as np
import cv2


def decode_one(path):
    img = cv2.imdecode(np.fromfile(path, dtype=np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        return []
    qr = cv2.QRCodeDetector()
    results = []
    for mat in (img, cv2.rotate(img, cv2.ROTATE_90_CLOCKWISE),
                cv2.rotate(img, cv2.ROTATE_180),
                cv2.rotate(img, cv2.ROTATE_90_COUNTERCLOCKWISE)):
        try:
            ok, datas, pts, _ = qr.detectAndDecodeMulti(mat)
            if ok:
                for d in datas:
                    if d and d not in results:
                        results.append(d)
        except Exception:
            data, pts, _ = qr.detectAndDecode(mat)
            if data and data not in results:
                results.append(data)
        # 微信风格 WeChatQRCode 不可用时忽略
    # 条形码（Code128/EAN 等）
    try:
        bd = cv2.barcode.BarcodeDetector()
        ok, decoded, _, _ = bd.detectAndDecode(img)
        if ok:
            for d in decoded:
                if d and d not in results:
                    results.append(d)
    except Exception:
        pass
    return results


def selftest():
    import qrcode
    p = os.path.join(os.environ.get("TEMP", "."), "qr_self.png")
    qrcode.make("flag{qr_decode_ok}").save(p)
    r = decode_one(p)
    assert any("qr_decode_ok" in x for x in r), r
    print("[+] selftest OK:", r)


def main():
    ap = argparse.ArgumentParser(description="二维码本地识别")
    ap.add_argument("images", nargs="*")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    files = []
    for pat in a.images:
        files += glob.glob(pat)
    if not files:
        print("[!] 用法: python qrcode_decode.py image.png"); return
    for f in files:
        r = decode_one(f)
        print(f"=== {f}")
        if r:
            for x in r:
                print("[+]", x)
        else:
            print("[-] 未识别到二维码（可尝试 QRazyBox 手工定位/修复）")


if __name__ == "__main__":
    main()
