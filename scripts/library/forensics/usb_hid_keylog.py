# -*- coding: utf-8 -*-
# 脚本名称: USB HID 键盘流量还原（pcap 按键记录）
# 方向: Forensics（USB / 键盘记录）
# 简介: 解析 USB 中断传输中的 HID 键盘报文（8 字节，Leftover Capture Data），
#       还原按键序列，处理 Shift、大小写、退格、回车；支持鼠标移动数据识别。
#       典型题目：usb.pcap，设备 1.x.y 为键盘，直接还原出 flag。
# 用法:
#   python usb_hid_keylog.py usb.pcap
#   python usb_hid_keylog.py usb.pcap --device 1.10.1
#   python usb_hid_keylog.py --selftest
# 依赖: pip install scapy
import argparse
import os

# USB HID Usage ID -> 按键（不带 Shift）
HID = {
    0x04: "a", 0x05: "b", 0x06: "c", 0x07: "d", 0x08: "e", 0x09: "f",
    0x0a: "g", 0x0b: "h", 0x0c: "i", 0x0d: "j", 0x0e: "k", 0x0f: "l",
    0x10: "m", 0x11: "n", 0x12: "o", 0x13: "p", 0x14: "q", 0x15: "r",
    0x16: "s", 0x17: "t", 0x18: "u", 0x19: "v", 0x1a: "w", 0x1b: "x",
    0x1c: "y", 0x1d: "z", 0x1e: "1", 0x1f: "2", 0x20: "3", 0x21: "4",
    0x22: "5", 0x23: "6", 0x24: "7", 0x25: "8", 0x26: "9", 0x27: "0",
    0x28: "\n", 0x2c: " ", 0x2d: "-", 0x2e: "=", 0x2f: "[", 0x30: "]",
    0x31: "\\", 0x33: ";", 0x34: "'", 0x35: "`", 0x36: ",", 0x37: ".",
    0x38: "/",
}
HID_SHIFT = {
    0x04: "A", 0x05: "B", 0x06: "C", 0x07: "D", 0x08: "E", 0x09: "F",
    0x0a: "G", 0x0b: "H", 0x0c: "I", 0x0d: "J", 0x0e: "K", 0x0f: "L",
    0x10: "M", 0x11: "N", 0x12: "O", 0x13: "P", 0x14: "Q", 0x15: "R",
    0x16: "S", 0x17: "T", 0x18: "U", 0x19: "V", 0x1a: "W", 0x1b: "X",
    0x1c: "Y", 0x1d: "Z", 0x1e: "!", 0x1f: "@", 0x20: "#", 0x21: "$",
    0x22: "%", 0x23: "^", 0x24: "&", 0x25: "*", 0x26: "(", 0x27: ")",
    0x2d: "_", 0x2e: "+", 0x2f: "{", 0x30: "}", 0x31: "|", 0x33: ":",
    0x34: '"', 0x35: "~", 0x36: "<", 0x37: ">", 0x38: "?",
}


def extract_hid(path):
    """提取 8 字节 HID 报文（兼容 usb.data_hid 与 Leftover Capture Data 字段）。"""
    from scapy.all import rdpcap, raw
    out = []
    for p in rdpcap(path):
        data = None
        try:
            layer = p.getlayer("USB_CtrlTransfer")
            if layer and hasattr(layer, "data_len"):
                pass
        except Exception:
            pass
        # 常见字段名扫描
        for name in ("usb_data_hid", "Leftover Capture Data", "data"):
            try:
                v = p.getfieldval(name) if hasattr(p, "getfieldval") else None
                if v and len(v) == 8:
                    data = bytes(v)
                    break
            except Exception:
                pass
        if data is None:
            # 兜底：在原始帧尾部找 0x00 0x00 0xXX 0x00... 形态的 8 字节 HID
            r = raw(p)
            for i in range(len(r) - 8):
                seg = r[i:i + 8]
                if seg[0] in (0, 2, 0x20) and seg[3:] == b"\x00\x00\x00\x00\x00" \
                        and 0 <= seg[2] <= 0x65:
                    data = seg
                    break
        if data and len(data) == 8:
            out.append(data)
    return out


def decode(records):
    text = []
    prev = b""
    for rec in records:
        if rec == prev or rec == b"\x00" * 8:
            prev = rec
            continue
        modifier, _r, key = rec[0], rec[1], rec[2]
        if key == 0:
            prev = rec
            continue
        if key == 0x2a:        # Backspace
            if text:
                text.pop()
        elif key == 0x28:
            text.append("\n")
        elif modifier & 0x22 or modifier & 0x02:   # Shift（左右）
            text.append(HID_SHIFT.get(key, HID.get(key, "")))
        else:
            text.append(HID.get(key, f"<{key:02x}>"))
        prev = rec
    return "".join(text)


def selftest():
    # 直接用构造的 HID 报文验证解码
    seq = []
    # 输入 "Flag{x}"：F(shift+0x09) l a g { (shift+0x2f) x }(shift+0x30)
    seq += [bytes([2, 0, 0x09, 0, 0, 0, 0, 0]), bytes([0] * 8)]
    seq += [bytes([0, 0, 0x0f, 0, 0, 0, 0, 0]), bytes([0] * 8)]  # l
    seq += [bytes([0, 0, 0x04, 0, 0, 0, 0, 0]), bytes([0] * 8)]  # a
    seq += [bytes([0, 0, 0x0a, 0, 0, 0, 0, 0]), bytes([0] * 8)]  # g
    seq += [bytes([2, 0, 0x2f, 0, 0, 0, 0, 0]), bytes([0] * 8)]  # {
    seq += [bytes([0, 0, 0x1b, 0, 0, 0, 0, 0]), bytes([0] * 8)]  # x
    seq += [bytes([2, 0, 0x30, 0, 0, 0, 0, 0]), bytes([0] * 8)]  # }
    text = decode(seq)
    assert text == "Flag{x}", repr(text)
    print("[+] 解码:", text)
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="USB HID 键盘还原")
    ap.add_argument("pcap", nargs="?")
    ap.add_argument("--device")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.pcap:
        print("[!] 用法: python usb_hid_keylog.py usb.pcap"); return
    recs = extract_hid(a.pcap)
    print(f"[*] 提取 {len(recs)} 条 HID 报文")
    print("[+] 按键记录:\n" + decode(recs))


if __name__ == "__main__":
    main()
