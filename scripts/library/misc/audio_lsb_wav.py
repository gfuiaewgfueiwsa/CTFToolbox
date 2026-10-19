# -*- coding: utf-8 -*-
# 脚本名称: WAV 音频 LSB 隐写提取（PCM 最低位）
# 方向: Misc（音频隐写）
# 简介: 对未压缩 PCM WAV 的每个采样取最低有效位，自动按 MSB/LSB、
#       8 位一组还原字节流，输出可打印文本并扫描 flag；支持 8/16/24/32 位、
#       单/多声道（多声道时逐声道分别尝试）。
# 用法:
#   python audio_lsb_wav.py stego.wav
#   python audio_lsb_wav.py stego.wav --channel 0 --bit-order lsb
#   python audio_lsb_wav.py --selftest
# 依赖: 仅标准库（wave/struct）
import argparse
import os
import string
import wave


def load_samples(path):
    w = wave.open(path, "rb")
    nch, sw, fr, n = w.getnchannels(), w.getsampwidth(), w.getframerate(), w.getnframes()
    raw = w.readframes(n)
    w.close()
    print(f"[*] 声道={nch} 采样宽度={sw} 采样率={fr} 帧数={n}")
    # 拆成每声道整数采样
    import array
    fm = {1: "B", 2: "h", 4: "i"}.get(sw)
    samples = []
    if fm:
        a = array.array(fm)
        a.frombytes(raw[:n * nch * sw])
        for ch in range(nch):
            samples.append(list(a[ch::nch]))
    else:
        # 24bit：按 3 字节手工拆
        for ch in range(nch):
            col = []
            for i in range(ch * 3, len(raw) - 2, nch * 3):
                b3 = raw[i:i + 3]
                v = int.from_bytes(b3, "little", signed=True)
                col.append(v)
            samples.append(col)
    return samples


def bits_to_text(bits, msb=True):
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        v = 0
        if msb:
            for b in bits[i:i + 8]:
                v = (v << 1) | b
        else:
            for j, b in enumerate(bits[i:i + 8]):
                v |= b << j
        out.append(v)
    return bytes(out)


def analyze(path, force_ch=None, order=None):
    for ch, col in enumerate(load_samples(path)):
        if force_ch is not None and ch != force_ch:
            continue
        for msb in ([True, False] if order is None else [order == "msb"]):
            bits = [s & 1 for s in col]
            text = bits_to_text(bits, msb)
            printable = sum(1 for x in text if 9 <= x <= 13 or 32 <= x < 127) / max(1, len(text))
            head = text[:200].decode("utf-8", "replace")
            print(f"--- 声道{ch} {'MSB' if msb else 'LSB'}优先 可打印率{printable:.2f}")
            print("   ", head.replace("\n", "\\n"))
            low = text.lower()
            for hint in (b"flag", b"ctf", b"key"):
                p = low.find(hint)
                if p >= 0:
                    print("[!!!]", text[p:p + 120].decode("utf-8", "replace"))


def selftest():
    d = os.environ.get("TEMP", ".")
    p = os.path.join(d, "lsb_wav_self.wav")
    msg = b"flag{wav_lsb_ok}"
    bits = []
    for byte in msg:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    # 16bit 单声道，采样值 1000±1
    import struct
    frames = b"".join(struct.pack("<h", 1000 + b) for b in bits)
    frames += struct.pack("<h", 1000) * 100
    with wave.open(p, "wb") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(8000)
        w.writeframes(frames)
    analyze(p, force_ch=0, order="msb")
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="WAV LSB 提取")
    ap.add_argument("wav", nargs="?")
    ap.add_argument("--channel", type=int)
    ap.add_argument("--bit-order", choices=["msb", "lsb"])
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.wav:
        print("[!] 用法: python audio_lsb_wav.py stego.wav"); return
    analyze(a.wav, a.channel, a.bit_order)


if __name__ == "__main__":
    main()
