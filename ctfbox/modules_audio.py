# -*- coding: utf-8 -*-
"""音频隐写分析全套（WAV / MP3 / FLAC / OGG / M4A / AAC / WMA / AMR / OPUS / AIFF / AU）。

能力：
  - 任意格式经随包 ffmpeg 静默解码为 16bit PCM WAV 再分析（干净电脑无需装环境）；
  - 音频基本信息、ffprobe/ID3/Vorbis/WAV-LIST 元数据与标签 flag 扫描；
  - 多位面 LSB 隐写：bit0~bit2 × 左/右/交错/中置/侧置 × MSB/LSB 位序，
    自动识别 flag / 常见文件头 / 高可读文本并落盘，命中文件头自动登记递归；
  - 高分辨率语谱图（全频带 + 低频带放大）+ 立体声侧声道语谱图（频谱藏字题）；
  - 波形包络图；
  - DTMF 拨号音解码、摩斯电码(音调开关键控)自动解码、双音 FSK 二进制自动解码；
  - 中置/侧置(Mid/Side)声道导出、反转音频导出（倒放藏字题）；
  - WAV 尾部附加数据提取、DeepSound/MP3Stego 痕迹、steghide 链、SSTV 慢扫描提示。
重活依赖 numpy / Pillow；格式转换依赖随包 ffmpeg/ffprobe，缺失时给出明确提示。
"""
import os
import re
import wave
import struct
import subprocess

import numpy as np

from .common import (Report, scan_flags, safe_name, shannon_entropy)

AUDIO_EXTS = (".wav", ".mp3", ".flac", ".ogg", ".m4a", ".aac", ".wma", ".amr",
              ".opus", ".aif", ".aiff", ".au", ".ape", ".mka", ".oga")

# 常见隐藏载荷文件头（LSB 解出数据命中即判定为文件并雕刻保存）
MAGIC_HEADERS = [
    (b"\x89PNG\r\n\x1a\n", "PNG图片", ".png"),
    (b"\xff\xd8\xff", "JPEG图片", ".jpg"),
    (b"GIF87a", "GIF", ".gif"),
    (b"GIF89a", "GIF", ".gif"),
    (b"PK\x03\x04", "ZIP压缩包", ".zip"),
    (b"Rar!\x1a\x07", "RAR压缩包", ".rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z压缩包", ".7z"),
    (b"%PDF", "PDF文档", ".pdf"),
    (b"\x1f\x8b\x08", "GZIP", ".gz"),
    (b"BZh", "BZIP2", ".bz2"),
    (b"RIFF", "RIFF容器", ".riff"),
    (b"fLaC", "FLAC音频", ".flac"),
    (b"ID3", "MP3音频", ".mp3"),
    (b"OggS", "OGG容器", ".ogg"),
    (b"\x7fELF", "ELF", ".elf"),
    (b"MZ", "PE可执行文件", ".exe"),
    (b"SQLite format 3\x00", "SQLite数据库", ".sqlite"),
]

LSB_SAMPLE_CAP = 12_000_000     # 每个平面参与 LSB 的样本上限
SPEC_COLS = 1800                # 语谱图时间轴列数上限


# ----------------------------------------------------------------------------
# 外部工具
# ----------------------------------------------------------------------------
def _ffmpeg():
    from . import toolsmgr
    exe = toolsmgr.get_tool("ffmpeg")
    if exe:
        return exe
    import shutil
    return shutil.which("ffmpeg") or shutil.which("ffmpeg.exe")


def _ffprobe():
    from . import toolsmgr
    exe = toolsmgr.get_tool("ffprobe")
    if exe:
        return exe
    ff = _ffmpeg()
    if ff:
        cand = os.path.join(os.path.dirname(ff), "ffprobe.exe")
        if os.path.exists(cand):
            return cand
    import shutil
    return shutil.which("ffprobe") or shutil.which("ffprobe.exe")


def _run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, timeout=300)
    except Exception:
        return None


# ----------------------------------------------------------------------------
# 解码 / 读取
# ----------------------------------------------------------------------------
def decode_to_wav(path, outdir):
    """非 WAV（或打不开的 WAV）经 ffmpeg 转 16bit PCM WAV；返回 wav 路径。"""
    can_open = False
    try:
        w = wave.open(path, "rb")
        # 仅支持标准 PCM/未压缩 WAV 直读，压缩 WAV 也走 ffmpeg
        can_open = w.getcomptype() == "NONE"
        w.close()
    except Exception:
        can_open = False
    if can_open:
        return path
    ff = _ffmpeg()
    if not ff:
        return None
    os.makedirs(outdir, exist_ok=True)
    out = os.path.join(outdir, "decoded_" + safe_name(os.path.splitext(os.path.basename(path))[0]) + ".wav")
    r = _run([ff, "-y", "-hide_banner", "-loglevel", "error", "-i", path,
              "-vn", "-c:a", "pcm_s16le", out])
    if r is not None and r.returncode == 0 and os.path.exists(out):
        return out
    return None


def load_pcm(wav_path):
    """读取 WAV，返回 (int16 二维数组[n,ch], float32 二维数组[n,ch], sr, nch)。"""
    w = wave.open(wav_path, "rb")
    nch, sw, sr, nframes = w.getnchannels(), w.getsampwidth(), w.getframerate(), w.getnframes()
    raw = w.readframes(nframes)
    w.close()
    if sw == 1:                  # 8bit 无符号
        x = (np.frombuffer(raw, dtype=np.uint8).astype(np.int32) - 128) << 8
    elif sw == 2:
        x = np.frombuffer(raw, dtype="<i2").astype(np.int32)
    elif sw == 4:
        x = (np.frombuffer(raw, dtype="<i4").astype(np.int64) >> 16).astype(np.int32)
    elif sw == 3:
        b = np.frombuffer(raw, dtype=np.uint8).reshape(-1, 3)
        x = (b[:, 0].astype(np.int32) | (b[:, 1].astype(np.int32) << 8) |
             (b[:, 2].astype(np.int32) << 16))
        x = np.where(x & 0x800000, x - 0x1000000, x)
        x = (x >> 8).astype(np.int32)
    else:
        raise ValueError(f"不支持的采样宽度 {sw}")
    if nch > 1:
        x = x.reshape(-1, nch)
    else:
        x = x.reshape(-1, 1)
    x = x[:LSB_SAMPLE_CAP]
    f = x.astype(np.float32) / 32768.0
    return x.astype(np.int16), f, sr, nch


def write_wav(path, samples_int16, sr):
    """写 16bit 单/立体声 WAV（samples 为 [n] 或 [n,ch] int16）。"""
    y = np.asarray(samples_int16, dtype="<i2")
    nch = 1 if y.ndim == 1 else y.shape[1]
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with wave.open(path, "wb") as w:
        w.setnchannels(nch)
        w.setsampwidth(2)
        w.setframerate(sr)
        w.writeframes(y.tobytes())
    return path


# ----------------------------------------------------------------------------
# 入口
# ----------------------------------------------------------------------------
def analyze(path, report: Report, outdir: str, do_carve: bool = False):
    os.makedirs(outdir, exist_ok=True)
    try:
        from PIL import Image  # noqa: F401
    except Exception:
        report.add("warn", "缺少 numpy/Pillow", "音频隐写分析需要 numpy 与 Pillow")
        return

    raw = b""
    try:
        with open(path, "rb") as f:
            raw = f.read(20 * 1024 * 1024)
    except Exception:
        pass

    wav_path = decode_to_wav(path, outdir)
    if not wav_path:
        report.add("warn", "音频解码失败",
                   "无法解析该音频；请在「工具中心」预置 FFmpeg 运行时后重试")
        return
    converted = os.path.abspath(wav_path) != os.path.abspath(path)
    try:
        xi, xf, sr, nch = load_pcm(wav_path)
    except Exception as e:
        report.add("warn", "PCM 读取失败", str(e))
        return

    n = xi.shape[0]
    dur = n / max(1, sr)
    report.add("info", "音频信息",
               f"文件: {os.path.basename(path)}" +
               (f"（已由 ffmpeg 解码为 PCM）" if converted else "") +
               f"\n声道={nch} 采样率={sr}Hz 位深=16bit 样本={n} 时长={dur:.2f}s")
    with open(wav_path, "rb") as f:
        head = f.read(4 * 1024 * 1024)
    report.add("info", "音频数据熵", f"{shannon_entropy(head):.4f}（接近 8.0 可能为加密/已压缩隐写载体）")

    # 1) 元数据 / 标签
    _metadata(path, report)

    # 2) 隐写工具痕迹
    try:
        from . import modules_forensics
        modules_forensics.audio_stego_signatures(path, report)
    except Exception:
        pass

    # 3) LSB 多位面隐写
    try:
        _lsb(xi, report, outdir)
    except Exception as e:
        report.add("info", "LSB 分析跳过", str(e)[:100])

    # 4) 语谱图 / 波形
    try:
        _spectrograms(xf, sr, nch, outdir, report)
    except Exception as e:
        report.add("info", "语谱图生成跳过", str(e)[:100])

    # 5) DTMF 拨号音
    try:
        from . import modules_forensics
        modules_forensics.dtmf_decode_wav(wav_path, report)
    except Exception:
        pass

    # 6) 摩斯电码（音调开关键控）
    try:
        _morse(xf, sr, report)
    except Exception as e:
        report.add("info", "摩斯解码跳过", str(e)[:80])

    # 7) 双音 FSK 二进制
    try:
        _fsk_binary(xf, sr, report, outdir)
    except Exception as e:
        report.add("info", "FSK 解码跳过", str(e)[:80])

    # 8) 中置/侧置声道、反转音频导出
    try:
        _derive_audio(xi, sr, nch, path, outdir, report)
    except Exception as e:
        report.add("info", "派生音频导出跳过", str(e)[:80])

    # 9) WAV 尾部附加数据
    try:
        _wav_tail(path, report, outdir)
    except Exception:
        pass

    # 10) SSTV 慢扫描电视提示
    try:
        _sstv_hint(xf, sr, report)
    except Exception:
        pass

    # 11) steghide（WAV）
    if path.lower().endswith((".wav", ".au", ".jpeg", ".jpg", ".bmp")):
        try:
            from . import modules_forensics
            modules_forensics.steghide_chain(path, report, out_dir=os.path.join(outdir, "steghide"))
        except Exception:
            pass

    # 12) 手动模式下补做雕刻与字符串（自动调度流程本身会做，避免重复）
    if do_carve:
        try:
            from . import modules_carve
            modules_carve.scan_and_carve(path, report, os.path.join(outdir, "carve"))
            modules_carve.strings_scan(path, report)
        except Exception:
            pass


# ----------------------------------------------------------------------------
# 元数据
# ----------------------------------------------------------------------------
def _metadata(path, report):
    lines, tags_blob = [], []
    fp = _ffprobe()
    if fp:
        r = _run([fp, "-v", "quiet", "-print_format", "json",
                  "-show_format", "-show_streams", path])
        if r is not None and r.returncode == 0 and r.stdout:
            try:
                import json
                data = json.loads(r.stdout.decode("utf-8", "replace"))
                fmt = data.get("format", {})
                for k in ("format_name", "duration", "bit_rate", "tags"):
                    if k in fmt and k != "tags":
                        lines.append(f"{k}: {fmt[k]}")
                for k, v in (fmt.get("tags") or {}).items():
                    lines.append(f"TAG {k} = {v}")
                    tags_blob.append(str(v))
                for st in data.get("streams", []):
                    for k, v in (st.get("tags") or {}).items():
                        lines.append(f"STREAM TAG {k} = {v}")
                        tags_blob.append(str(v))
            except Exception:
                pass
    # WAV LIST/INFO 与 ID3 原始字符串兜底
    try:
        with open(path, "rb") as f:
            head = f.read(2 * 1024 * 1024)
        for tag in (b"INAM", b"IART", b"ICMT", b"ICOP", b"IGNR", b"ISFT", b"ITRK"):
            i = 0
            while True:
                j = head.find(tag, i)
                if j < 0:
                    break
                chunk = head[j + 4:j + 260].split(b"\x00", 1)[0]
                txt = chunk.decode("utf-8", "replace").strip()
                if txt and len(txt) >= 2:
                    lines.append(f"{tag.decode()} {txt}")
                    tags_blob.append(txt)
                i = j + 4
    except Exception:
        pass
    if lines:
        report.add("ok", "音频元数据/标签", "\n".join(lines[:60])[:2500])
        for fl in scan_flags("\n".join(tags_blob).encode("utf-8", "ignore")):
            report.add("flag", "音频标签中发现 flag", fl)
    else:
        report.add("info", "音频元数据", "未发现标签（或 ffprobe 未就绪）")


# ----------------------------------------------------------------------------
# 多位面 LSB
# ----------------------------------------------------------------------------
def _bits_to_bytes(bits, msb_first=True):
    n = len(bits) - len(bits) % 8
    bits = bits[:n]
    if not n:
        return b""
    b = np.asarray(bits, dtype=np.uint8).reshape(-1, 8)
    if msb_first:
        w = (1 << np.arange(7, -1, -1)).astype(np.uint32)
    else:
        w = (1 << np.arange(0, 8)).astype(np.uint32)
    return (b.astype(np.uint32) * w).sum(axis=1).astype(np.uint8).tobytes()


def _grade(data):
    """返回 (分值, 命中类型列表, flags)；分值越高越像隐藏载荷。"""
    head = data[:512]
    score, kinds, flags = 0, [], []
    fl = scan_flags(data[:2 * 1024 * 1024])
    if fl:
        score += 100
        flags = fl
        kinds.append("flag")
    for magic, name, _ext in MAGIC_HEADERS:
        if head.startswith(magic) or data[:2048].find(magic) >= 0:
            score += 60
            kinds.append("文件头:" + name)
            break
    printable = sum(1 for b in head if 9 <= b <= 13 or 32 <= b < 127) / max(1, len(head))
    if printable > 0.92 and re.search(rb"[A-Za-z0-9_ \{\}\-:;,.]{10,}", head):
        score += 20
        kinds.append("可读文本")
    return score, kinds, flags


def _lsb(xi, report, outdir):
    nch = xi.shape[1]
    planes = {}
    for c in range(nch):
        planes[f"CH{c+1}"] = xi[:, c]
    if nch >= 2:
        planes["交错LR"] = xi.reshape(-1)
        mid = ((xi[:, 0].astype(np.int32) + xi[:, 1].astype(np.int32)) // 2).astype(np.int16)
        side = (xi[:, 0].astype(np.int32) - xi[:, 1].astype(np.int32)).astype(np.int16)
        planes["中置Mid"] = mid
        planes["侧置Side"] = side
    hits = 0
    saved_strong = set()
    for pname, samples in planes.items():
        for bit in range(3):
            vals = ((samples.astype(np.int32) >> bit) & 1).astype(np.uint8)
            for msb in (True, False):
                data = _bits_to_bytes(vals, msb)
                if not data:
                    continue
                score, kinds, flags = _grade(data)
                if score <= 0:
                    continue
                order = "MSB" if msb else "LSB"
                fp = os.path.join(outdir, f"audio_lsb_{safe_name(pname)}_bit{bit}_{order}.bin")
                with open(fp, "wb") as f:
                    f.write(data[:4 * 1024 * 1024])
                preview = data[:160].decode("latin-1", "replace").replace("\x00", "")
                report.add("ok", f"音频LSB提取 {pname} 第{bit}位/{order}序 [{', '.join(kinds)}]",
                           f"预览: {preview!r}\n已保存: {fp}")
                for flg in flags:
                    report.add("flag", f"音频LSB({pname}/bit{bit}/{order}) 中发现 flag", flg)
                # 命中文件头：登记递归（雕刻/解压），同一平面只登记一次
                if any(k.startswith("文件头") for k in kinds) and fp not in saved_strong:
                    report.extracted.append(fp)
                    saved_strong.add(fp)
                    _carve_embedded(data, outdir, report, pname, bit, order)
                hits += 1
    if not hits:
        report.add("info", "音频 LSB 隐写", "bit0~bit2 各声道/位序未发现可读数据或文件头")


def _carve_embedded(data, outdir, report, pname, bit, order):
    """从 LSB 数据中把命中的内嵌文件头雕刻成对应后缀文件。"""
    for magic, name, ext in MAGIC_HEADERS:
        off = data.find(magic)
        if 0 <= off < 2048:
            payload = data[off:]
            fp = os.path.join(outdir, f"lsb_payload_{safe_name(pname)}_b{bit}_{order}{ext}")
            with open(fp, "wb") as f:
                f.write(payload[:8 * 1024 * 1024])
            report.add("ok", f"LSB 中雕刻出 {name}", fp)
            if fp not in report.extracted:
                report.extracted.append(fp)
            for fl in scan_flags(payload[:2 * 1024 * 1024]):
                report.add("flag", "LSB 载荷中发现 flag", fl)
            return


# ----------------------------------------------------------------------------
# 语谱图 / 波形
# ----------------------------------------------------------------------------
def _stft_mag(mono, sr, nfft=2048, hop=None):
    hop = hop or nfft // 4
    win = np.hanning(nfft)
    need = min(len(mono), LSB_SAMPLE_CAP)
    mono = mono[:need]
    ncol = max(1, (len(mono) - nfft) // hop)
    # 列数过多则加大 hop
    if ncol > SPEC_COLS:
        hop = max(hop, (len(mono) - nfft) // SPEC_COLS)
        ncol = max(1, (len(mono) - nfft) // hop)
    idx = np.arange(ncol) * hop
    frames = np.lib.stride_tricks.as_strided(
        mono, shape=(ncol, nfft),
        strides=(mono.strides[0] * hop, mono.strides[0])) * win
    mag = np.abs(np.fft.rfft(frames, n=nfft))
    freqs = np.fft.rfftfreq(nfft, 1.0 / sr)
    return mag, freqs


def _spec_image(mag, freqs, fmax=None, percentile_hi=99.9):
    db = 20 * np.log10(mag.T + 1e-8)
    if fmax:
        keep = int(np.searchsorted(freqs, fmax))
        db = db[:max(2, keep), :]
    lo, hi = np.percentile(db, 20), np.percentile(db, percentile_hi)
    img = np.clip((db - lo) / max(1e-6, hi - lo), 0, 1)
    im = np.flipud((img * 255).astype(np.uint8))
    return im


def _spectrograms(xf, sr, nch, outdir, report):
    from PIL import Image
    mono = xf.mean(axis=1) if nch > 1 else xf[:, 0]
    mag, freqs = _stft_mag(mono, sr)
    made = []
    full = _spec_image(mag, freqs)
    fp = os.path.join(outdir, "audio_spectrogram.png")
    Image.fromarray(full).save(fp)
    made.append(("全频带语谱图", fp))
    # 低频带放大（频谱画字常贴 0~4kHz 底部）
    lowf = min(4000, sr / 2 - 100)
    low = _spec_image(mag, freqs, fmax=lowf, percentile_hi=99.95)
    h, w = low.shape
    fp2 = os.path.join(outdir, "audio_spectrogram_low.png")
    Image.fromarray(low).resize((min(3600, w * 2), h * 2), Image.BILINEAR).save(fp2)
    made.append(("低频带放大(0-%dHz)" % int(lowf), fp2))
    if nch > 1:
        side = (xf[:, 0] - xf[:, 1]) / 2.0
        if np.abs(side).max() > 1e-4:
            ms, fs2 = _stft_mag(side, sr)
            sim = _spec_image(ms, fs2, percentile_hi=99.95)
            fp3 = os.path.join(outdir, "audio_spectrogram_side.png")
            Image.fromarray(sim).save(fp3)
            made.append(("侧声道(Side)语谱图", fp3))
    # 波形包络图
    fp4 = _waveform_png(mono, outdir)
    if fp4:
        made.append(("波形包络图", fp4))
    for nm, p in made:
        report.add("tool", f"已生成{nm}（请肉眼查看是否藏字/盲文/摩斯）", p)


def _waveform_png(mono, outdir, width=1600, height=360):
    from PIL import Image, ImageDraw
    if len(mono) < width:
        return None
    bins = np.array_split(mono, width)
    top, bot = [], []
    mid = height // 2
    for seg in bins:
        if len(seg) == 0:
            top.append(mid); bot.append(mid); continue
        mn, mx = seg.min(), seg.max()
        top.append(int(mid - mx * mid * 0.95))
        bot.append(int(mid - mn * mid * 0.95))
    im = Image.new("RGB", (width, height), (16, 16, 20))
    dr = ImageDraw.Draw(im)
    dr.line([(0, mid), (width, mid)], fill=(70, 70, 80))
    for x in range(width):
        dr.line([(x, top[x]), (x, bot[x])], fill=(90, 200, 250))
    fp = os.path.join(outdir, "audio_waveform.png")
    im.save(fp)
    return fp


# ----------------------------------------------------------------------------
# 摩斯电码（音调开关键控）
# ----------------------------------------------------------------------------
MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9", ".-.-.-": ".", "--..--": ",", "..--..": "?",
    "-..-.": "/", "-.--.": "(", "-.--.-": ")", ".-...": "&", "---...": ":",
    "-.-.-.": ";", "-...-": "=", ".-.-.": "+", ".----.": "'", "-..-.": "/",
    ".-..-.": '"', "...-..-": "$", ".--.-.": "@", "-....-": "-", "..--.-": "_",
}


def _tone_envelope(mono, sr, f_lo=400, f_hi=3000, win=0.03, hop=0.01):
    """逐帧判断是否存在显著窄带单音（频谱峰值远高于本底），返回布尔序列与帧长(秒)。"""
    n = int(win * sr)
    h = int(hop * sr)
    nfft = max(256, 1 << (n - 1).bit_length())
    winf = np.hanning(n)
    flags = []
    powers = []
    for st in range(0, len(mono) - n, h):
        seg = mono[st:st + n] * winf
        if np.sum(seg ** 2) < 1e-6:
            flags.append(False); powers.append(0.0); continue
        sp = np.abs(np.fft.rfft(seg, n=nfft))
        fr = np.fft.rfftfreq(nfft, 1.0 / sr)
        band = (fr >= f_lo) & (fr <= f_hi)
        if band.sum() < 4:
            flags.append(False); powers.append(0.0); continue
        sub = sp[band]
        pk = sub.max()
        mean = sub.mean() + 1e-9
        powers.append(float(pk / mean))
        flags.append(bool(pk / mean > 6.0 and pk > 0.05))
    return flags, hop


def _runs(flags):
    out, cur, start = [], flags[0], 0
    for i in range(1, len(flags)):
        if flags[i] != cur:
            out.append((cur, i - start))
            cur, start = flags[i], i
    out.append((cur, len(flags) - start))
    return out


def _morse(xf, sr, report):
    mono = xf.mean(axis=1) if xf.shape[1] > 1 else xf[:, 0]
    mono = mono / (np.abs(mono).max() or 1.0)
    flags, hop = _tone_envelope(mono, sr)
    runs = _runs(flags)
    on_lens = [ln for v, ln in runs if v and ln >= 2]
    if len(on_lens) < 3:
        return
    on_lens.sort()
    dit = max(1, on_lens[len(on_lens) // 4])      # 用较短的一批估计点长
    text, cur = [], ""
    gap_letter = max(2.2, dit * 2.2)
    gap_word = max(4.5, dit * 4.5)
    for v, ln in runs:
        if v:
            cur += "-" if ln >= dit * 2.2 else "."
        else:
            if cur and ln >= gap_letter:
                text.append(MORSE.get(cur, "?"))
                cur = ""
                if ln >= gap_word:
                    text.append(" ")
    if cur:
        text.append(MORSE.get(cur, "?"))
    out = "".join(text).strip()
    letters = [c for c in out if c.isalnum()]
    if len(letters) >= 3:
        report.add("ok", "摩斯电码解码(音调键控)", out)
        for fl in scan_flags(out.encode()):
            report.add("flag", "摩斯电码中发现 flag", fl)
    else:
        report.add("info", "摩斯电码", "检测到断续单音但未能稳定解码，可结合语谱图/波形人工判读")


# ----------------------------------------------------------------------------
# 双音 FSK 二进制
# ----------------------------------------------------------------------------
def _fsk_binary(xf, sr, report, outdir):
    mono = xf.mean(axis=1) if xf.shape[1] > 1 else xf[:, 0]
    mono = mono / (np.abs(mono).max() or 1.0)
    n = int(0.02 * sr)
    h = int(0.01 * sr)
    nfft = max(512, 1 << (n - 1).bit_length())
    winf = np.hanning(n)
    rows, fr = [], None
    for st in range(0, len(mono) - n, h):
        seg = mono[st:st + n] * winf
        sp = np.abs(np.fft.rfft(seg, n=nfft))
        fr = np.fft.rfftfreq(nfft, 1.0 / sr)
        rows.append(sp)
    if len(rows) < 50:
        return
    S = np.array(rows)
    band = (fr >= 300) & (fr <= 4000)
    Sb = S[:, band]
    fb = fr[band]
    # 占用率最高的两个频点作为 mark/space
    occ = (Sb > Sb.mean(axis=1, keepdims=True) * 3).sum(axis=0)
    peaks = np.where(occ > len(Sb) * 0.15)[0]
    if len(peaks) < 2:
        return
    # 聚合成两个频点（取间隔最远的两个高占用峰）
    cand = sorted(peaks.tolist(), key=lambda i: -occ[i])[:12]
    cand.sort()
    if len(cand) < 2:
        return
    f0_i, f1_i = cand[0], cand[-1]
    if abs(fb[f1_i] - fb[f0_i]) < 80:
        return
    e0 = Sb[:, max(0, f0_i - 2):f0_i + 3].max(axis=1)
    e1 = Sb[:, max(0, f1_i - 2):f1_i + 3].max(axis=1)
    raw_bits = (e1 > e0).astype(np.uint8)
    # 以最短游程作为 1 位时长，重采样
    rl = []
    cur, cnt = raw_bits[0], 1
    for b in raw_bits[1:]:
        if b == cur:
            cnt += 1
        else:
            rl.append(cnt); cur, cnt = b, 1
    rl.append(cnt)
    short_runs = [x for x in rl if 1 <= x <= 20]
    if not short_runs:
        return
    unit = max(1, int(np.median(short_runs)))
    bits = raw_bits[::unit]
    if len(bits) < 24:
        return
    found = False
    for inv in (False, True):
        bb = (1 - bits) if inv else bits
        for msb in (True, False):
            data = _bits_to_bytes(bb.tolist(), msb)
            score, kinds, flags = _grade(data)
            if score > 0:
                fp = os.path.join(outdir, f"audio_fsk_{'inv' if inv else 'norm'}_{'MSB' if msb else 'LSB'}.bin")
                with open(fp, "wb") as f:
                    f.write(data[:1024 * 1024])
                report.add("ok",
                           f"FSK 双音二进制（{fb[f0_i]:.0f}/{fb[f1_i]:.0f}Hz）[{', '.join(kinds)}]",
                           f"预览: {data[:120]!r}\n已保存: {fp}")
                for fl in flags:
                    report.add("flag", "FSK 音频数据中发现 flag", fl)
                found = True
    if not found:
        report.add("info", "FSK 双音检测",
                   f"发现两个持续单音 {fb[f0_i]:.0f}/{fb[f1_i]:.0f}Hz，但未还原出可读数据")


# ----------------------------------------------------------------------------
# 派生音频（中置/侧置/反转）
# ----------------------------------------------------------------------------
def _derive_audio(xi, sr, nch, orig_path, outdir, report):
    made = []
    if nch >= 2:
        mid = ((xi[:, 0].astype(np.int32) + xi[:, 1].astype(np.int32)) // 2).astype(np.int16)
        side = np.clip(xi[:, 0].astype(np.int32) - xi[:, 1].astype(np.int32), -32768, 32767).astype(np.int16)
        made.append(("中置声道 Mid(L+R)", write_wav(os.path.join(outdir, "audio_mid.wav"), mid, sr)))
        made.append(("侧置声道 Side(L-R)", write_wav(os.path.join(outdir, "audio_side.wav"), side, sr)))
    # 反转（倒放）音频：优先 ffmpeg 对原文件 areverse（保留压缩格式听感），否则 numpy
    rev_fp = os.path.join(outdir, "audio_reversed.wav")
    ff = _ffmpeg()
    ok = False
    if ff:
        r = _run([ff, "-y", "-hide_banner", "-loglevel", "error", "-i", orig_path,
                  "-vn", "-af", "areverse", "-c:a", "pcm_s16le", rev_fp])
        ok = r is not None and r.returncode == 0 and os.path.exists(rev_fp)
    if not ok:
        write_wav(rev_fp, xi[:, 0][::-1].copy() if nch >= 1 else xi.reshape(-1)[::-1].copy(), sr)
    made.append(("反转(倒放)音频", rev_fp))
    for nm, p in made:
        report.add("tool", f"已导出{nm}（请用播放器/ffplay 试听是否藏有内容）", p)


# ----------------------------------------------------------------------------
# WAV 尾部附加数据
# ----------------------------------------------------------------------------
def _wav_tail(path, report, outdir):
    if not path.lower().endswith(".wav"):
        return
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"RIFF":
        return
    # 定位 data 块，计算其真实结束位置
    pos = 12
    data_end = None
    while pos + 8 <= len(data):
        cid = data[pos:pos + 4]
        ln = struct.unpack("<I", data[pos + 4:pos + 8])[0]
        body = pos + 8
        if cid == b"data":
            data_end = body + ln + (ln & 1)
            break
        pos = body + ln + (ln & 1)
    if data_end is None:
        return
    tail = data[data_end:]
    if len(tail.strip(b"\x00")) > 32:
        fp = os.path.join(outdir, "wav_appended_data.bin")
        with open(fp, "wb") as f:
            f.write(tail)
        report.add("warn", "WAV data 块后存在附加数据",
                   f"{len(tail)} 字节，已保存: {fp}（可能内嵌文件，将递归雕刻）", fp)
        if fp not in report.extracted:
            report.extracted.append(fp)
        for fl in scan_flags(tail[:4 * 1024 * 1024]):
            report.add("flag", "WAV 附加数据中发现 flag", fl)


# ----------------------------------------------------------------------------
# SSTV 提示
# ----------------------------------------------------------------------------
def _sstv_hint(xf, sr, report):
    mono = (xf.mean(axis=1) if xf.shape[1] > 1 else xf[:, 0])
    mono = mono / (np.abs(mono).max() or 1.0)
    n = int(0.02 * sr)
    h = int(0.01 * sr)
    nfft = max(512, 1 << (n - 1).bit_length())
    winf = np.hanning(n)
    hit1900 = 0
    for st in range(0, min(len(mono), sr * 30), h):   # 只看前 30 秒
        seg = mono[st:st + n] * winf
        if len(seg) < n:
            break
        sp = np.abs(np.fft.rfft(seg, n=nfft))
        fr = np.fft.rfftfreq(nfft, 1.0 / sr)
        i = np.argmin(np.abs(fr - 1900))
        if sp[i] > sp.mean() * 8 and sp[i] > 0.05:
            hit1900 += 1
    if hit1900 >= 8:   # ≥80ms 的 1900Hz 领头音
        report.add("warn", "疑似 SSTV 慢扫描电视信号",
                   "检测到 1900Hz SSTV 领头校准音，可能是图片传真（Robot36/Scottie/Martin 模式），"
                   "建议用 MMSSTV/Robot36 解码")
