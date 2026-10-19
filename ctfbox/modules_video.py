# -*- coding: utf-8 -*-
"""视频分析（隐写向）：

- ffprobe 容器/流元数据与标签（comment/title/encoder 常藏 flag）；
- 快速 seek 均匀抽帧（不再顺序硬解整片，长视频也快）+ 场景切换帧；
- 逐帧 QR / 一维条码 / 反色二维码识别（原图、灰度、放大、反色多策略）；
- 跨采样帧 LSB 低位流提取（视频帧 LSB 隐写），自动识别 flag/文件头/可读文本；
- 相邻帧差异热图，定位单帧闪烁/局部篡改并导出；
- 抽取音轨为无损 WAV 后联动「音频隐写全套」（音轨藏字/LSB/DTMF/摩斯/FSK）；
- 字幕轨提取为 SRT 并扫描 flag；
- 关键帧落盘并登记，递归进入图片隐写分析。
"""
import os
import json
import shutil
import subprocess

import numpy as np

from .common import Report, scan_flags, WORKSPACE, safe_name

MAX_SAMPLE = 48          # 均匀采样帧数上限
MAX_RECURSE_FRAMES = 18  # 登记递归图片分析的帧数上限
LSB_W, LSB_H = 128, 72   # 逐帧 LSB 下采样尺寸


def _ffmpeg():
    from . import toolsmgr
    exe = toolsmgr.get_tool("ffmpeg")
    if exe:
        return exe
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
    return shutil.which("ffprobe") or shutil.which("ffprobe.exe")


def _run(cmd, timeout=300):
    try:
        return subprocess.run(cmd, capture_output=True, timeout=timeout)
    except Exception:
        return None


def analyze(path, report: Report, outdir: str = None):
    base = safe_name(os.path.splitext(os.path.basename(path))[0])
    outdir = outdir or os.path.join(WORKSPACE, "video_" + base)
    framedir = os.path.join(outdir, "frames")
    os.makedirs(framedir, exist_ok=True)

    # ---------- ffprobe 元数据 / 标签 / 字幕轨 ----------
    meta = _ffprobe_meta(path, report)

    has_cv2 = True
    try:
        import cv2
    except Exception:
        has_cv2 = False
        report.add("warn", "OpenCV 未安装", "跳过帧分析；元数据/音轨/字幕仍可分析，建议安装 opencv")

    frames, fps, w, h = 0, 25.0, 0, 0
    cap = None
    if has_cv2:
        cap = cv2.VideoCapture(path)
        if cap.isOpened():
            frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT)) or 0
            fps = cap.get(cv2.CAP_PROP_FPS) or 0
            if not fps or fps <= 0 or fps > 240:
                fps = 25.0
            w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        else:
            report.add("warn", "视频无法打开", "cv2 缺少解码器，可在工具中心预置 FFmpeg")
    # ffprobe 兜底修正帧数/帧率
    if meta:
        for st in meta.get("streams", []):
            if st.get("codec_type") == "video":
                try:
                    rf = st.get("r_frame_rate", "0/1")
                    a, _, b = rf.partition("/")
                    cand_fps = float(a) / float(b or 1)
                    if 0 < cand_fps <= 240:
                        fps = cand_fps
                except Exception:
                    pass
                nb = st.get("nb_frames")
                if (not frames) and nb and str(nb).isdigit():
                    frames = int(nb)
                w = w or int(st.get("width") or 0)
                h = h or int(st.get("height") or 0)
    dur = frames / fps if frames else float(meta.get("format", {}).get("duration") or 0)
    report.add("info", "视频信息",
               f"分辨率 {w}x{h}  帧数 {frames}  FPS {fps:.2f}  时长 {dur:.1f}s")

    qr_hits, saved = [], []

    # ---------- 抽帧分析 ----------
    if cap is not None and cap.isOpened():
        det = cv2.QRCodeDetector()
        try:
            bardet = cv2.barcode.BarcodeDetector()
        except Exception:
            bardet = None

        if frames > 0:
            step = max(1, frames // MAX_SAMPLE)
            sample_idx = list(range(0, frames, step))[:MAX_SAMPLE]
        else:
            sample_idx = list(range(0, MAX_SAMPLE * 100, 100))[:MAX_SAMPLE]

        small_gray, small_rgb, prev_small = [], [], None
        diffs, diff_pairs = [], []
        for n, idx in enumerate(sample_idx):
            cap.set(cv2.CAP_PROP_POS_FRAMES, idx)
            ok, frame = cap.read()
            if not ok:
                continue
            _probe_codes(cv2, det, bardet, frame, idx, qr_hits, report)
            gh, gw = frame.shape[:2]
            small = cv2.cvtColor(cv2.resize(frame, (LSB_W, LSB_H)), cv2.COLOR_BGR2GRAY)
            small_gray.append(small)
            small_rgb.append(cv2.resize(frame, (LSB_W, LSB_H)))
            if prev_small is not None:
                d = float(np.mean(cv2.absdiff(small, prev_small)))
                diffs.append(d)
                diff_pairs.append((d, n, idx, frame))
            prev_small = small
            # 均匀登记若干帧供递归图片分析
            if n % max(1, len(sample_idx) // 10) == 0 and len(saved) < MAX_RECURSE_FRAMES:
                fp = os.path.join(framedir, f"frame_{idx:06d}.png")
                cv2.imwrite(fp, frame)
                saved.append(fp)

        # 场景切换 / 单帧异常：差异最大的位置
        if diff_pairs:
            for d, n, idx, frame in sorted(diff_pairs, key=lambda x: -x[0])[:3]:
                if d > 40 and len(saved) < MAX_RECURSE_FRAMES:
                    fp = os.path.join(framedir, f"scene_{idx:06d}.png")
                    cv2.imwrite(fp, frame)
                    saved.append(fp)
            d, n, idx, frame = max(diff_pairs, key=lambda x: x[0])
            if d > 40:
                _diff_heatmap(cv2, small_rgb, n, idx, outdir, report, d)
        cap.release()

        # 跨帧 LSB 隐写
        if small_rgb:
            _frame_lsb(np.array(small_rgb), report, outdir)

    for txt in qr_hits:
        for fl in scan_flags(txt.encode()):
            report.add("flag", "视频帧条码中发现 flag", fl)

    if saved:
        report.add("ok", f"已导出 {len(saved)} 张采样/场景关键帧",
                   framedir + "（将递归做图片隐写分析）")
        report.extracted.extend(saved[:MAX_RECURSE_FRAMES])

    # ---------- 音轨 → 音频隐写全套 ----------
    _extract_audio_and_analyze(path, outdir, report)

    # ---------- 字幕轨 ----------
    _extract_subtitles(path, outdir, report, meta)

    report.add("info", "视频抽帧", f"采样 {len(saved)} 帧" +
               (f"，估算总帧 {frames}" if frames else ""))


# ----------------------------------------------------------------------------
def _probe_codes(cv2, det, bardet, frame, idx, qr_hits, report):
    variants = [("原图", frame)]
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    variants.append(("灰度", gray))
    variants.append(("反色", 255 - gray))
    gh, gw = gray.shape[:2]
    if gh * gw <= 900_000:
        big = cv2.resize(gray, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
        variants.append(("放大2x", big))
        variants.append(("放大反色", 255 - big))
    for tag, im in variants:
        try:
            txt, _, _ = det.detectAndDecode(im)
            if txt and txt not in qr_hits:
                qr_hits.append(txt)
                report.add("ok", f"第 {idx} 帧二维码({tag})", txt)
        except Exception:
            pass
    if bardet is not None:
        try:
            ok, decoded, dtype, _ = bardet.detectAndDecode(frame)
            if ok:
                for dval, dt in zip(decoded, dtype):
                    if dval and dval not in qr_hits:
                        qr_hits.append(dval)
                        report.add("ok", f"第 {idx} 帧一维条码({dt})", dval)
        except Exception:
            pass


def _frame_lsb(rgb_arr, report, outdir):
    """rgb_arr: [T,H,W,3] 采样帧。拼接各通道 bit0 流并尝试识别隐藏数据。"""
    from .modules_audio import _grade, _bits_to_bytes
    found = 0
    planes = {
        "Gray": ((rgb_arr.mean(axis=3)).astype(np.uint8).reshape(-1)),
        "B": rgb_arr[:, :, :, 0].reshape(-1),
        "G": rgb_arr[:, :, :, 1].reshape(-1),
        "R": rgb_arr[:, :, :, 2].reshape(-1),
        "RGB交错": rgb_arr.reshape(-1),
    }
    for name, vals in planes.items():
        bits = (vals.astype(np.int32) & 1)
        # 按“帧内连续”与“逐帧同位置”两种顺序，后者更贴合逐帧写 1bit 的套路
        for order_name, bb in (("帧内", bits), ):
            for msb in (True, False):
                data = _bits_to_bytes(bb, msb)
                score, kinds, flags = _grade(data)
                if score <= 0:
                    continue
                fp = os.path.join(outdir, f"video_lsb_{safe_name(name)}_{'MSB' if msb else 'LSB'}.bin")
                with open(fp, "wb") as f:
                    f.write(data[:2 * 1024 * 1024])
                report.add("ok", f"视频帧 LSB 提取({name}/{order_name}/{'MSB' if msb else 'LSB'})"
                                 f" [{', '.join(kinds)}]",
                           f"预览: {data[:140]!r}\n已保存: {fp}")
                for fl in flags:
                    report.add("flag", "视频帧 LSB 中发现 flag", fl)
                found += 1
    # 逐帧同位置 bit：每帧每个通道取 1bit 组成慢速信道
    try:
        per = []
        for t in range(rgb_arr.shape[0]):
            gray = (rgb_arr[t].mean(axis=2)).astype(np.uint8)
            per.append(int(gray[LSB_H // 2, LSB_W // 2] & 1))
        if len(per) >= 32:
            for msb in (True, False):
                data = _bits_to_bytes(per, msb)
                score, kinds, flags = _grade(data)
                if score > 0:
                    fp = os.path.join(outdir, f"video_centerbit_{'MSB' if msb else 'LSB'}.bin")
                    with open(fp, "wb") as f:
                        f.write(data)
                    report.add("ok", f"逐帧中心像素 bit 信道 [{', '.join(kinds)}]", repr(data[:80]))
                    for fl in flags:
                        report.add("flag", "逐帧 bit 信道中发现 flag", fl)
                    found += 1
    except Exception:
        pass
    if not found:
        report.add("info", "视频帧 LSB", "采样帧低位流未发现可读数据")


def _diff_heatmap(cv2, small_rgb, n, idx, outdir, report, score):
    try:
        a = cv2.cvtColor(small_rgb[n - 1], cv2.COLOR_BGR2GRAY).astype(np.int16)
        b = cv2.cvtColor(small_rgb[n], cv2.COLOR_BGR2GRAY).astype(np.int16)
        diff = np.abs(a - b).astype(np.uint8)
        heat = cv2.applyColorMap((diff * 4).clip(0, 255).astype(np.uint8), cv2.COLORMAP_JET)
        fp = os.path.join(outdir, f"diff_heatmap_{idx:06d}.png")
        cv2.imwrite(fp, heat)
        report.add("warn", f"第 {idx} 帧与上一采样帧差异显著(均值 {score:.1f})",
                   "可能存在单帧闪烁/局部篡改，差异热图: " + fp)
    except Exception:
        pass


def _ffprobe_meta(path, report):
    fp = _ffprobe()
    if not fp:
        return None
    r = _run([fp, "-v", "quiet", "-print_format", "json", "-show_format", "-show_streams", path])
    if r is None or r.returncode != 0 or not r.stdout:
        return None
    try:
        data = json.loads(r.stdout.decode("utf-8", "replace"))
    except Exception:
        return None
    lines, blob = [], []
    for k, v in (data.get("format", {}).get("tags") or {}).items():
        lines.append(f"FORMAT {k} = {v}"); blob.append(str(v))
    for i, st in enumerate(data.get("streams", [])):
        for k, v in (st.get("tags") or {}).items():
            lines.append(f"STREAM{i} {st.get('codec_type')} {k} = {v}"); blob.append(str(v))
    if lines:
        report.add("ok", "ffprobe 容器/流元数据标签", "\n".join(lines[:50])[:2500])
        for fl in scan_flags("\n".join(blob).encode("utf-8", "ignore")):
            report.add("flag", "视频元数据标签中发现 flag", fl)
    return data


def _extract_audio_and_analyze(path, outdir, report):
    ff = _ffmpeg()
    if not ff:
        report.add("info", "音轨提取", "未找到 ffmpeg，跳过音轨隐写分析")
        return
    audir = os.path.join(outdir, "audio_track")
    os.makedirs(audir, exist_ok=True)
    wav = os.path.join(audir, "track_pcm.wav")
    r = _run([ff, "-y", "-hide_banner", "-loglevel", "error", "-i", path,
              "-vn", "-c:a", "pcm_s16le", wav])
    if r is None or r.returncode != 0 or not os.path.exists(wav) or os.path.getsize(wav) < 64:
        return
    report.add("info", "已抽取视频音轨", wav + "（联动音频隐写全套分析）")
    try:
        from . import modules_audio
        sub = Report(path=wav)
        modules_audio.analyze(wav, sub, audir)
        for fnd in sub.findings:
            report.add(fnd.level, "[音轨] " + fnd.title, fnd.detail, fnd.data)
        report.extracted.extend(p for p in sub.extracted if p not in report.extracted)
    except Exception as e:
        report.add("info", "音轨隐写分析跳过", str(e)[:120])


def _extract_subtitles(path, outdir, report, meta):
    ff = _ffmpeg()
    if not ff or not meta:
        return
    sub_streams = [i for i, st in enumerate(meta.get("streams", []))
                   if st.get("codec_type") == "subtitle"]
    if not sub_streams:
        return
    subdir = os.path.join(outdir, "subtitles")
    os.makedirs(subdir, exist_ok=True)
    texts = []
    for k, si in enumerate(sub_streams[:5]):
        out = os.path.join(subdir, f"sub_{k}.srt")
        r = _run([ff, "-y", "-hide_banner", "-loglevel", "error", "-i", path,
                  "-map", f"0:s:{k}?", "-f", "srt", out])
        if r is not None and r.returncode == 0 and os.path.exists(out) and os.path.getsize(out) > 0:
            try:
                t = open(out, encoding="utf-8", errors="replace").read()
                texts.append(t)
            except Exception:
                pass
    if texts:
        joined = "\n".join(texts)
        report.add("ok", f"提取到 {len(sub_streams)} 条字幕轨", joined[:2000])
        for fl in scan_flags(joined.encode("utf-8", "ignore")):
            report.add("flag", "视频字幕中发现 flag", fl)
