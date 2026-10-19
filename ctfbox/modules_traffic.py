# -*- coding: utf-8 -*-
"""流量包分析：协议统计、会话、TCP 流重组、HTTP/FTP 明文、DNS/SNI、USB HID 键盘鼠标题。"""
import os
import re
import struct
from collections import defaultdict, Counter
from .common import Finding, Report, scan_flags, WORKSPACE

try:
    from scapy.all import PcapReader, PcapNgReader, TCP, UDP, IP, IPv6, Raw, DNS, DNSRR, ICMP, ARP
    from scapy.layers.tls.extensions import TLS_Ext_ServerName
except Exception:
    PcapReader = None
try:
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, EAPOL
except Exception:
    Dot11 = None

HID_KEYS = {
    0x04: "a", 0x05: "b", 0x06: "c", 0x07: "d", 0x08: "e", 0x09: "f", 0x0a: "g",
    0x0b: "h", 0x0c: "i", 0x0d: "j", 0x0e: "k", 0x0f: "l", 0x10: "m", 0x11: "n",
    0x12: "o", 0x13: "p", 0x14: "q", 0x15: "r", 0x16: "s", 0x17: "t", 0x18: "u",
    0x19: "v", 0x1a: "w", 0x1b: "x", 0x1c: "y", 0x1d: "z", 0x1e: "1", 0x1f: "2",
    0x20: "3", 0x21: "4", 0x22: "5", 0x23: "6", 0x24: "7", 0x25: "8", 0x26: "9",
    0x27: "0", 0x28: "\n", 0x2c: " ", 0x2d: "-", 0x2e: "=", 0x2f: "[", 0x30: "]",
    0x31: "\\", 0x33: ";", 0x34: "'", 0x35: "`", 0x36: ",", 0x37: ".", 0x38: "/",
    0x2a: "[BACK]", 0x2b: "\t", 0x39: "[CAPS]",
    0x4f: "→", 0x50: "←", 0x51: "↓", 0x52: "↑", 0x29: "[ESC]", 0x4c: "[DEL]",
}
MODS = {0: "LCtrl", 1: "LShift", 2: "LAlt", 3: "LGui", 4: "RCtrl", 5: "RShift", 6: "RAlt"}

def _reader(path):
    if path.lower().endswith(".pcapng"):
        return PcapNgReader(path)
    return PcapReader(path)

def analyze(path, report: Report, outdir: str):
    if PcapReader is None:
        report.add("warn", "scapy 未安装，流量分析不可用")
        return
    os.makedirs(outdir, exist_ok=True)

    # ---- 蓝牙 / BLE 分流（btsnoop HCI 日志、H4/H4_WITH_PHDR、LE_LL、nRF 272）----
    try:
        from . import modules_bluetooth
        with open(path, "rb") as _bf:
            _bh = _bf.read(16)
        if _bh[:8] == modules_bluetooth.BTSNOOP_MAGIC:
            modules_bluetooth.analyze_btsnoop(path, report, outdir)
            return
        if _bh[:4] == b"\x0a\x0d\x0d\x0a" or _bh[:4] in (
                b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1",
                b"\xa1\xb2\xc3\xd4", b"\x34\xcd\xb2\xa1"):
            _lt, _pkts = modules_bluetooth.read_capture(path)
            if _lt in modules_bluetooth.BLUETOOTH_LINKTYPES:
                modules_bluetooth.analyze(path, report, outdir, linktype=_lt)
                return
    except Exception as _e:
        report.add("info", "蓝牙分流检测跳过", str(_e)[:120])

    proto_count = Counter()
    endpoints = Counter()
    convs = Counter()
    tcp_segs = defaultdict(dict)     # 四元组 -> {seq: payload}
    http_objects = []
    ftp_creds = []
    dns_names = []
    tls_sni = []
    all_raw = bytearray()
    usb_kb = []
    usb_mouse = []
    icmp_data = defaultdict(list)      # (src,dst,type) -> [(seq, payload)]
    dns_txt = []                        # TXT 应答拼接
    dns_exfil = defaultdict(list)       # 域名后缀 -> [(序号/原文, 标签)]
    usb_mass = {"cbw": 0, "blobs": []}
    wifi_ssids = set()
    eapol_pairs = Counter()
    n = 0

    try:
        reader = _reader(path)
        linktype = getattr(reader, "linktype", 1)
        for pkt in reader:
            n += 1
            layer = pkt
            # ---- USB HID / 大容量存储 (链路层 189/220/266) ----
            if linktype in (189, 220, 266):
                _usb_collect(pkt, usb_kb, usb_mouse)
                _usb_mass_collect(pkt, usb_mass)
            try:
                if pkt.haslayer("USBpcap") or pkt.haslayer("Urb"):
                    _usb_collect(pkt, usb_kb, usb_mouse)
                    _usb_mass_collect(pkt, usb_mass)
            except Exception:
                pass

            # ---- 802.11 WiFi (105/119/127) ----
            if Dot11 is not None and linktype in (105, 119, 127):
                try:
                    if pkt.haslayer(Dot11Beacon):
                        elt = pkt[Dot11Elt]
                        while isinstance(elt, Dot11Elt):
                            if elt.ID == 0 and elt.info:
                                wifi_ssids.add(elt.info.decode("utf-8", "replace"))
                            elt = elt.payload.getlayer(Dot11Elt)
                    if pkt.haslayer(EAPOL):
                        d = pkt[Dot11]
                        pair = tuple(sorted([d.addr1, d.addr2]))
                        eapol_pairs[pair] += 1
                except Exception:
                    pass

            if IP in pkt:
                ip = pkt[IP]
                endpoints[ip.src] += 1
                endpoints[ip.dst] += 1
                if TCP in pkt:
                    t = pkt[TCP]
                    proto_count["TCP"] += 1
                    convs[(ip.src, t.sport, ip.dst, t.dport)] += 1
                    payload = bytes(t.payload)
                    if payload:
                        key = tuple(sorted([(ip.src, t.sport), (ip.dst, t.dport)]))
                        tcp_segs[key][t.seq] = payload
                        all_raw += payload
                elif UDP in pkt:
                    u = pkt[UDP]
                    proto_count["UDP"] += 1
                    payload = bytes(u.payload)
                    all_raw += payload
                    if u.dport == 53 or u.sport == 53:
                        try:
                            _dns_collect(pkt, dns_names, dns_txt, dns_exfil)
                        except Exception:
                            pass
                    if u.dport in (67, 68):
                        proto_count["DHCP"] += 1
                elif ICMP in pkt:
                    proto_count["ICMP"] += 1
                    try:
                        ic = pkt[ICMP]
                        if ic.type in (8, 0):   # echo request/reply
                            data = bytes(ic.payload)
                            if data:
                                icmp_data[(ip.src, ip.dst, ic.type)].append((ic.seq, data))
                    except Exception:
                        pass
                else:
                    proto_count[str(pkt[IP].proto)] += 1
            elif pkt.haslayer(ARP):
                proto_count["ARP"] += 1
            # TLS SNI
            try:
                if pkt.haslayer(TLS_Ext_ServerName):
                    for s in pkt[TLS_Ext_ServerName].servernames:
                        tls_sni.append(s.servername.decode())
            except Exception:
                pass
            # 粗粒度 TLS/HTTP 判定
            try:
                pl = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
            except Exception:
                pl = b""
            if pl:
                if pl[:3] in (b"GET", b"POS", b"HTT", b"PUT", b"OPT", b"HEA") or pl.startswith(b"HTTP/"):
                    proto_count["HTTP"] += 1
                if pl[:2] == b"\x16\x03":
                    proto_count["TLS"] += 1
    except Exception as e:
        report.add("warn", "pcap 读取中断", str(e))
    finally:
        try:
            reader.close()
        except Exception:
            pass

    report.add("info", "流量包概览", f"数据包数: {n}")
    report.add("info", "协议分布", ", ".join(f"{k}={v}" for k, v in proto_count.most_common()))
    top_ep = ", ".join(f"{ip}({c})" for ip, c in endpoints.most_common(15))
    report.add("info", "最活跃端点 Top15", top_ep)
    top_conv = "\n".join(f"{a}:{p1} <-> {b}:{p2}  包数={c}"
                         for (a, p1, b, p2), c in convs.most_common(15))
    report.add("info", "最活跃会话 Top15", top_conv)
    if dns_names:
        report.add("info", "DNS 查询域名", "\n".join(sorted(set(dns_names))[:100]))
    if tls_sni:
        report.add("info", "TLS SNI 域名", "\n".join(sorted(set(tls_sni))[:100]))

    # WebShell 管理工具流量取证（菜刀 / 蚁剑 / 冰蝎 / 哥斯拉，仅识别解密、不连接）
    if proto_count.get("HTTP", 0) > 0:
        try:
            from . import modules_webshell
            modules_webshell.analyze_pcap(path, report, outdir)
        except Exception as _we:
            report.add("info", "WebShell 取证跳过", str(_we)[:120])

    # TCP 流重组与解析
    streams_dir = os.path.join(outdir, "streams")
    os.makedirs(streams_dir, exist_ok=True)
    si = 0
    for key, segs in tcp_segs.items():
        data = b"".join(segs[s] for s in sorted(segs))
        if not data:
            continue
        # HTTP 请求/凭据
        for req in re.finditer(rb"(GET|POST|PUT|HEAD|OPTIONS) ([^\r\n ]+) HTTP", data):
            report.add("info", "HTTP 请求",
                       data[max(0, req.start() - 200):req.start() + 600].decode("latin-1", "replace")[:800])
        for m in re.finditer(rb"(USER|user)(?:NAME)?[ :]+([^\r\n]+)[\s\S]{0,80}?(PASS|pass)(?:WORD)?[ :]+([^\r\n]+)", data):
            pair = (m.group(2).decode("latin-1", "ignore").strip(),
                    m.group(4).decode("latin-1", "ignore").strip())
            if pair not in ftp_creds:
                ftp_creds.append(pair)
        # HTTP 对象导出
        for body in re.finditer(rb"Content-Type:\s*([^\r\n]+)[\s\S]*?\r\n\r\n([\s\S]+?)(?=HTTP/|\Z)", data):
            ctype = body.group(1).decode("latin-1", "ignore").strip()
            blob = body.group(2)
            if len(blob) > 64 and not ctype.startswith("text/html"):
                ext = ".bin"
                for k, e in (("image/png", ".png"), ("image/jpeg", ".jpg"),
                             ("image/gif", ".gif"), ("zip", ".zip"), ("octet-stream", ".bin")):
                    if k in ctype:
                        ext = e
                        break
                fp = os.path.join(streams_dir, f"http_obj_{si}{ext}")
                with open(fp, "wb") as f:
                    f.write(blob[:5_000_000])
                http_objects.append((ctype, fp))
                si += 1
        # 流落盘（文本/全部）
        if len(data) >= 16:
            fp = os.path.join(streams_dir, f"stream_{si}.bin")
            with open(fp, "wb") as f:
                f.write(data[:20_000_000])
            report.extracted.append(fp)
            si += 1
        for fl in scan_flags(data):
            report.add("flag", "TCP 流中发现 flag", fl)

    if ftp_creds:
        report.add("ok", "明文协议凭据(FTP/POP3/IMAP/Telnet 风格)",
                   "\n".join(f"用户名: {u}  密码: {p}" for u, p in ftp_creds[:20]))
    if http_objects:
        report.add("ok", f"导出 {len(http_objects)} 个 HTTP 对象",
                   "\n".join(f"{c} -> {p}" for c, p in http_objects[:30]))

    # 全包 flag
    for fl in scan_flags(bytes(all_raw)):
        report.add("flag", "流量原始载荷中发现 flag", fl)

    # ICMP 载荷拼接（ping 带外）
    for (src, dst, t), segs in icmp_data.items():
        blob = b"".join(d for _, d in sorted(segs))
        if len(blob) >= 8:
            fp = os.path.join(outdir, f"icmp_{src.replace('.','_')}_{t}.bin")
            with open(fp, "wb") as f:
                f.write(blob)
            report.extracted.append(fp)
            report.add("info", f"ICMP 载荷拼接 {src}->{dst} (type={t},{len(segs)}包)", fp, fp)
            for fl in scan_flags(blob):
                report.add("flag", "ICMP 载荷中发现 flag", fl)

    # DNS TXT / 子域带外重建
    if dns_txt:
        joined = "".join(dns_txt)
        report.add("ok", f"DNS TXT 记录拼接（{len(dns_txt)} 段）", joined[:2000])
        for fl in scan_flags(joined.encode("utf-8", "replace")):
            report.add("flag", "DNS TXT 中发现 flag", fl)
        fp = os.path.join(outdir, "dns_txt_data.bin")
        with open(fp, "wb") as f:
            f.write(joined.encode("utf-8", "replace"))
        report.extracted.append(fp)
    for suffix, labels in dns_exfil.items():
        if len(labels) < 2:
            continue
        recovered = _dns_labels_rebuild(labels)
        if recovered:
            report.add("ok", f"DNS 子域带外数据重建（*.{suffix}，{len(labels)} 段）",
                       recovered[:2000])
            for fl in scan_flags(recovered.encode("utf-8", "replace")):
                report.add("flag", "DNS 子域数据中发现 flag", fl)

    # DNS 隧道 / dnscat2 / iodine 专项取证（独立增强模块）
    if dns_names:
        try:
            from . import modules_dns
            modules_dns.analyze_pcap(path, report, outdir)
        except Exception as _de:
            report.add("info", "DNS 隧道分析跳过", str(_de)[:120])

    # USB 大容量存储
    if usb_mass["cbw"] or usb_mass["blobs"]:
        _usb_mass_report(usb_mass, outdir, report)

    # WiFi
    if wifi_ssids:
        report.add("info", "WiFi 热点(SSID)", ", ".join(sorted(wifi_ssids)))
    for pair, cnt in eapol_pairs.items():
        if cnt >= 3:
            report.add("ok", f"检测到 WPA/WPA2 四次握手（{cnt} 个 EAPOL 帧）",
                       f"{pair[0]} <-> {pair[1]}\n"
                       "可用 hcxpcapngtool 转换为 22000 哈希后用 hashcat -m 22000 爆破")

    # USB 键盘
    if usb_kb:
        text = _hid_keyboard(usb_kb)
        report.add("ok", f"USB HID 键盘流量还原（{len(usb_kb)} 个击键包）", text[:2000])
        for fl in scan_flags(text.encode("utf-8", "ignore")):
            report.add("flag", "键盘流量中发现 flag", fl)
    # USB 鼠标
    if usb_mouse:
        fp = _mouse_draw(usb_mouse, outdir)
        if fp:
            report.add("ok", f"USB 鼠标轨迹已绘制（{len(usb_mouse)} 个移动包）", fp)
            report.extracted.append(fp)

    if not usb_kb and not usb_mouse and linktype in (189, 220, 266):
        report.add("info", "USB 流量", "未提取到标准 HID 键盘/鼠标数据")

# ----------------------------------------------------------------------------
# USB HID
# ----------------------------------------------------------------------------
def _usb_collect(pkt, kb, mouse):
    payload = b""
    # scapy USB 层
    try:
        for layer_name in ("USBpcap", "Urb"):
            if pkt.haslayer(layer_name):
                lyr = pkt[layer_name]
                # 数据可能在 load / urb.data
                payload = bytes(lyr.payload) if hasattr(lyr, "payload") else b""
                break
    except Exception:
        pass
    if not payload:
        try:
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
        except Exception:
            return
    # 启发式：取末尾 8/4 字节
    if len(payload) >= 8:
        rep = payload[-8:]
        modifier, reserved = rep[0], rep[1]
        keys = rep[2:8]
        if reserved == 0 and all(k == 0 or 0x04 <= k <= 0xe7 for k in keys):
            # 全零报告是按键释放，同样记录以清空 prev，避免连按丢键
            kb.append((modifier, keys))
            return
    if len(payload) >= 4:
        rep = payload[-4:] if len(payload) >= 5 else payload
        b = rep[0]
        try:
            dx, dy = struct.unpack("bb", rep[1:3])
            if abs(dx) <= 127 and abs(dy) <= 127 and (dx or dy or b):
                mouse.append((b & 1, dx, dy))
        except struct.error:
            pass

def _hid_keyboard(records):
    out = []
    prev = set()
    for modifier, keys in records:
        cur = set(k for k in keys if k)
        # 只处理新按下的键
        new = cur - prev
        shift = (modifier & 0x22) != 0
        caps = False
        for k in sorted(new):
            ch = HID_KEYS.get(k)
            if ch is None:
                continue
            if k == 0x39:
                caps = True
            if len(ch) == 1 and ch.isalpha():
                ch = ch.upper() if shift else ch
            elif shift and len(ch) == 1:
                shifted = {"1": "!", "2": "@", "3": "#", "4": "$", "5": "%", "6": "^",
                           "7": "&", "8": "*", "9": "(", "0": ")", "-": "_", "=": "+",
                           "[": "{", "]": "}", "\\": "|", ";": ":", "'": '"', "`": "~",
                           ",": "<", ".": ">", "/": "?"}
                ch = shifted.get(ch, ch)
            out.append(ch)
        prev = cur
    text = "".join(out)
    # 处理退格
    while "[BACK]" in text:
        text = re.sub(r".?\[BACK\]", "", text, count=1)
    return text

def _mouse_draw(records, outdir):
    try:
        from PIL import Image, ImageDraw
    except Exception:
        return None
    x = y = 400
    W = H = 800
    img = Image.new("RGB", (W, H), "white")
    d = ImageDraw.Draw(img)
    for btn, dx, dy in records:
        nx, ny = x + dx, y + dy
        color = "red" if btn else "black"
        d.line([x, y, nx, ny], fill=color, width=1)
        x, y = nx, ny
    fp = os.path.join(outdir, "usb_mouse_track.png")
    img.save(fp)
    return fp

# ----------------------------------------------------------------------------
# USB 大容量存储（Bulk-Only Transport + SCSI READ/WRITE）
# ----------------------------------------------------------------------------
CBW_SIG = b"USBC"
CSW_SIG = b"USBS"


def _usb_payload(pkt):
    payload = b""
    try:
        for layer_name in ("USBpcap", "Urb"):
            if pkt.haslayer(layer_name):
                payload = bytes(pkt[layer_name].payload)
                break
    except Exception:
        pass
    if not payload:
        try:
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
        except Exception:
            pass
    return payload


def _usb_mass_collect(pkt, mass):
    p = _usb_payload(pkt)
    if not p:
        return
    if len(p) >= 31 and p[:4] == CBW_SIG:
        mass["cbw"] += 1
        cdb = p[15:31]
        if cdb[0] in (0x28, 0x2A):      # READ(10) / WRITE(10)
            lba = struct.unpack(">I", cdb[2:6])[0]
            blocks = struct.unpack(">H", cdb[7:9])[0]
            mass.setdefault("cmds", []).append((cdb[0], lba, blocks, p[14]))
        return
    if p[:4] == CSW_SIG:
        return
    if len(p) >= 64:
        mass["blobs"].append(p)


def _usb_mass_report(mass, outdir, report):
    cmds = mass.get("cmds", [])
    blobs = mass["blobs"]
    placed = []
    qi = 0
    # 按 READ(10)（设备->主机, flag=0x80）顺序消费数据包，按 LBA 摆放
    for op, lba, blocks, flag in cmds:
        expect = blocks * 512
        if op == 0x28 and expect:
            for j in range(qi, min(qi + 4, len(blobs))):
                if len(blobs[j]) >= expect:
                    placed.append((lba, blobs[j][:expect]))
                    qi = j + 1
                    break
    if placed:
        max_end = max(l + len(b) // 512 for l, b in placed)
        img = bytearray(max_end * 512)
        for l, b in placed:
            img[l * 512:l * 512 + len(b)] = b
        fp = os.path.join(outdir, "usb_mass.img")
        with open(fp, "wb") as f:
            f.write(bytes(img))
        report.add("ok", f"USB 大容量存储：按 LBA 重组磁盘镜像（{len(placed)} 次读取）", fp, fp)
    else:
        fp = os.path.join(outdir, "usb_mass_dump.bin")
        with open(fp, "wb") as f:
            f.write(b"".join(blobs))
        report.add("info", f"USB 大容量存储：{mass['cbw']} 个 CBW，"
                           f"拼接 {len(blobs)} 个数据包", fp, fp)
    report.extracted.append(fp)
    try:
        from .modules_carve import scan_and_carve
        sub = Report(fp)
        scan_and_carve(fp, sub, outdir, carve=True, depth=1)
        for fnd in sub.findings:
            report.add(fnd.level, "[U盘雕刻] " + fnd.title, fnd.detail, fnd.data)
    except Exception as e:
        report.add("info", "U盘雕刻跳过", str(e)[:100])
    with open(fp, "rb") as f:
        for fl in scan_flags(f.read(200_000_000)):
            report.add("flag", "U盘流量中发现 flag", fl)

# ----------------------------------------------------------------------------
# DNS TXT / 子域带外
# ----------------------------------------------------------------------------
def _dns_collect(pkt, dns_names, dns_txt, dns_exfil):
    import base64  # noqa
    d = pkt[DNS]
    if d.qd:
        name = d.qd.qname.decode(errors="replace").rstrip(".")
        dns_names.append(name)
        labels = name.split(".")
        if len(labels) >= 3:
            for lab in labels[:-2]:
                if len(lab) >= 12 and re.fullmatch(r"[0-9a-zA-Z+/=_-]+", lab):
                    dns_exfil[".".join(labels[-2:])].append(lab)
    layer = d.an
    while DNSRR is not None and isinstance(layer, DNSRR):
        if getattr(layer, "type", 0) == 16:
            rd = layer.rdata
            if isinstance(rd, (bytes, bytearray)):
                dns_txt.append(rd.decode("utf-8", "replace"))
            elif isinstance(rd, str):
                dns_txt.append(rd)
        layer = layer.payload


def _printable_ratio(s):
    if not s:
        return 0
    return sum(1 for c in s if 32 <= ord(c) < 127 or ord(c) > 0x2e80) / len(s)


def _dns_labels_rebuild(labels):
    import base64
    seq, ok = [], True
    for lab in labels:
        m = re.match(r"^(\d{1,4})[._-]?(.+)$", lab)
        if m:
            seq.append((int(m.group(1)), m.group(2)))
        else:
            ok = False
            break
    body = "".join(s for _, s in sorted(seq)) if ok and seq else "".join(sorted(labels))
    cands = [("raw", body)]
    try:
        cands.append(("hex", bytes.fromhex(body).decode("utf-8", "replace")))
    except Exception:
        pass
    try:
        pad = "=" * ((8 - len(body) % 8) % 8)
        cands.append(("b32", base64.b32decode(body.upper() + pad).decode("utf-8", "replace")))
    except Exception:
        pass
    try:
        pad = "=" * ((4 - len(body) % 4) % 4)
        cands.append(("b64", base64.b64decode(body + pad).decode("utf-8", "replace")))
    except Exception:
        pass
    # 优先选择解码后直接含 flag 的候选
    for cname, val in cands:
        if re.search(r"(flag|ctf)\{", val, re.I):
            return val
    # 否则在可读性相同的情况下，优先解码后的候选（hex/b32/b64）而非原始拼接
    decoded = [c for c in cands if c[0] != "raw" and _printable_ratio(c[1]) >= 0.95]
    if decoded:
        return max(decoded, key=lambda kv: _printable_ratio(kv[1]))[1]
    name, best = max(cands, key=lambda kv: _printable_ratio(kv[1]))
    return best if _printable_ratio(best) >= 0.8 else body
