# -*- coding: utf-8 -*-
"""蓝牙 / BLE 流量取证分析（CTF 向，纯离线解析）。

支持输入：
  1. Android btsnoop_hci.log（magic "btsnoop\\0"，datalink 1002 = HCI UART H4）；
  2. 经典 pcap / pcapng，链路层：
       187 = BLUETOOTH_HCI_H4（裸 H4）
       251 = BLUETOOTH_HCI_H4_WITH_PHDR（4 字节方向伪头）
       250 = BLUETOOTH_LE_LL（裸 BLE 链路层）
       272 = BLUETOOTH_LE_LL_WITH_PHDR（nRF Sniffer，伪头后按 Access Address 定位）

输出（写入 Report）：
  - 控制器/本机 BDADDR（Read BD_ADDR Complete、Enhanced Connection Complete）；
  - 广播与连接中出现的设备地址、广播名/服务/厂商数据；
  - HCI ACL / LE LL 分片重组 -> L2CAP -> ATT 全流水（read/write/notify/indicate 的 handle 与 value）；
  - GATT 特征声明还原（handle -> 特征 UUID / 属性）；
  - SMP 配对密钥（TK/LTK/IRK/CSRK/Passkey）；
  - 经典蓝牙 RFCOMM/SPP 串口明文；
  - 全部 value 的 ASCII/UTF-8 解码与 flag 扫描，并对 MAC / write value 给出 MD5 候选。
"""
import os
import re
import struct
import hashlib
from collections import defaultdict, Counter

from .common import Report, save_artifact, scan_flags, safe_name

ADV_AA = bytes.fromhex("d6be898e")          # 广播通道 Access Address（线上小端序）
HCI_EVT_CMD_COMPLETE = 0x0E
HCI_EVT_DISCONNECT = 0x05
HCI_EVT_LE_META = 0x3E
LE_CONN_COMPLETE = 0x01
LE_ADV_REPORT = 0x02
LE_ENH_CONN_COMPLETE = 0x0A
LE_EXT_ADV_REPORT = 0x0D
OCF_READ_BDADDR = 0x1009

ATT_NAMES = {
    0x02: "MTU Request", 0x03: "MTU Response",
    0x04: "Find Information Req", 0x05: "Find Information Rsp",
    0x08: "Read Req", 0x09: "Read Rsp",
    0x0A: "Read Blob Req", 0x0B: "Read Blob Rsp",
    0x0C: "Read By Type Req", 0x0D: "Read By Type Rsp",
    0x10: "Read By Group Type Req", 0x11: "Read By Group Type Rsp",
    0x12: "Write Req", 0x13: "Write Rsp",
    0x16: "Prepare Write Req", 0x17: "Prepare Write Rsp",
    0x18: "Execute Write Req", 0x19: "Execute Write Rsp",
    0x1B: "Handle Value Notification", 0x1D: "Handle Value Indication",
    0x1E: "Confirmation", 0x52: "Write Cmd(Without Response)",
    0xD2: "Signed Write Cmd",
}
# 携带“句柄 + value”的 ATT 方法
ATT_HANDLE_VALUE = {0x12, 0x52, 0xD2, 0x1B, 0x1D, 0x16}
ATT_READ_RSP = {0x09, 0x0B}
AD_TYPE_NAMES = {
    0x01: "Flags", 0x02: "16bit UUID(partial)", 0x03: "16bit UUID(complete)",
    0x07: "128bit UUID(complete)", 0x08: "Shortened Local Name",
    0x09: "Complete Local Name", 0x0A: "TX Power", 0x16: "Service Data(16bit UUID)",
    0x19: "Appearance", 0x1F: "List of 32bit Service UUIDs",
    0xFF: "Manufacturer Specific Data",
}


def _md5(b: bytes) -> str:
    if isinstance(b, str):
        b = b.encode("utf-8", "replace")
    return hashlib.md5(b).hexdigest()


def _mac_rev(raw: bytes) -> str:
    """BLE/BR 地址线上为小端，转成标准 XX:XX:XX:XX:XX:XX。"""
    return ":".join("%02X" % b for b in raw[::-1])


def _ascii(b: bytes) -> str:
    return "".join(chr(x) if 32 <= x < 127 else "." for x in b)


def _decode_value(b: bytes):
    """返回 (可读文本, 候选字符串列表)。"""
    cands = []
    txt = None
    for enc in ("utf-8", "gbk"):
        try:
            t = b.decode(enc)
            if sum(c.isprintable() or c in "\r\n\t" for c in t) / max(1, len(t)) > 0.9:
                txt = t
                break
        except Exception:
            pass
    if txt is None:
        txt = _ascii(b)
    if txt and any(c.isalnum() for c in txt):
        cands.append(txt.strip())
    return txt, cands


# ============================================================================
# pcap / pcapng 极简读取器（只取 linktype 与原始包字节，不依赖 scapy 蓝牙层）
# ============================================================================
def read_capture(path):
    """返回 (linktype, [(pkt_bytes, direction_hint), ...])。direction: 0=未知,1=发,2=收。"""
    with open(path, "rb") as f:
        head = f.read(16)
    if head[:4] == b"\x0a\x0d\x0d\x0a":
        return _read_pcapng(path)
    if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1",
                    b"\xa1\xb2\xc3\xd4", b"\x34\xcd\xb2\xa1"):
        return _read_pcap(path)
    return None, []


def _read_pcap(path):
    data = open(path, "rb").read()
    bom = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    linktype = struct.unpack(bom + "I", data[20:24])[0] & 0xffff
    pkts = []
    off = 24
    while off + 16 <= len(data):
        _, _, caplen, _ = struct.unpack(bom + "IIII", data[off:off + 16])
        off += 16
        if caplen > 4096 or off + caplen > len(data):
            break
        pkts.append((data[off:off + caplen], 0))
        off += caplen
        if data[off:off + 2] == b"\x00\x00":   # 对齐填充
            pad = (4 - caplen % 4) % 4
            off += pad
    return linktype, pkts


def _read_pcapng(path):
    data = open(path, "rb").read()
    bom = "<" if data[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
    linktype = 1
    if_tsresol = 1_000_000
    pkts = []
    off = 0
    while off + 12 <= len(data):
        bt, bl = struct.unpack(bom + "II", data[off:off + 8])
        if bl < 12 or off + bl > len(data):
            break
        body = data[off + 8:off + bl - 4]
        if bt == 1:   # IDB
            linktype = struct.unpack(bom + "H", body[0:2])[0]
            # 选项里找 if_tsresol(9)
            o = 8
            while o + 4 <= len(body):
                code, ln = struct.unpack(bom + "HH", body[o:o + 4])
                val = body[o + 4:o + 4 + ln]
                if code == 9 and val:
                    v = val[0]
                    if_tsresol = 10 ** (v & 0x7f) if not (v & 0x80) else 2 ** (v & 0x7f)
                o += 4 + ((ln + 3) & ~3)
        elif bt in (6, 3):   # EPB / 旧 SPB
            ifid = struct.unpack(bom + "I", body[0:4])[0]
            caplen = struct.unpack(bom + "I", body[12:16])[0]
            pkt = body[20:20 + caplen]
            pkts.append((pkt, 0))
        off += bl
    return linktype, pkts


# ============================================================================
# btsnoop HCI log
# ============================================================================
BTSNOOP_MAGIC = b"btsnoop\x00"


def read_btsnoop(path):
    """返回 [(direction, h4_bytes)]，direction: 1=host->controller(发), 2=controller->host(收)。"""
    data = open(path, "rb").read()
    if data[:8] != BTSNOOP_MAGIC:
        return []
    out = []
    off = 16
    while off + 24 <= len(data):
        orig_len, inc_len, flags, _drops, _ts = struct.unpack(">IIIIQ", data[off:off + 24])
        off += 24
        if inc_len == 0 or inc_len > 4096 or off + inc_len > len(data):
            break
        rec = data[off:off + inc_len]
        off += inc_len
        d = flags & 0x01
        direction = 1 if d == 0 else 2      # 0 sent(host->ctrl), 1 recv(ctrl->host)
        out.append((direction, rec))
    return out


# ============================================================================
# HCI（H4：首字节 1=cmd 2=ACL 4=event）解析，喂给公共重组器
# ============================================================================
class BtAssembler:
    def __init__(self, report: Report, outdir: str):
        self.rep = report
        self.outdir = outdir
        self.local_addr = None
        self.addrs = {}                 # mac -> 线索集合
        self.adv_data = []              # (mac, name, uuid[], mfr)
        self.le_aa = None               # 数据通道 AA
        # HCI ACL 重组：(handle, direction) -> bytearray
        self.acl_buf = {}
        # LE LL 数据 PDU 重组：direction -> bytearray（272/250 链路层抓取）
        self.ll_buf = {}
        self.gatt = {}                  # value handle -> (uuid, props)
        self.att_rows = []              # (方向, 方法名, handle, value bytes)
        self.smp = []
        self.rfcomm = bytearray()
        self.rfcomm_streams = {}        # (方向, DLCI) -> bytearray（SPP 串口流）
        self.rfcomm_frames = []         # (方向, DLCI, data) 每个 UIH 数据帧
        self.rfcomm_raw = {}            # (方向, CID) -> bytearray（未拆帧的 RFCOMM 字节流）
        self._adv_seen = set()
        self._flag_seen = set()
        self.n_acl = self.n_att = self.n_smp = 0
        self.conn = {}                  # handle -> dict(role, peer, local)

    def log(self, lvl, title, detail="", data=None):
        self.rep.add(lvl, title, detail, data)

    # ---- HCI 命令 / 事件 ----
    def feed_h4(self, direction, h4):
        if not h4:
            return
        t = h4[0]
        pl = h4[1:]
        if t == 0x01:
            self._hci_command(pl)
        elif t == 0x04:
            self._hci_event(pl)
        elif t == 0x02:
            self.n_acl += 1
            self._hci_acl(direction, pl)

    def _note_addr(self, mac, note):
        if not mac or mac == "00:00:00:00:00:00":
            return
        s = self.addrs.setdefault(mac, set())
        if note not in s:
            s.add(note)

    def _parse_adv_payload(self, adva, payload):
        name, uuids, mfr = "", [], b""
        off = 0
        while off + 2 <= len(payload):
            ln = payload[off]
            if ln == 0 or off + 1 + ln > len(payload):
                break
            typ = payload[off + 1]
            val = payload[off + 2:off + 1 + ln]
            if typ in (0x08, 0x09):
                name = val.decode("utf-8", "replace").strip()
            elif typ in (0x02, 0x03):
                uuids += ["%04x" % struct.unpack("<H", val[i:i + 2])[0]
                          for i in range(0, len(val) - 1, 2)]
            elif typ == 0xFF:
                mfr = val
            off += 1 + ln
        if adva:
            self._note_addr(adva, "广播设备")
        self.adv_data.append((adva, name, uuids, mfr))
        # 同一 (地址, 广播名, 厂商数据) 只报告一次，避免广播包刷屏
        dedup_key = (adva, name, mfr[:24])
        if name and dedup_key not in self._adv_seen:
            self._adv_seen.add(dedup_key)
            self.log("ok", f"BLE 广播设备 {adva}", f"广播名: {name}" +
                     (f"  服务: {','.join(sorted(set(uuids)))}" if uuids else ""))
        for fl in scan_flags(name.encode("utf-8", "replace") + b" " + mfr):
            if fl not in self._flag_seen:
                self._flag_seen.add(fl)
                self.log("flag", "广播数据中发现 flag", fl)
        if mfr and any(32 <= c < 127 for c in mfr):
            for fl in scan_flags(mfr):
                if fl not in self._flag_seen:
                    self._flag_seen.add(fl)
                    self.log("flag", "广播厂商数据中发现 flag", fl)

    def _hci_command(self, pl):
        if len(pl) < 3:
            return
        opcode = struct.unpack("<H", pl[0:2])[0]
        plen = pl[2]
        params = pl[3:3 + plen]
        if opcode == 0x200b and len(params) >= 32:        # LE Set Advertising Data
            self._parse_adv_payload(None, params[1:32])
        elif opcode == 0x200e and len(params) >= 32:      # LE Set Scan Response Data
            self._parse_adv_payload(None, params[1:32])

    def _hci_event(self, pl):
        if not pl:
            return
        code = pl[0]
        tot = pl[1] if len(pl) > 1 else 0
        p = pl[2:2 + tot]
        if code == HCI_EVT_CMD_COMPLETE and len(p) >= 4:
            opcode = struct.unpack("<H", p[1:3])[0]
            status = p[3]
            ret = p[4:]
            if opcode == OCF_READ_BDADDR and status == 0 and len(ret) >= 6:
                self.local_addr = _mac_rev(ret[:6])
                self._note_addr(self.local_addr, "本机控制器(Read BD_ADDR)")
                self.log("ok", "蓝牙控制器地址(BD_ADDR)", self.local_addr +
                         f"\nMD5({self.local_addr})={_md5(self.local_addr)}\n"
                         f"MD5(小写)={_md5(self.local_addr.lower())}")
        elif code == 0x03 and len(p) >= 7:                # Connection Complete(BR/EDR)
            if p[0] == 0:
                mac = _mac_rev(p[3:9])
                self._note_addr(mac, "经典蓝牙连接对端")
                self.log("info", "经典蓝牙连接", f"对端地址: {mac}")
        elif code == HCI_EVT_LE_META and p:
            self._le_meta(p)

    def _le_meta(self, p):
        sub = p[0]
        d = p[1:]
        try:
            if sub == LE_CONN_COMPLETE and len(d) >= 18 and d[0] == 0:
                handle = struct.unpack("<H", d[1:3])[0]
                role = d[3]
                peer = _mac_rev(d[5:11])
                self.conn[handle] = {"role": role, "peer": peer}
                self._note_addr(peer, "BLE连接对端")
                self.log("info", "BLE 连接完成",
                         f"handle=0x{handle:04x} 角色={'主(Master)' if role==0 else '从(Slave)'} 对端={peer}")
            elif sub == LE_ENH_CONN_COMPLETE and len(d) >= 24 and d[0] == 0:
                handle = struct.unpack("<H", d[1:3])[0]
                role = d[3]
                peer = _mac_rev(d[5:11])
                local = _mac_rev(d[11:17])
                self.conn[handle] = {"role": role, "peer": peer, "local": local}
                self._note_addr(peer, "BLE连接对端")
                self._note_addr(local, "本机地址(Enhanced)")
                if not self.local_addr:
                    self.local_addr = local
                self.log("info", "BLE 增强连接完成", f"对端={peer} 本机={local}")
            elif sub == LE_ADV_REPORT and len(d) >= 2:
                num = d[0]
                off = 1
                for _ in range(num):
                    if off + 9 > len(d):
                        break
                    _et, at = d[off], d[off + 1]
                    mac = _mac_rev(d[off + 2:off + 8])
                    ln = d[off + 8]
                    data = d[off + 9:off + 9 + ln]
                    self._parse_adv_payload(mac, data)
                    off += 9 + ln + 1   # +RSSI
            elif sub == LE_EXT_ADV_REPORT and len(d) >= 2:
                # LE Extended Advertising Report(v2)：每条报告固定 24 字节头 + data
                num = d[0]
                off = 1
                for _ in range(num):
                    if off + 24 > len(d):
                        break
                    mac = _mac_rev(d[off + 3:off + 9])
                    dlen = d[off + 23]
                    data = d[off + 24:off + 24 + dlen]
                    if len(data) < dlen:
                        break
                    self._parse_adv_payload(mac, data)
                    off += 24 + dlen
        except Exception:
            pass

    # ---- HCI ACL（btsnoop / H4）----
    def _hci_acl(self, direction, pl):
        if len(pl) < 4:
            return
        h = struct.unpack("<H", pl[0:2])[0]
        dlen = struct.unpack("<H", pl[2:4])[0]
        handle = h & 0x0fff
        pb = (h >> 12) & 0x3
        body = pl[4:4 + dlen]
        key = (handle, direction)
        # PB 标志：经典蓝牙 0=首包/1=续包；LE-U 2=首包/3=续包
        if pb in (0, 2):          # 首个/完整 L2CAP
            self.acl_buf[key] = bytearray(body)
        elif pb in (1, 3):        # 后续分片
            self.acl_buf.setdefault(key, bytearray()).extend(body)
        else:
            return
        # 经典 ACL(handle 上的 L2CAP 固定 CID 1-6 与动态 CID) 与 LE-U 都按 length 切帧
        self._try_l2cap(key, self.acl_buf[key], direction, le=(pb in (2, 3)))

    def _try_l2cap(self, key, buf, direction, le=True):
        """L2CAP：前 4 字节 length+CID，收满即解析。经典蓝牙 le=False。"""
        while len(buf) >= 4:
            length, cid = struct.unpack("<HH", bytes(buf[:4]))
            # L2CAP length 字段不含 4 字节头，整帧总长 = length + 4
            if length < 1 or length > 2000:
                return
            total = length + 4
            if len(buf) < total:
                return
            l2 = bytes(buf[4:total])
            del buf[:total]
            self._l2cap(cid, l2, direction, le)

    # ---- LE LL（链路层直抓 272/250）----
    def feed_ll(self, direction, aa, pdu, crc_len=3):
        """pdu = header(2)+payload（已去掉 AA，调用方负责去伪头/CRC）。"""
        if len(pdu) < 2:
            return
        hdr, length = pdu[0], pdu[1]
        ptype = hdr & 0x0f
        payload = pdu[2:2 + length]
        if aa == ADV_AA:
            self._ll_adv(ptype, payload)
        else:
            llid = hdr & 0x03
            if llid == 3:           # LL Control PDU
                return
            if llid == 2:           # 起始 L2CAP
                self.ll_buf[direction] = bytearray(payload)
            elif llid == 1:         # 续片
                self.ll_buf.setdefault(direction, bytearray()).extend(payload)
            else:
                return
            buf = self.ll_buf[direction]
            self._try_l2cap(("LE", direction), buf, direction, le=True)

    def _ll_adv(self, ptype, payload):
        try:
            if ptype in (0, 2, 6):            # ADV_IND / NONCONN / SCAN_IND
                adva = _mac_rev(payload[:6])
                self._parse_adv_payload(adva, payload[6:])
            elif ptype == 4:                  # SCAN_RSP
                adva = _mac_rev(payload[:6])
                self._parse_adv_payload(adva, payload[6:])
            elif ptype == 5 and len(payload) >= 34:   # CONNECT_IND
                inita = _mac_rev(payload[:6])
                adva = _mac_rev(payload[6:12])
                lldata = payload[12:34]
                self.le_aa = lldata[0:4]
                self._note_addr(inita, "连接发起方(Master)")
                self._note_addr(adva, "广播从设备(Slave)")
                self.log("info", "CONNECT_IND 连接请求",
                         f"发起方={inita}  目标={adva}\n数据通道AA="
                         + self.le_aa.hex() + "（后续数据包按此 AA 归属）")
        except Exception:
            pass

    # ---- L2CAP 分发 ----
    def _l2cap(self, cid, payload, direction, le):
        if cid == 0x0004:
            self._att(payload, direction)
        elif cid == 0x0006:
            self._smp(payload, direction)
        elif cid == 0x0005:
            pass    # L2CAP signaling
        elif cid >= 0x0040:
            # 动态 CID(0x40+)：经典蓝牙多为 RFCOMM/AVDTP/AVCTP，LE 为 CoC；
            # 统一喂给 RFCOMM 拆帧器，靠建链帧头(SABM/UA)自行甄别，非 RFCOMM 会被丢弃。
            self._rfcomm_feed(cid, payload, direction)

    # ---- RFCOMM / SPP（经典蓝牙串口，按 TS 07.10 解帧）----
    _RFCOMM_UIH = {0xEF, 0xFF}
    _RFCOMM_NODATA = {0x2F, 0x3F, 0x63, 0x73, 0x0F, 0x1F, 0x43, 0x53}

    def _rfcomm_feed(self, cid, payload, direction):
        """同一 (方向,CID) 的 L2CAP 段拼成连续 RFCOMM 字节流，finish 时统一拆帧。"""
        key = (direction, cid)
        if key not in self.rfcomm_raw:
            self.rfcomm_raw[key] = bytearray()
        self.rfcomm_raw[key] += payload

    @staticmethod
    def _rfcomm_valid_addr(b):
        """单字节 RFCOMM 地址：EA=1（最低位为 1）。"""
        return b & 0x01

    def _parse_rfcomm_stream(self, direction, cid, raw):
        """对一条连续 RFCOMM 流拆帧，产出 (dlci, data) UIH 数据帧；自适应 credit 字节。"""
        n = len(raw)
        off = 0
        frames = []
        while off + 2 < n:
            addr = raw[off]
            if not (addr & 0x01):               # 两字节扩展地址
                if off + 1 >= n:
                    break
                addr |= raw[off + 1] << 8
                off += 2
            else:
                off += 1
            dlci = (addr >> 2) & 0x3F
            if off >= n:
                break
            ctrl = raw[off]
            off += 1
            if ctrl in self._RFCOMM_NODATA:
                # SABM/UA/DM/DISC：本抓包实测为 ctrl+1 字节+FCS（共再跳 2 字节）
                off += 2
                continue
            if ctrl not in self._RFCOMM_UIH:
                # 非 RFCOMM（AVDTP/AVCTP 等同 CID 数据），停止本流解析
                break
            if off >= n:
                break
            b0 = raw[off]
            off += 1
            if b0 & 0x01:
                length = b0 >> 1
            else:
                if off >= n:
                    break
                b1 = raw[off]
                off += 1
                length = (b0 >> 1) | ((b1 & 0xFE) << 6)
            if length <= 0 or off + length + 1 > n:
                break
            # credit 自适应：无 credit 时 data 后是 FCS，再后是下一帧地址(EA=1)+合法控制字。
            # 双重确认下一帧 addr 与 ctrl；不成立则认为 length 后有 1 字节 credit。
            fcs_at = off + length
            nxt_addr = fcs_at + 1
            nxt_ctrl = fcs_at + 2
            valid_next = (nxt_ctrl < n and (raw[nxt_addr] & 0x01)
                          and raw[nxt_ctrl] in (self._RFCOMM_UIH | self._RFCOMM_NODATA))
            if valid_next:
                data = bytes(raw[off:fcs_at])
                off = fcs_at + 1                # 跳过 FCS
            elif off + 1 + length + 1 <= n:
                data = bytes(raw[off + 1:off + 1 + length])
                off = off + 1 + length + 1     # credit + data + FCS
            else:
                break
            if dlci != 0 and data:
                frames.append((dlci, data))
        return frames

    # ---- ATT ----
    def _att(self, pl, direction):
        if not pl:
            return
        op = pl[0] & 0x3f
        self.n_att += 1
        name = ATT_NAMES.get(op, "opcode 0x%02x" % op)
        try:
            if op in ATT_HANDLE_VALUE:
                if op == 0x16 and len(pl) >= 5:       # Prepare Write
                    handle = struct.unpack("<H", pl[1:3])[0]
                    value = pl[5:]
                else:
                    handle = struct.unpack("<H", pl[1:3])[0]
                    value = pl[3:]
                self._att_value(direction, name, handle, value, write=op in (0x12, 0x52, 0xD2, 0x16))
            elif op in ATT_READ_RSP:
                value = pl[1:]
                self._att_value(direction, name, None, value, write=False)
            elif op == 0x05 and len(pl) >= 2:        # Find Information Rsp
                fmt = pl[1]
                body = pl[2:]
                step = 4 if fmt == 1 else 18
                for i in range(0, len(body) - step + 1, step):
                    h = struct.unpack("<H", body[i:i + 2])[0]
                    uuid = body[i + 2:i + step]
                    self.gatt[h] = (uuid.hex(), "声明")
            elif op == 0x0d:                         # Read By Type Rsp（含特征声明）
                self._read_by_type(pl[1:])
            elif op == 0x11:                         # Read By Group Type Rsp（服务）
                self._read_by_group(pl[1:])
        except Exception:
            pass

    def _read_by_type(self, body):
        if not body:
            return
        ln = body[0]
        for off in range(1, len(body) - ln + 1, ln):
            rec = body[off:off + ln]
            if len(rec) >= 5:
                decl_h = struct.unpack("<H", rec[0:2])[0]
                props = rec[2]
                val_h = struct.unpack("<H", rec[3:5])[0]
                uuid = rec[5:].hex()
                self.gatt[val_h] = (uuid, "0x%02x" % props)

    def _read_by_group(self, body):
        if not body:
            return
        ln = body[0]
        for off in range(1, len(body) - ln + 1, ln):
            rec = body[off:off + ln]
            if len(rec) >= 4:
                start = struct.unpack("<H", rec[0:2])[0]
                uuid = rec[4:].hex() if ln > 4 else "%04x" % struct.unpack("<H", rec[4:6])[0]
                self.gatt[start] = (uuid, "service")

    def _att_value(self, direction, name, handle, value, write):
        if not value:
            return
        dname = "主→从" if direction == 1 else ("从→主" if direction == 2 else "?")
        hdesc = "0x%04x" % handle if handle is not None else "-"
        gatt = self.gatt.get(handle) if handle is not None else None
        gatt_s = f"  特征UUID={gatt[0]}" if gatt else ""
        txt, cands = _decode_value(value)
        self.att_rows.append((direction, name, handle, bytes(value)))
        level = "ok" if write else "info"
        self.log(level, f"ATT {name} [{dname}] handle={hdesc}{gatt_s}",
                 f"HEX: {value.hex()}\nASCII: {txt}")
        # 特征值 MD5（灯泡开锁类题常要求“开启特征值 -> MD5”）
        if write and handle is not None:
            hv = f"{handle:04x}_{value.hex()}"
            self.log("info", "写入特征值候选",
                     f"handle=0x{handle:04x} value_hex={value.hex()} value_ascii={txt!r}\n"
                     f"MD5(value_hex)={_md5(value.hex())}\nMD5(value_ascii)={_md5(txt.strip())}")
        for c in cands:
            for fl in scan_flags(c.encode("utf-8", "replace")):
                self.log("flag", f"ATT {name} value 中发现 flag", fl)
        # 单字节开关值（00/01/02）也保留 hex 供核对
        if write and 1 <= len(value) <= 4:
            self.log("info", "短开关值", f"handle=0x{handle:04x} value=0x{value.hex()}")

    # ---- SMP ----
    def _smp(self, pl, direction):
        if not pl:
            return
        code = pl[0]
        self.n_smp += 1
        names = {0x01: "Pairing Request", 0x02: "Pairing Response", 0x03: "Pairing Confirm",
                 0x04: "Pairing Random", 0x05: "Pairing Failed", 0x08: "Encryption Info(LTK)",
                 0x09: "Master Identification", 0x0A: "Identity Info(IRK)",
                 0x0C: "Signing Info(CSRK)", 0x0D: "Security Request",
                 0x0E: "Pairing Public Key", 0x0F: "Pairing DHKey Check",
                 0x10: "Keypress Notification"}
        if code in (0x08, 0x0A, 0x0C) and len(pl) >= 17:
            key = pl[1:17].hex()
            label = {0x08: "LTK 长期密钥", 0x0A: "IRK 身份解析密钥", 0x0C: "CSRK 签名密钥"}[code]
            self.smp.append((label, key))
            self.log("ok", f"SMP {label}", key)
        elif code == 0x10 and len(pl) >= 2:
            self.log("info", "SMP 按键通知(Passkey 输入过程)", f"通知类型=0x{pl[1]:02x}")
        else:
            self.log("info", "SMP", names.get(code, "code=0x%02x" % code))

    # ---- 汇总落盘 ----
    def finish(self):
        # 经典蓝牙：先把每条 RFCOMM 字节流拆成 UIH 数据帧
        for (direction, cid), raw in self.rfcomm_raw.items():
            head = bytes(raw[:16])
            # RFCOMM 必以 DLCI0 的 SABM/UA 建链开头；否则该 CID 是 AVDTP/AVCTP，跳过
            if not any(m in head for m in (b"\x03\x3f", b"\x03\x2f", b"\x03\x73", b"\x03\x63")):
                continue
            for dlci, data in self._parse_rfcomm_stream(direction, cid, bytes(raw)):
                key = (direction, dlci)
                if key not in self.rfcomm_streams:
                    self.rfcomm_streams[key] = bytearray()
                self.rfcomm_streams[key] += data
                self.rfcomm_frames.append((direction, dlci, data))
        if self.att_rows:
            fp = os.path.join(self.outdir, "att_values.txt")
            lines = []
            for direction, name, handle, value in self.att_rows:
                dname = "M->S" if direction == 1 else ("S->M" if direction == 2 else "?")
                h = "0x%04x" % handle if handle is not None else "-"
                lines.append(f"[{dname}] {name:28s} handle={h:6s} hex={value.hex()} ascii={_ascii(value)}")
            save_artifact(fp, ("\n".join(lines)).encode("utf-8"))
            self.rep.extracted.append(fp)
            self.log("ok", f"ATT 流水已导出（{len(self.att_rows)} 条）", fp, fp)
        if self.rfcomm_frames:
            # 逐帧清单（含二进制 data 的 hex，便于定位“第一组开关指令”）
            fp = os.path.join(self.outdir, "rfcomm_frames.txt")
            lines = []
            for i, (d, dlci, data) in enumerate(self.rfcomm_frames):
                dn = "发" if d == 1 else "收"
                lines.append(f"#{i:<4d} [{dn}] DLCI={dlci:<2d} len={len(data):<3d} "
                             f"hex={data.hex()} ascii={_ascii(data)}")
            save_artifact(fp, ("\n".join(lines)).encode("utf-8"))
            self.rep.extracted.append(fp)
            self.log("ok", f"RFCOMM 帧清单已导出（{len(self.rfcomm_frames)} 帧）", fp, fp)
        if self.rfcomm_streams:
            for (d, dlci), buf in sorted(self.rfcomm_streams.items()):
                fp = os.path.join(self.outdir, f"rfcomm_spp_{'tx' if d == 1 else 'rx'}_dlci{dlci}.txt")
                save_artifact(fp, bytes(buf))
                self.rep.extracted.append(fp)
                self.rfcomm += bytes(buf)
                for fl in scan_flags(bytes(buf)):
                    if fl not in self._flag_seen:
                        self._flag_seen.add(fl)
                        self.log("flag", f"RFCOMM/SPP(DLCI{dlci}) 明文 flag", fl)
            # 对每个二进制数据帧也给 MD5（开关指令类题常要求“第 N 组 data 的 md5”）
            for i, (d, dlci, data) in enumerate(self.rfcomm_frames):
                if not any(32 <= c < 127 for c in data):   # 非纯文本 = 二进制控制指令
                    self.log("info", f"RFCOMM 二进制指令帧 #{i} [{ '发' if d==1 else '收' }] DLCI{dlci}",
                             f"hex={data.hex()}\nMD5(hex)={_md5(data.hex())}\nMD5(bytes)={hashlib.md5(data).hexdigest()}")
        # 地址清单
        if self.addrs:
            lines = []
            for mac, notes in sorted(self.addrs.items()):
                lines.append(f"{mac}  ({','.join(sorted(notes))})  MD5={_md5(mac)} md5lower={_md5(mac.lower())}")
            self.log("ok", f"蓝牙地址清单（{len(self.addrs)} 个）", "\n".join(lines))
        self.log("info", "蓝牙分析统计",
                 f"HCI ACL={self.n_acl}  ATT 消息={self.n_att}  SMP={self.n_smp}  "
                 f"广播记录={len(self.adv_data)}  GATT 句柄={len(self.gatt)}")


# ============================================================================
# BLE 链路层包（272 伪头 / 250 裸）定位 AA 并解析
# ============================================================================
def _strip_phdr_272(pkt):
    """nRF Sniffer(272) 伪头后定位 BLE 帧。
    返回 (aa, frame_without_aa) 或 None。广播帧直接搜 d6be898e；数据包用学到的 AA。"""
    idx = pkt.find(ADV_AA)
    if 0 <= idx <= 40:
        return ADV_AA, pkt[idx + 4:]
    return None


def analyze_ble_pcap(path, report: Report, outdir: str, linktype, pkts):
    asm = BtAssembler(report, outdir)
    os.makedirs(outdir, exist_ok=True)

    # 确定伪头长度 PH 与每个包的 (方向, AA 所在 body)
    if linktype == 250:
        ph = 0
    elif linktype == 251:
        ph = 4
    else:           # 272 nRF Sniffer：从广播 AA 偏移学伪头长度（实测 17 字节）
        ph = 17
        offs = Counter()
        for raw, _d in pkts:
            idx = raw.find(ADV_AA)
            if 0 <= idx <= 40:
                offs[idx] += 1
        if offs:
            ph = offs.most_common(1)[0][0]

    # 学习数据通道 AA：以“非广播包 PH 偏移处高频 4 字节”为准（连接中稳定出现，
    # 最可靠，可避开周边其他设备 CONNECT_IND 的干扰）；过短抓包再回退 CONNECT_IND。
    cand = Counter()
    for raw, _d in pkts:
        if len(raw) > ph + 4:
            aa = raw[ph:ph + 4]
            if aa != ADV_AA and aa not in (b"\x00\x00\x00\x00", b"\xff\xff\xff\xff"):
                cand[aa] += 1
    data_aa = cand.most_common(1)[0][0] if cand and cand.most_common(1)[0][1] >= 20 else None
    if data_aa is None:
        for raw, _d in pkts:
            body = raw[ph:] if ph else raw
            if body[:4] == ADV_AA and len(body) >= 6:
                ptype, length = body[4] & 0x0f, body[5]
                payload = body[6:6 + length]
                if ptype == 5 and len(payload) >= 16:
                    data_aa = payload[12:16]
                    break

    n = 0
    for raw, _d in pkts:
        body = raw[ph:] if ph else raw
        if len(body) < 7:
            continue
        aa = body[:4]
        if aa == ADV_AA:
            direction = 1
        elif data_aa and aa == data_aa:
            if linktype == 272:
                # btle_radio flags 在伪头偏移 8，bit1=1 为主→从（Write Req 方向）
                direction = 1 if ((raw[8] >> 1) & 1) == 1 else 2
            elif linktype == 251:
                direction = 1 if (raw[0] & 0x01) == 0 else 2
            else:
                direction = 1
        else:
            continue
        # PDU = header(2)+payload，末尾 3 字节 CRC 去掉（length 字段本身不含 CRC）
        hdr, length = body[4], body[5]
        frame = body[4:6 + length]      # 仅 header+payload，天然不含 CRC
        if len(frame) >= 3:
            asm.feed_ll(direction, aa, frame)
            n += 1
    report.add("info", "BLE 链路层抓包",
               f"linktype={linktype} 伪头={ph}B 解析PDU={n} 数据通道AA="
               + (data_aa.hex() if data_aa else "(无连接/纯广播)"))
    asm.finish()


def analyze_hci_pcap(path, report: Report, outdir: str, linktype, pkts):
    asm = BtAssembler(report, outdir)
    os.makedirs(outdir, exist_ok=True)
    for raw, _d in pkts:
        if linktype == 251:
            direction = 1 if (raw[0] & 0x01) == 0 else 2
            h4 = raw[4:]
        else:               # 187 裸 H4，方向未知：按包类型推断
            h4 = raw
            direction = 1 if h4 and h4[0] in (0x01, 0x02) else 2
        if h4:
            asm.feed_h4(direction, h4)
    report.add("info", "HCI 抓包", f"linktype={linktype} HCI 包={len(pkts)}")
    asm.finish()


def analyze_btsnoop(path, report: Report, outdir: str):
    os.makedirs(outdir, exist_ok=True)
    recs = read_btsnoop(path)
    asm = BtAssembler(report, outdir)
    for direction, h4 in recs:
        asm.feed_h4(direction, h4)
    report.add("info", "btsnoop HCI 日志", f"记录数={len(recs)}（Android 蓝牙 HCI snoop，H4）")
    asm.finish()


# ============================================================================
# 统一入口（供 modules_traffic 调用）
# ============================================================================
BLUETOOTH_LINKTYPES = {187, 250, 251, 272}


def analyze(path, report: Report, outdir: str, linktype=None, magic=None):
    """根据文件形态选择解析器。返回 True 表示已按蓝牙处理。"""
    try:
        with open(path, "rb") as f:
            head = f.read(16)
        if head[:8] == BTSNOOP_MAGIC:
            analyze_btsnoop(path, report, outdir)
            return True
        lt, pkts = read_capture(path)
        if linktype is not None:
            lt = linktype
        if lt in BLUETOOTH_LINKTYPES:
            if lt in (250, 272):
                analyze_ble_pcap(path, report, outdir, lt, pkts)
            else:
                analyze_hci_pcap(path, report, outdir, lt, pkts)
            return True
    except Exception as e:
        report.add("warn", "蓝牙分析异常", f"{type(e).__name__}: {e}")
    return False
