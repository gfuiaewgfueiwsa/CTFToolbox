# -*- coding: utf-8 -*-
"""DNS 隧道 / 带外传数据取证（防御 / CTF 向，纯离线）。

识别并还原通过 DNS 偷带的数据：
  - dnscat2：默认 TXT（hex 编码），可选 magic "ABCD"(0x41424344)，按 MSG_DATA
    的 session/seq 去重排序，还原双向数据流（仅明文模式；带 pre-shared secret
    的加密流量无法离线解密，会明确提示）；
  - iodine：NULL(10) / PRIVATE(65535) / TXT / CNAME，base32/base64/raw 子域拼接；
  - 通用高熵长子域带外：A/AAAA/CNAME/TXT/NULL，按序号标签重组后尝试 hex/base32/base64/raw；
  - 隧道特征统计：超长 / 高熵标签、TXT/NULL 异常、查询频率与 NXDOMAIN 比例。

只做识别与还原，不发起任何 DNS 请求、不提供隧道通信能力。
"""
import os
import re
import math
import base64
import struct
from collections import defaultdict, Counter

from .common import Report, save_artifact, scan_flags

DNScat_MSG_DATA = 1
DNScat_MSG_STATE = 0
MAGIC = b"\x41\x42\x43\x44"          # "ABCD"


# ----------------------------------------------------------------------------
# 基础
# ----------------------------------------------------------------------------
def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def _try_hex(s: str):
    s = s.strip().replace("-", "")
    if len(s) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", s):
        return None
    try:
        return bytes.fromhex(s)
    except Exception:
        return None


def _try_b64(s: str):
    try:
        pad = "=" * ((-len(s)) % 4)
        return base64.b64decode(s + pad, validate=False)
    except Exception:
        return None


def _try_b32(s: str):
    try:
        pad = "=" * ((-len(s)) % 8)
        return base64.b32decode(s.upper() + pad, casefold=True)
    except Exception:
        return None


def _readable(b: bytes) -> bool:
    if not b:
        return False
    good = sum(1 for x in b if 9 <= x <= 13 or 32 <= x < 127)
    return good / len(b) > 0.85


def _best_decode(blob: str):
    """对拼接后的字符串给出最可信的解码候选。返回 (方式, bytes)。"""
    cands = []
    hx = _try_hex(blob)
    if hx:
        cands.append(("hex", hx))
    b64 = _try_b64(blob)
    if b64:
        cands.append(("base64", b64))
    b32 = _try_b32(blob)
    if b32:
        cands.append(("base32", b32))
    cands.append(("raw", blob.encode("latin-1", "replace")))
    # 优先可读且含 flag，其次可读性
    for name, b in cands:
        if _readable(b) and re.search(rb"(flag|ctf)\{", b, re.I):
            return name, b
    for name, b in cands:
        if name != "raw" and _readable(b):
            return name, b
    return cands[0]


# ----------------------------------------------------------------------------
# 采集 DNS 数据单元
# ----------------------------------------------------------------------------
def _iter_rr(dns_pkt, DNSRR):
    """稳健展开 DNS answer（兼容单条 payload 链与 scapy _list 容器）。"""
    an = getattr(dns_pkt, "an", None)
    if an is None:
        return
    if type(an).__name__ == "_list":
        for rr in list(an):
            if hasattr(rr, "rdata"):
                yield rr
        return
    layer = an
    while layer is not None and DNSRR in layer:
        yield layer[DNSRR]
        layer = getattr(layer, "payload", None)
        if not hasattr(layer, "rdata"):
            break


def collect(path: str):
    """返回 dict: 查询名、TXT/NULL rdata、原始数据单元、统计指标。"""
    try:
        from scapy.all import PcapReader, PcapNgReader, UDP, IP, DNS, DNSQR, DNSRR
    except Exception:
        return None
    reader = PcapNgReader(path) if open(path, "rb").read(4) == b"\x0a\x0d\x0d\x0a" else PcapReader(path)

    names = []
    txt_rdata = []                 # (方向, 字符串)
    units = []                     # (方向 0=上行query 1=下行answer, 编码文本, 记录类型, 主域)
    null_rdata = []
    n_query = n_txt = n_null = n_long = n_highent = 0
    label_len_max = 0
    suffix_counter = Counter()

    def process_qname(qname, direction):
        nonlocal n_long, n_highent, label_len_max
        name = qname.decode("utf-8", "replace").rstrip(".")
        names.append(name)
        labs = name.split(".")
        if len(labs) >= 2:
            suffix = ".".join(labs[-2:])
            suffix_counter[suffix] += 1
            data_labs = labs[:-2]
            for lab in data_labs:
                label_len_max = max(label_len_max, len(lab))
                if len(lab) >= 40:
                    n_long += 1
                if len(lab) >= 16 and _entropy(lab) > 3.5:
                    n_highent += 1
                if re.fullmatch(r"[0-9a-zA-Z+/=_-]{8,}", lab):
                    units.append((direction, lab, "qlabel", suffix))

    try:
        for pkt in reader:
            try:
                if DNS not in pkt:
                    continue
                d = pkt[DNS]
                qr = int(getattr(d, "qr", 0))
                if d.qd:
                    n_query += 1
                    process_qname(bytes(d.qd.qname), 0)
                for rr in _iter_rr(d, DNSRR):
                    rtype = int(getattr(rr, "type", 0))
                    rdata = rr.rdata
                    if rtype == 16:        # TXT
                        n_txt += 1
                        if isinstance(rdata, (bytes, bytearray)):
                            txt = rdata.decode("utf-8", "replace")
                        elif isinstance(rdata, list):
                            txt = "".join(x.decode("utf-8", "replace")
                                          if isinstance(x, (bytes, bytearray)) else str(x)
                                          for x in rdata)
                        else:
                            txt = str(rdata)
                        txt_rdata.append((1, txt))
                        units.append((1, txt.strip(), "TXT", ""))
                    elif rtype in (10, 65535):   # NULL / PRIVATE（iodine 常用）
                        n_null += 1
                        if isinstance(rdata, (bytes, bytearray)):
                            null_rdata.append((1, bytes(rdata)))
                            units.append((1, bytes(rdata).hex(), "NULL", ""))
                    elif rtype == 5:      # CNAME
                        try:
                            process_qname(bytes(rr.rdata) if isinstance(rr.rdata, (bytes, bytearray))
                                          else str(rr.rdata).encode(), 1)
                        except Exception:
                            pass
            except Exception:
                continue
    finally:
        try:
            reader.close()
        except Exception:
            pass

    return {
        "names": names, "txt": txt_rdata, "null": null_rdata, "units": units,
        "n_query": n_query, "n_txt": n_txt, "n_null": n_null,
        "n_long": n_long, "n_highent": n_highent, "label_max": label_len_max,
        "suffix": suffix_counter,
    }


# ----------------------------------------------------------------------------
# dnscat2 解析（明文 TXT / hex）
# ----------------------------------------------------------------------------
def parse_dnscat2(units):
    """从 hex 编码单元解析 dnscat2 MSG_DATA，按 (方向,session) seq 排序拼接。"""
    streams = defaultdict(dict)        # (direction, session) -> {seq: data}
    syn = []
    used = 0
    for direction, text, rtype, suffix in units:
        raw = _try_hex(text)
        if not raw:
            continue
        if raw[:4] == MAGIC:
            raw = raw[4:]
        if len(raw) < 6:
            continue
        # packet_id(2) + type(2)
        try:
            _pid, ptype = struct.unpack(">HH", raw[:4])
        except Exception:
            continue
        body = raw[4:]
        if ptype == DNScat_MSG_STATE and len(body) >= 6:    # SYN
            sid, seq, ack = struct.unpack(">HHH", body[:6])
            syn.append((direction, sid))
            used += 1
        elif ptype == DNScat_MSG_DATA and len(body) >= 6:
            sid, seq, ack = struct.unpack(">HHH", body[:6])
            data = body[6:]
            streams[(direction, sid)][seq] = data
            used += 1
    if used == 0:
        return None
    out = {}
    for key, segs in streams.items():
        blob = b"".join(segs[s] for s in sorted(segs))
        if blob:
            out[key] = blob
    return {"streams": out, "syn": syn, "segments": used}


# ----------------------------------------------------------------------------
# 主入口
# ----------------------------------------------------------------------------
def analyze_pcap(path: str, report: Report, outdir: str):
    try:
        c = collect(path)
    except Exception as e:
        report.add("warn", "DNS 采集失败", f"{type(e).__name__}: {e}")
        return False
    if not c or c["n_query"] == 0:
        return False

    dns_dir = os.path.join(outdir, "dns_tunnel")
    findings = 0

    # ---- 隧道特征统计 ----
    signals = []
    if c["n_txt"] >= 8:
        signals.append(f"TXT 应答 {c['n_txt']} 条（dnscat2/带外常见）")
    if c["n_null"] >= 1:
        signals.append(f"NULL/PRIVATE 记录 {c['n_null']} 条（iodine 常见）")
    if c["n_long"] >= 8:
        signals.append(f"超长标签(>=40) {c['n_long']} 个")
    if c["n_highent"] >= 10:
        signals.append(f"高熵长标签 {c['n_highent']} 个")
    top_suffix = c["suffix"].most_common(3)
    tunnel_like = bool(signals)

    # ---- 1) dnscat2 ----
    cat = parse_dnscat2(c["units"])
    cat_hit = bool(cat and cat["streams"])
    if cat and cat["streams"]:
        os.makedirs(dns_dir, exist_ok=True)
        for (direction, sid), blob in cat["streams"].items():
            dn = "上行(query)" if direction == 0 else "下行(answer)"
            fp = os.path.join(dns_dir, f"dnscat2_{'up' if direction==0 else 'down'}_sess{sid}.bin")
            save_artifact(fp, blob)
            report.extracted.append(fp)
            report.add("flag", f"dnscat2 隧道数据流 {dn} session={sid}（{len(blob)} 字节）",
                       f"明文 dnscat2，已按 seq 重组: {fp}\n预览: {blob[:200]!r}", fp)
            for fl in scan_flags(blob):
                report.add("flag", "dnscat2 数据中发现 flag", fl)
            findings += 1
        if not cat["streams"] and cat["segments"]:
            signals.append("检测到 dnscat2 控制包但无数据段（可能为加密会话）")
    elif c["n_txt"] >= 8:
        signals.append("大量 TXT 但未按明文 dnscat2 解析（可能启用 pre-shared key 加密）")

    # ---- 2) iodine / 通用 NULL/TXT 拼接 ----
    if c["null"]:
        os.makedirs(dns_dir, exist_ok=True)
        blob = b"".join(x for _d, x in c["null"])
        fp = os.path.join(dns_dir, "dns_null_rdata.bin")
        save_artifact(fp, blob)
        report.extracted.append(fp)
        report.add("ok", f"NULL/PRIVATE 记录拼接（{len(c['null'])} 段，iodine 特征）",
                   f"{fp}\n预览: {blob[:200]!r}", fp)
        for fl in scan_flags(blob):
            report.add("flag", "NULL 记录中发现 flag", fl)
        findings += 1

    # ---- 3) 通用高熵子域带外：按主域后缀聚合，序号重组 + 解码 ----
    suffix_units = defaultdict(list)
    for direction, text, rtype, suffix in c["units"]:
        if rtype == "qlabel" and suffix:
            suffix_units[(direction, suffix)].append(text)
        elif rtype == "TXT":
            suffix_units[(direction, "(TXT)")].append(text)
    for (direction, suffix), labs in suffix_units.items():
        if len(labs) < 2:
            continue
        if suffix == "(TXT)" and cat_hit:
            continue   # dnscat2 已精确还原，避免重复拼接
        # 去掉序号前缀（如 01-xxx / 1.xxx / 01_xxx），再按序号排序
        ordered = []
        numbered = 0
        for lab in labs:
            m = re.match(r"^(\d{1,4})[._-]?(.+)$", lab)
            if m:
                ordered.append((int(m.group(1)), m.group(2)))
                numbered += 1
            else:
                ordered.append((None, lab))
        if numbered >= max(2, len(labs) * 0.6):
            joined = "".join(t for _i, t in sorted(ordered, key=lambda x: (x[0] is None, x[0] or 0)))
        else:
            joined = "".join(t for _i, t in ordered)
        if len(joined) < 16:
            continue
        name, dec = _best_decode(joined)
        if not _readable(dec) and not re.search(rb"(flag|ctf)\{", dec, re.I):
            continue
        os.makedirs(dns_dir, exist_ok=True)
        tag = ("up_" if direction == 0 else "down_") + re.sub(r"[^0-9a-zA-Z]", "_", suffix)[:40]
        fp = os.path.join(dns_dir, f"exfil_{tag}.bin")
        save_artifact(fp, dec)
        report.extracted.append(fp)
        report.add("ok", f"DNS 带外数据还原（{suffix or 'TXT'}，{len(labs)} 段，{name} 解码）",
                   f"{fp}\n预览: {dec[:300]!r}", fp)
        for fl in scan_flags(dec):
            report.add("flag", "DNS 带外数据中发现 flag", fl)
        findings += 1

    # ---- 汇总告警 ----
    if tunnel_like:
        report.add("ok" if findings else "info",
                   f"DNS 隧道特征（查询 {c['n_query']}，TXT {c['n_txt']}，NULL {c['n_null']}）",
                   "；".join(signals) +
                   (f"\n最活跃后缀: {', '.join(f'{s}({n})' for s, n in top_suffix)}"
                    if top_suffix else ""))
    return findings > 0 or tunnel_like
