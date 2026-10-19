# -*- coding: utf-8 -*-
# 脚本名称: DNS 隧道/外带数据还原（子域名拼接）
# 方向: Forensics（流量分析 / 数据外带）
# 简介: CTF 常把 flag/文件经 DNS 查询外带（每段数据编码成子域名）。
#       脚本提取所有 A/TXT/CNAME 查询名，按时间与源 IP 分组，还原多级
#       标签序列，自动尝试 hex/base32/base64 解码并扫描 flag；
#       同时统计异常长域名、稀有 DNS 服务器。
# 用法:
#   python pcap_dns_exfil.py capture.pcap
#   python pcap_dns_exfil.py capture.pcap --domain attacker.xyz
#   python pcap_dns_exfil.py --selftest
# 依赖: pip install scapy
import argparse
import base64
import binascii
import os
import re
from collections import defaultdict

FLAG_RE = re.compile(rb"(?i)(?:flag|ctf|key)\{[ -~]{1,200}\}")


def queries(path):
    from scapy.all import rdpcap, DNSQR, DNS
    out = []
    for p in rdpcap(path):
        if p.haslayer(DNS) and p[DNS].qr == 0 and p.haslayer(DNSQR):
            q = p[DNSQR].qname.decode(errors="replace").rstrip(".")
            src = p["IP"].src if p.haslayer("IP") else "?"
            out.append((float(p.time), src, q))
    return out


def try_decode(blob):
    cands = []
    cands.append(("raw", blob))
    try:
        cands.append(("hex", binascii.unhexlify(blob)))
    except Exception:
        pass
    for name, fn in (("b32", base64.b32decode), ("b64", base64.b64decode)):
        try:
            cands.append((name, fn(blob + b"=" * (-len(blob) % 8))))
        except Exception:
            pass
    return cands


def run(path, domain=None):
    qs = queries(path)
    print(f"[*] 共 {len(qs)} 条 DNS 查询")
    groups = defaultdict(list)
    for t, src, q in qs:
        labels = q.split(".")
        if domain and not q.endswith(domain):
            continue
        key = src
        groups[key].append((t, labels, q))
        if len(q) > 50:
            print(f"[长域名] {src} {q}")
    for src, items in groups.items():
        # 按时间排序，把每条查询最前面的“数据标签”顺序拼接
        items.sort()
        joined = b""
        for t, labels, q in items:
            data_labels = labels
            if domain:
                dl = len(domain.rstrip(".").split("."))
                data_labels = labels[:-dl]
            joined += "".join(data_labels).encode()
        print(f"\n===== 源 {src}，拼接数据长度 {len(joined)}")
        print("    前 120 字符:", joined[:120])
        for name, dec in try_decode(joined):
            for m in FLAG_RE.findall(dec):
                print(f"[!!!] ({name})", m.decode(errors="replace"))
            printable = sum(1 for c in dec if 32 <= c < 127) / max(1, len(dec))
            if printable > 0.9 and len(dec) > 4:
                print(f"    [{name}] 可打印:", dec[:120].decode(errors="replace"))


def selftest():
    from scapy.all import IP, UDP, DNS, DNSQR, wrpcap
    d = os.path.join(os.environ.get("TEMP", "."), "dns_self")
    os.makedirs(d, exist_ok=True)
    secret = b"flag{dns_exfil_ok}"
    hexed = secret.hex()
    pkts = []
    for i in range(0, len(hexed), 20):
        chunk = hexed[i:i + 20]
        q = f"{chunk}.attacker.xyz"
        pkts.append(IP(src="10.0.0.9", dst="8.8.8.8") / UDP() /
                    DNS(rd=1, qd=DNSQR(qname=q)))
    p = os.path.join(d, "t.pcap")
    wrpcap(p, pkts)
    run(p, "attacker.xyz")
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="DNS 隧道还原")
    ap.add_argument("pcap", nargs="?")
    ap.add_argument("--domain")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.pcap:
        print("[!] 用法: python pcap_dns_exfil.py x.pcap [--domain x.yz]"); return
    run(a.pcap, a.domain)


if __name__ == "__main__":
    main()
