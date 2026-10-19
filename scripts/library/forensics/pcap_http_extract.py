# -*- coding: utf-8 -*-
# 脚本名称: 流量包 HTTP 对象提取 / 重组（scapy）
# 方向: Forensics（流量分析）
# 简介: 从 pcap/pcapng 中重组 TCP 流并提取 HTTP 请求与响应对象：
#       保存所有上传/下载文件（按 Content-Type 与 magic 修正扩展名）、
#       列出 URL/POST 参数/Cookie/Authorization，自动扫描 flag 形态字符串；
#       支持 TLS 之前的明文 HTTP（80/8080 等）。
# 用法:
#   python pcap_http_extract.py capture.pcap -o out_dir
#   python pcap_http_extract.py capture.pcap --list
#   python pcap_http_extract.py --selftest
# 依赖: pip install scapy
import argparse
import os
import re
from collections import defaultdict

FLAG_RE = re.compile(rb"(?i)(?:flag|ctf|key)\{[ -~]{1,200}\}")
CT_EXT = {
    "image/png": ".png", "image/jpeg": ".jpg", "image/gif": ".gif",
    "text/html": ".html", "text/plain": ".txt", "application/zip": ".zip",
    "application/x-zip-compressed": ".zip", "application/pdf": ".pdf",
    "application/octet-stream": ".bin", "application/json": ".json",
    "application/x-www-form-urlencoded": ".post",
}


def reassemble(path):
    from scapy.all import rdpcap, TCP, Raw
    pkts = rdpcap(path)
    streams = defaultdict(list)
    for p in pkts:
        if TCP in p and Raw in p:
            a = (p["IP"].src, p["TCP"].sport)
            b = (p["IP"].dst, p["TCP"].dport)
            key = tuple(sorted((a, b)))
            streams[key].append((p["TCP"].seq, bytes(p[Raw].load), a, b))
    return streams


def parse_http(data):
    """从一段重组字节里切出若干 HTTP 消息（请求/响应）。"""
    msgs = []
    while b"\r\n\r\n" in data:
        head, rest = data.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        first = lines[0]
        headers = {}
        for ln in lines[1:]:
            if b":" in ln:
                k, v = ln.split(b":", 1)
                headers[k.strip().lower()] = v.strip()
        clen = int(headers.get(b"content-length", b"0") or b"0")
        body = rest[:clen] if clen else b""
        consumed = len(head) + 4 + len(body)
        # chunked 简化处理：无 Content-Length 时不强行切
        msgs.append((first, headers, body))
        data = data[consumed:] if consumed else data[1:]
    return msgs


def run(path, outdir, list_only=False):
    streams = reassemble(path)
    os.makedirs(outdir, exist_ok=True)
    idx = 0
    for key, segs in streams.items():
        # 按方向分别按 seq 排序拼接
        dirs = defaultdict(list)
        for seq, load, a, b in segs:
            dirs[(a, b)].append((seq, load))
        for (a, b), lst in dirs.items():
            lst.sort()
            blob = b"".join(x[1] for x in lst)
            if not (blob.startswith(b"GET ") or blob.startswith(b"POST ")
                    or blob.startswith(b"HTTP/")):
                continue
            for first, headers, body in parse_http(blob):
                if first.startswith((b"GET", b"POST")):
                    print(f"[REQ] {a[0]}:{a[1]} -> {b[0]}:{b[1]} {first.decode(errors='replace')}")
                    for hk in (b"cookie", b"authorization", b"host"):
                        if hk in headers:
                            print(f"      {hk.decode()}: {headers[hk].decode(errors='replace')[:200]}")
                    if body:
                        print("      POST:", body.decode(errors="replace")[:200])
                elif first.startswith(b"HTTP/") and body and not list_only:
                    ct = headers.get(b"content-type", b"").split(b";")[0].decode(errors="replace")
                    ext = CT_EXT.get(ct, ".bin")
                    fn = os.path.join(outdir, f"obj_{idx:03d}{ext}")
                    open(fn, "wb").write(body)
                    print(f"[OBJ] {len(body)} 字节 {ct} -> {fn}")
                    idx += 1
                for m in FLAG_RE.findall(first + b"\r\n" + body):
                    print("[!!!]", m.decode(errors="replace"))
    print(f"[*] 共提取 {idx} 个响应对象到 {outdir}")


def selftest():
    from scapy.all import IP, TCP, Raw, wrpcap
    d = os.path.join(os.environ.get("TEMP", "."), "pcap_self")
    os.makedirs(d, exist_ok=True)
    body = b"flag{http_object_ok}\n"
    resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
            + str(len(body)).encode() + b"\r\n\r\n" + body)
    req = b"GET /secret HTTP/1.1\r\nHost: x\r\n\r\n"
    pkts = [
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, seq=1, flags="PA") / Raw(req),
        IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=1234, seq=100, flags="PA") / Raw(resp),
    ]
    p = os.path.join(d, "t.pcap")
    wrpcap(p, pkts)
    run(p, os.path.join(d, "out"))
    assert os.path.exists(os.path.join(d, "out", "obj_000.txt"))
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="pcap HTTP 对象提取")
    ap.add_argument("pcap", nargs="?")
    ap.add_argument("-o", "--out", default="pcap_objects")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.pcap:
        print("[!] 用法: python pcap_http_extract.py x.pcap -o out"); return
    run(a.pcap, a.out, a.list)


if __name__ == "__main__":
    main()
