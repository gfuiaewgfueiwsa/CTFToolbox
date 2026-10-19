# -*- coding: utf-8 -*-
# 脚本名称: HTTP 基础探测（方法/头/指纹/TLS/参数污染）
# 方向: Web（信息收集 / 漏洞验证）
# 简介: 对单个 URL 做快速体检：状态码与跳转链、响应头安全配置审计、
#       允许的 HTTP 方法（OPTIONS）、常见方法试探(TRACE/PUT/DELETE)、
#       Server/X-Powered-By 指纹、Cookie 属性、TLS 证书信息、参数反射检测。
# 用法:
#   python http_probe.py http://target/
#   python http_probe.py http://target/ --param q
#   python http_probe.py --selftest
# 依赖: pip install requests
import argparse
import ssl
import socket
try:
    import requests
    import urllib3
    urllib3.disable_warnings()
except Exception:
    requests = None

SECURITY_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy",
                    "X-Frame-Options", "X-Content-Type-Options",
                    "Referrer-Policy", "Permissions-Policy"]


def probe(url, param=None):
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0 (CTF http-probe)"
    print("===== 基本请求")
    r = s.get(url, timeout=10, verify=False, allow_redirects=True)
    print("最终 URL:", r.url)
    print("跳转链:", " -> ".join(str(h.status_code) + ":" + h.headers.get("Location", "")
                                  for h in r.history) or "(无)")
    print("状态:", r.status_code, "长度:", len(r.content))
    print("===== 响应头")
    for k, v in r.headers.items():
        print(f"  {k}: {v}")
    print("===== 安全头审计")
    for h in SECURITY_HEADERS:
        print(f"  [{'缺失' if h not in r.headers else 'OK  '}] {h}")
    print("===== Cookie 属性")
    for c in s.cookies:
        flags = []
        if c.secure: flags.append("Secure")
        if c.has_nonstandard_attr("HttpOnly") if hasattr(c, "has_nonstandard_attr") else False:
            flags.append("HttpOnly")
        print(f"  {c.name}={c.value[:30]}  {' '.join(flags)}")
    print("===== HTTP 方法")
    try:
        o = s.options(url, timeout=8, verify=False)
        print("  OPTIONS Allow:", o.headers.get("Allow", "(未返回)"))
    except Exception as e:
        print("  OPTIONS 失败:", e)
    for m in ("TRACE", "PUT", "DELETE"):
        try:
            rr = s.request(m, url, timeout=8, verify=False)
            print(f"  {m:7s} -> {rr.status_code}")
        except Exception as e:
            print(f"  {m:7s} 失败: {e}")
    print("===== TLS 证书")
    try:
        host = url.split("//", 1)[1].split("/")[0].split(":")[0]
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=8) as sk:
            with ctx.wrap_socket(sk, server_hostname=host) as ss:
                cert = ss.getpeercert()
        print("  Subject:", cert.get("subject"))
        print("  Issuer :", cert.get("issuer"))
        print("  有效期 :", cert.get("notBefore"), "->", cert.get("notAfter"))
        san = cert.get("subjectAltName")
        if san:
            print("  SAN    :", [x[1] for x in san][:10])
    except Exception as e:
        print("  (无 HTTPS 或证书读取失败:", e, ")")
    if param:
        print("===== 参数反射检测")
        marker = "ctfprobe9f3k2"
        rr = s.get(r.url, params={param: marker}, timeout=8, verify=False)
        print(f"  {param}={marker} 是否原样回显:", marker in rr.text)
        print("  若回显且未编码，进一步测 XSS（见 xss_payloads.txt）")


def selftest():
    import http.server
    import socketserver
    import threading
    h = http.server.SimpleHTTPRequestHandler
    srv = socketserver.TCPServer(("127.0.0.1", 0), h)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        probe(f"http://127.0.0.1:{port}/")
        print("[+] selftest OK")
    finally:
        srv.shutdown()


def main():
    if requests is None:
        print("[!] 请先 pip install requests"); return
    ap = argparse.ArgumentParser(description="HTTP 基础探测")
    ap.add_argument("url", nargs="?")
    ap.add_argument("--param")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.url:
        print("[!] 用法: python http_probe.py http://target/"); return
    probe(a.url, a.param)


if __name__ == "__main__":
    main()
