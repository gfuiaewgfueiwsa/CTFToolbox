# -*- coding: utf-8 -*-
# 脚本名称: 多线程目录/敏感文件扫描器
# 方向: Web（信息收集 / 目录爆破）
# 简介: 对目标 URL 做目录与敏感文件爆破：内置常见后台、备份文件、.git/.svn、
#       配置文件、云元数据等字典；按状态码+响应长度去重，自动识别 404 软响应，
#       支持自定义字典、线程数、超时、Cookie、代理、扩展名字典。
# 用法:
#   python dirscan.py http://target.com/
#   python dirscan.py http://target.com/ -w dirs.txt -t 30 --ext php,bak,txt
#   python dirscan.py http://target.com/ --cookie "PHPSESSID=xxx" --proxy http://127.0.0.1:8080
#   python dirscan.py --selftest
# 依赖: pip install requests
# 注意: 仅对授权目标使用；未经授权的扫描可能违法。
import argparse
import concurrent.futures as cf
import sys
import urllib.parse as up

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
except Exception:
    requests = None

BUILTIN = [
    "admin", "login", "manage", "manager", "backend", "system", "console",
    "phpmyadmin", "admin.php", "login.php", "index.php~", "index.php.bak",
    "test", "demo", "dev", "api", "api/v1", "swagger", "swagger-ui.html",
    "actuator", "actuator/env", "metrics", "debug", "status", "info.php",
    "phpinfo.php", "robots.txt", "sitemap.xml", "crossdomain.xml",
    ".git/HEAD", ".git/config", ".svn/entries", ".env", ".DS_Store",
    "web.config", "WEB-INF/web.xml", "config.php", "config.php.bak",
    "database.sql", "db.sql", "backup.sql", "dump.sql", "backup.zip",
    "backup.tar.gz", "www.zip", "web.zip", "site.zip", "1.zip",
    "package.json", "composer.json", ".idea/workspace.xml",
    "server-status", "nginx_status", "upload", "uploads", "files",
    "static", "js", "css", "flag", "flag.txt", "/etc/passwd",
]
HARD_EXT = (".zip", ".tar.gz", ".bak", ".sql", ".txt", ".xml", ".php~")


class Scanner:
    def __init__(self, base, threads=20, timeout=8, cookie=None, proxy=None,
                 headers=None):
        self.base = base.rstrip("/") + "/"
        self.threads = threads
        self.timeout = timeout
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": "Mozilla/5.0 (CTF dirscan)"})
        if cookie:
            self.s.headers["Cookie"] = cookie
        if headers:
            for kv in headers:
                k, v = kv.split(":", 1)
                self.s.headers[k.strip()] = v.strip()
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.fake404 = None

    def req(self, path):
        url = self.base + path.lstrip("/")
        try:
            r = self.s.get(url, timeout=self.timeout, verify=False,
                           proxies=self.proxies, allow_redirects=False)
            return r.status_code, len(r.content), r.headers.get("Location", "")
        except Exception as e:
            return None, 0, str(e)

    def calibrate(self):
        """请求一个必不存在的随机路径，识别软 404 的状态码与长度。"""
        code, ln, _ = self.req("nope_%d_404calib" % 0x5eed)
        self.fake404 = (code, ln)
        return self.fake404

    def hit(self, path):
        code, ln, loc = self.req(path)
        if code is None:
            return None
        if self.fake404 and code == self.fake404[0] and abs(ln - self.fake404[1]) < 16:
            return None
        if code in (200, 201, 301, 302, 307, 401, 403, 500):
            return code, ln, loc
        return None

    def scan(self, words, exts=()):
        paths = []
        for w in words:
            w = w.strip().lstrip("/")
            if not w or w.startswith("#"):
                continue
            paths.append(w)
            if exts and "." not in w.split("/")[-1]:
                for e in exts:
                    paths.append(w + "." + e.lstrip("."))
        self.calibrate()
        found = []
        with cf.ThreadPoolExecutor(self.threads) as ex:
            futs = {ex.submit(self.hit, p): p for p in dict.fromkeys(paths)}
            for fut in cf.as_completed(futs):
                r = fut.result()
                if r:
                    p = futs[fut]
                    found.append((p,) + r)
                    print(f"[{r[0]}] {len(str(r[1])) and r[1]:>8}  {p}  -> {r[2]}")
        return found


def selftest():
    # 起本地 HTTP 服务验证扫描链路
    import http.server
    import socketserver
    import threading
    import os
    d = os.path.join(os.environ.get("TEMP", "."), "dirscan_self")
    os.makedirs(os.path.join(d, "admin"), exist_ok=True)
    open(os.path.join(d, "robots.txt"), "w").write("User-agent: *")
    open(os.path.join(d, "admin", "index.html"), "w").write("admin ok")
    os.chdir(d)
    srv = socketserver.TCPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        sc = Scanner(f"http://127.0.0.1:{port}/", threads=4)
        found = sc.scan(["robots.txt", "admin/", "notexist_xyz"])
        paths = [f[0] for f in found]
        assert "robots.txt" in paths and "admin/" in paths, paths
        print("[+] selftest OK, 发现:", paths)
    finally:
        srv.shutdown()


def main():
    if requests is None:
        print("[!] 请先 pip install requests"); return
    ap = argparse.ArgumentParser(description="目录扫描器")
    ap.add_argument("url", nargs="?")
    ap.add_argument("-w", "--wordlist")
    ap.add_argument("-t", "--threads", type=int, default=20)
    ap.add_argument("--ext", default="", help="追加扩展名，逗号分隔，如 php,bak,txt")
    ap.add_argument("--cookie")
    ap.add_argument("--proxy")
    ap.add_argument("-H", "--header", action="append")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.url:
        print("[!] 用法: python dirscan.py http://target/"); return
    words = BUILTIN
    if a.wordlist:
        words = open(a.wordlist, encoding="utf-8", errors="replace").read().splitlines()
    exts = tuple(x for x in a.ext.split(",") if x)
    sc = Scanner(a.url, a.threads, cookie=a.cookie, proxy=a.proxy, headers=a.header)
    sc.scan(words, exts)


if __name__ == "__main__":
    main()
