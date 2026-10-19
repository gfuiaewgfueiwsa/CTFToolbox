# -*- coding: utf-8 -*-
# 脚本名称: 备份文件/源码泄露专项扫描
# 方向: Web（信息收集）
# 简介: 针对 CTF/实战高频的源码与备份泄露做专项探测：
#       编辑器备份(.swp/.swo/~/.bak)、压缩包(zip/tar.gz/rar/7z)、
#       VCS(.git/.svn/.hg)、依赖清单、云凭据、框架默认文件；
#       对命中的压缩包自动 HEAD 校验 Content-Length 并给出恢复命令。
# 用法:
#   python backup_scan.py http://target.com/
#   python backup_scan.py http://target.com/ -p /index.php
#   python backup_scan.py --selftest
# 依赖: pip install requests
# 注意: 仅对授权目标使用。
import argparse

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
except Exception:
    requests = None

PREFIXES = ["", "www", "web", "backup", "bak", "site", "wwwroot", "html",
            "1", "admin", "code", "src", "source"]
SUFFIXES = [".zip", ".tar.gz", ".tgz", ".tar", ".rar", ".7z", ".bak",
            ".old", ".txt", ".sql", ".log"]
EDITOR = [".index.php.swp", ".index.php.swo", "index.php~", "index.php.bak",
          ".index.php.un~", ".DS_Store", "Thumbs.db"]
VCS = [".git/HEAD", ".git/config", ".git/index", ".svn/entries",
       ".svn/wc.db", ".hg/store", "CVS/Root"]
FRAMEWORK = [".env", "package.json", "composer.json", "composer.lock",
             "requirements.txt", "web.config", "WEB-INF/web.xml",
             "WEB-INF/classes/", "config/database.yml", ".idea/workspace.xml",
             ".vscode/sftp.json", "crossdomain.xml", "phpinfo.php",
             "server-info", "actuator/heapdump", "Druid/index.html",
             "struts/webconsole.html", "struts/devmode.action"]


def build_words(page=None):
    words = list(VCS) + list(FRAMEWORK) + list(EDITOR)
    for p in PREFIXES:
        for s in SUFFIXES:
            words.append((p + s) if p else s.lstrip("."))
    if page:
        base = page.strip("/").rsplit("/", 1)[-1]
        stem = base.rsplit(".", 1)[0]
        words += [f".{base}.swp", f".{base}.swo", f"{base}~", f"{base}.bak",
                  f"{stem}.zip", f"{stem}.tar.gz", f"{stem}.bak"]
    return words


def scan(base, words, timeout=8):
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0 (CTF backup-scan)"
    base = base.rstrip("/") + "/"
    # 软 404 校准
    try:
        cal = s.get(base + "zzz_nonexist_%d" % 0xa71, timeout=timeout,
                    verify=False, allow_redirects=False)
        fake = (cal.status_code, len(cal.content))
    except Exception:
        fake = (None, -1)
    hits = []
    for w in dict.fromkeys(words):
        try:
            r = s.get(base + w.lstrip("/"), timeout=timeout, verify=False,
                      allow_redirects=False, stream=True)
            r.close()
        except Exception:
            continue
        if r.status_code == 200 and not (r.status_code == fake[0]
                                         and abs(len(r.content if hasattr(r, 'content') else b'') - fake[1]) < 16):
            size = r.headers.get("Content-Length", "?")
            print(f"[200] {size:>10}  {w}")
            hits.append((w, size))
        elif r.status_code in (301, 302, 401, 403):
            print(f"[{r.status_code}]            {w}")
    print("\n[*] 命中 .git 时恢复源码:")
    print("    python dirsearch/git-dumper: git-dumper http://t/.git/ out && git log -p")
    print("    手工: wget -r -np http://t/.git/ && git checkout .")
    return hits


def selftest():
    import http.server
    import socketserver
    import threading
    import os
    d = os.path.join(os.environ.get("TEMP", "."), "bak_self")
    os.makedirs(os.path.join(d, ".git"), exist_ok=True)
    open(os.path.join(d, ".git", "HEAD"), "w").write("ref: refs/heads/main\n")
    open(os.path.join(d, "www.zip"), "wb").write(b"PK\x03\x04" + b"\x00" * 100)
    os.chdir(d)
    srv = socketserver.TCPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        hits = scan(f"http://127.0.0.1:{port}/", [".git/HEAD", "www.zip", "nope.zip"])
        names = [h[0] for h in hits]
        assert ".git/HEAD" in names and "www.zip" in names, names
        print("[+] selftest OK")
    finally:
        srv.shutdown()


def main():
    if requests is None:
        print("[!] 请先 pip install requests"); return
    ap = argparse.ArgumentParser(description="备份/源码泄露扫描")
    ap.add_argument("url", nargs="?")
    ap.add_argument("-p", "--page", help="已知页面，如 /index.php，用于生成编辑器备份名")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.url:
        print("[!] 用法: python backup_scan.py http://target/"); return
    scan(a.url, build_words(a.page))


if __name__ == "__main__":
    main()
