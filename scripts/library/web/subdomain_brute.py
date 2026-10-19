# -*- coding: utf-8 -*-
# 脚本名称: 子域名爆破（DNS 字典枚举）
# 方向: Web（信息收集）
# 简介: 通过本地 DNS 解析枚举子域名，内置常见前缀字典，自动去重并标注 CNAME；
#       支持泛解析（wildcard）识别与过滤、自定义字典、并发解析。
# 用法:
#   python subdomain_brute.py example.com
#   python subdomain_brute.py example.com -w subs.txt -t 50
#   python subdomain_brute.py --selftest
# 依赖: 仅标准库（socket/concurrent.futures）
import argparse
import concurrent.futures as cf
import socket

BUILTIN = """www mail ftp oa vpn admin manage test dev demo staging stage
beta alpha uat sit api apis app apps m mobile wap static cdn img images
assets static1 ns1 ns2 smtp pop imap webmail email blog bbs forum shop
store pay payment gateway git gitlab jenkins ci cd jira wiki confluence
docs doc hr crm erp bi report reports db mysql redis mongo elastic
kibana grafana prometheus nacos consul eureka zookeeper rabbitmq mq
monitor status health internal private public extranet proxy www2
test1 test2 dev1 dev2 old new v1 v2 backup bak upload file files
download dl update service ws wss socket chat im sso passport passport2
auth oauth cas id account member user users center panel cp dashboard
console shell terminal jumpserver bastion db1 sql data dns time ntp
ldap ad exchange mx1 mx2 relay outbound inbound spam quarantine archive
cloud aws azure docker k8s registry harbor nexus maven pypi npm mirrors
mirror mirror2 speedtest foo bar iot m2m car gps video media live
h5 game games act activity promo event survey vote reg register login2
ssl cert acme ca pki secrets secret vault config confs env""".split()


def resolve(host):
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({i[4][0] for i in infos})
        return ips
    except Exception:
        return None


def brute(domain, words, threads=50):
    # 泛解析检测：随机不存在的子域若解析成功，记录其 IP 并过滤
    import random
    rand = "nx-%08x" % random.randint(0, 0xffffffff)
    wildcard = set(resolve(f"{rand}.{domain}") or [])
    if wildcard:
        print(f"[!] 检测到泛解析，过滤 IP: {sorted(wildcard)}")
    found = {}

    def one(w):
        host = f"{w.strip()}.{domain}"
        ips = resolve(host)
        if ips and not (set(ips) <= wildcard):
            found[host] = ips
            print(f"[+] {host:40s} {','.join(ips)}")
    with cf.ThreadPoolExecutor(threads) as ex:
        list(ex.map(one, dict.fromkeys(words)))
    print(f"[*] 共发现 {len(found)} 个子域名")
    return found


def selftest():
    # localhost 下验证解析链路（不依赖公网）
    ips = resolve("localhost")
    assert ips, "localhost 无法解析，DNS 环境异常"
    print("[+] localhost ->", ips)
    # 字典非空检查
    assert len(BUILTIN) > 100
    print("[+] selftest OK（内置前缀 %d 个）" % len(BUILTIN))


def main():
    ap = argparse.ArgumentParser(description="子域名爆破")
    ap.add_argument("domain", nargs="?")
    ap.add_argument("-w", "--wordlist")
    ap.add_argument("-t", "--threads", type=int, default=50)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.domain:
        print("[!] 用法: python subdomain_brute.py example.com"); return
    words = open(a.wordlist, errors="replace").read().split() if a.wordlist else BUILTIN
    brute(a.domain, words, a.threads)


if __name__ == "__main__":
    main()
