# -*- coding: utf-8 -*-
# 脚本名称: 多线程端口扫描器（含服务指纹/常见端口）
# 方向: Util / Web（信息收集）
# 简介: TCP connect 扫描，内置 CTF 高频端口表（Web/数据库/中间件/调试端口），
#       多线程、超时可调，开放端口尝试抓 banner 识别服务；支持端口范围与列表。
# 用法:
#   python port_scan.py 10.10.10.10
#   python port_scan.py 10.10.10.10 -p 1-10000 -t 200
#   python port_scan.py 10.10.10.10 -p 22,80,443,3306,6379,8080 --banner
#   python port_scan.py --selftest
# 依赖: 仅标准库
# 注意: 仅扫描授权目标。
import argparse
import concurrent.futures as cf
import socket

COMMON = [
    21, 22, 23, 25, 53, 69, 79, 80, 81, 88, 110, 111, 119, 123, 135, 137,
    138, 139, 143, 161, 389, 443, 445, 465, 512, 513, 514, 587, 623, 636,
    873, 990, 993, 995, 1080, 1099, 1433, 1434, 1521, 1883, 2049, 2181,
    2375, 2376, 2601, 2604, 3000, 3001, 3128, 3306, 3389, 4000, 4040,
    4369, 4443, 4848, 5000, 5432, 5601, 5672, 5900, 5984, 6000, 6379,
    6443, 7001, 7002, 7077, 7180, 7474, 7547, 8000, 8001, 8009, 8010,
    8025, 8060, 8080, 8081, 8088, 8089, 8090, 8161, 8200, 8443, 8500,
    8530, 8649, 8666, 8686, 8787, 8800, 8848, 8888, 8889, 9000, 9001,
    9002, 9009, 9043, 9080, 9090, 9092, 9100, 9200, 9300, 9418, 9443,
    9999, 10000, 10250, 11211, 15672, 15692, 25565, 27017, 27018, 28017,
    32400, 50000, 50070, 50090, 61616, 63791,
]
SERVICE_HINT = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    88: "Kerberos", 110: "POP3", 111: "rpcbind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 873: "rsync",
    1099: "RMI", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 2181: "ZooKeeper",
    2375: "Docker API", 3000: "Grafana/Node", 3128: "Squid", 3306: "MySQL",
    3389: "RDP", 4040: "Spark", 4848: "GlassFish", 5432: "PostgreSQL",
    5601: "Kibana", 5672: "RabbitMQ", 5900: "VNC", 5984: "CouchDB",
    6379: "Redis", 6443: "K8s API", 7001: "WebLogic", 7180: "Cloudera",
    7474: "Neo4j", 8009: "Tomcat AJP", 8080: "HTTP-Alt", 8161: "ActiveMQ",
    8500: "Consul", 8848: "Nacos", 9000: "PHP-FPM/Portainer", 9092: "Kafka",
    9200: "Elasticsearch", 9300: "ES集群", 11211: "Memcached",
    15672: "RabbitMQ管理", 27017: "MongoDB", 50070: "Hadoop NameNode",
}


def parse_ports(spec):
    if not spec:
        return COMMON
    ports = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            ports += range(int(a), int(b) + 1)
        else:
            ports.append(int(part))
    return sorted(set(ports))


def scan_one(host, port, timeout, banner):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        b = b""
        if banner:
            try:
                s.sendall(b"\r\n")
                b = s.recv(128)
            except Exception:
                pass
        return port, b.decode("utf-8", "replace").strip()
    except Exception:
        return None
    finally:
        s.close()


def run(host, ports, threads=100, timeout=1.5, banner=False):
    open_ports = []
    with cf.ThreadPoolExecutor(threads) as ex:
        futs = [ex.submit(scan_one, host, p, timeout, banner) for p in ports]
        for f in cf.as_completed(futs):
            r = f.result()
            if r:
                open_ports.append(r)
    open_ports.sort()
    for port, b in open_ports:
        hint = SERVICE_HINT.get(port, "")
        print(f"[OPEN] {host}:{port:<6d} {hint}  {b[:60]}")
    print(f"[*] {host} 开放 {len(open_ports)} 个端口")
    return open_ports


def selftest():
    import http.server
    import socketserver
    import threading
    srv = socketserver.TCPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        r = run("127.0.0.1", [port, port + 1, port + 2], threads=3, timeout=1)
        assert [x[0] for x in r] == [port], r
        print("[+] selftest OK")
    finally:
        srv.shutdown()


def main():
    ap = argparse.ArgumentParser(description="端口扫描")
    ap.add_argument("host", nargs="?")
    ap.add_argument("-p", "--ports", help="如 1-1000 或 22,80,443")
    ap.add_argument("-t", "--threads", type=int, default=100)
    ap.add_argument("--timeout", type=float, default=1.5)
    ap.add_argument("--banner", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.host:
        print("[!] 用法: python port_scan.py 10.10.10.10 -p 1-10000"); return
    run(a.host, parse_ports(a.ports), a.threads, a.timeout, a.banner)


if __name__ == "__main__":
    main()
