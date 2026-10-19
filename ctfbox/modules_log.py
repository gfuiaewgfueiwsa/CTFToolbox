# -*- coding: utf-8 -*-
"""Web 访问日志分析（access.log / nginx / apache / IIS 通用文本）。

纯离线、只读分析：统计 IP/URL/UA/状态码，识别 SQL 注入、XSS、命令执行、
文件包含/目录穿越、WebShell 连接、扫描器、文件上传、flag 泄露等。
不包含任何攻击载荷发送能力。
"""
import os
import re
import urllib.parse
from collections import Counter, defaultdict

from .common import Report, Finding, save_text, safe_name, WORKSPACE, scan_flags

LOG_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,39})\s+\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)?\s?(?P<path>.*?)(?:\s+HTTP/[\d.]+)?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>[\d-]+)'
    r'(?:\s+"(?P<referer>.*?)"\s+"(?P<ua>.*?)")?'
)

ATTACK_PATTERNS = [
    ("SQL注入", re.compile(
        r"(union[\s/*]+select|information_schema|sleep\s*\(|benchmark\s*\(|"
        r"load_file\s*\(|into\s+outfile|extractvalue\s*\(|updatexml\s*\(|"
        r"or\s+1\s*=\s*1|'\s*or\s*'?\d|concat\s*\(|0x[0-9a-f]{8,}|sqlmap|"
        r"waitfor\s+delay|char\s*\(\s*\d+\s*,|%20or%20|--\s+-|/\*.*?\*/)", re.I)),
    ("XSS跨站", re.compile(
        r"(<script|javascript:|onerror\s*=|onload\s*=|<img[^>]+src|"
        r"<svg|alert\s*\(|document\.cookie|<iframe|String\.fromCharCode|"
        r"%3cscript|eval\s*\()", re.I)),
    ("命令执行", re.compile(
        r"(;\s*(cat|ls|id|whoami|uname|pwd|ifconfig|ipconfig|ping|wget|curl|nc|bash|sh)\b|"
        r"\|\s*(cat|ls|id|whoami|bash|sh|nc)\b|`[^`]+`|\$\([^)]+\)|"
        r"/bin/(sh|bash)|cmd\.exe|powershell|/etc/init\.d|"
        r"bash\s+-i|nc\s+-[a-z]*e|python\s+-c\s+['\"]|system\s*\(\s*['\"])", re.I)),
    ("文件包含/目录穿越", re.compile(
        r"(\.\./|\.\.%2f|\.\.%5c|/etc/passwd|/etc/shadow|boot\.ini|win\.ini|"
        r"php://filter|php://input|file://|data://|%00|/proc/self/environ|"
        r"c:\\windows\\system32)", re.I)),
    ("WebShell连接", re.compile(
        r"(cmd|exec|command|shell|eval|assert|system|passthru|run|do|func|"
        r"action|payload|x|z0|a)\s*=\s*([a-z0-9+/=]{2,}|[A-Za-z]:|\.\.|"
        r"(?:base64|rot13)|<\?|char|echo|whoami)", re.I)),
    ("危险文件上传/访问", re.compile(
        r"(upload|upfile|uploads?|attachment|attach|/data/|/static/|/images?/|"
        r"/media/|/files?/)[^ ]{0,80}\.(php|phtml|php3|php5|asp|aspx|jsp|jspx|asa|cer)\b|"
        r"\.(php|asp|aspx|jsp)\s*\.\w+|multipart/form-data", re.I)),
    ("敏感文件探测", re.compile(
        r"(/\.git/|/\.svn/|/\.env\b|/web\.config|/WEB-INF/web\.xml|"
        r"/phpinfo\.php|/admin|/manager/html|/console/|/actuator/|"
        r"server-status|/backup|\.(sql|bak|zip|tar|rar|7z|log)(\?|$))", re.I)),
    ("SSRF/协议利用", re.compile(
        r"(gopher://|dict://|ftp://|file://|127\.0\.0\.1|localhost|0\.0\.0\.0|"
        r"169\.254\.169\.254|@[0-9.]+)", re.I)),
    ("XXE", re.compile(r"(<!ENTITY|<!DOCTYPE[^>]+SYSTEM)", re.I)),
    ("模板注入SSTI", re.compile(
        r"(\{\{.*?\}\}|\{%.*?%\}|\$\{.*?\}|#set\s*\(|T(java|Runtime))", re.I)),
]

SCANNER_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|gobuster|wpscan|"
    r"hydra|fuzz|ffuf|wfuzz|havij|awvs|netsparker|qualys|openvas|zgrab|censys|"
    r"python-requests|curl|wget|go-http-client|libwww-perl)", re.I)

SHELL_NAME = re.compile(
    r"(shell|c99|c100|r57|webshell|ma|1\.php|cmd\.php|a\.php|x\.php|eval\.php|"
    r"hack|spy|后门|木马)", re.I)


def _urldecode(s: str) -> str:
    try:
        once = urllib.parse.unquote_plus(s, errors="replace")
        twice = urllib.parse.unquote_plus(once, errors="replace")
        return twice if once != twice else once
    except Exception:
        return s


def analyze_weblog(path: str, report: Report, out_dir: str = None):
    import codecs
    raw = open(path, "rb").read()
    text = None
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            text = raw.decode(enc)
            break
        except Exception:
            continue
    if text is None:
        text = raw.decode("latin-1", "replace")

    lines = [ln for ln in text.splitlines() if ln.strip()]
    entries = []
    for ln in lines:
        m = LOG_RE.search(ln)
        if m:
            d = m.groupdict()
            entries.append(d)
        else:
            # 无法按标准格式解析的行：保留原始 URL 片段做攻击特征扫描
            entries.append({"ip": "-", "time": "-", "method": "", "path": ln,
                            "status": "0", "size": "-", "referer": "", "ua": "", "raw": ln})

    if not entries:
        report.add("warn", "日志解析", "未识别出任何日志条目")
        return

    report.add("info", "日志概览", f"共 {len(entries)} 条请求，成功解析 "
               f"{sum(1 for e in entries if e.get('ip') != '-')} 条")

    ip_cnt = Counter(e.get("ip", "-") for e in entries)
    url_cnt = Counter((e.get("path") or "").split("?")[0] for e in entries)
    ua_cnt = Counter(e.get("ua") or "-" for e in entries)
    status_cnt = Counter(e.get("status", "?") for e in entries)
    report.add("info", "状态码分布", ", ".join(f"{k}:{v}" for k, v in
                                               sorted(status_cnt.items())))
    report.add("info", "Top 15 来源 IP",
               "\n".join(f"{ip:<20} {n}" for ip, n in ip_cnt.most_common(15)))
    report.add("info", "Top 15 访问路径",
               "\n".join(f"{n:>5}  {u[:90]}" for u, n in url_cnt.most_common(15)))

    # 攻击识别
    hits_by_ip = defaultdict(lambda: defaultdict(list))
    scanner_ips = set()
    flag_leaks = []
    for i, e in enumerate(entries):
        url = e.get("path") or ""
        ua = e.get("ua") or ""
        decoded = _urldecode(url)
        line = f"{e.get('ip')} [{e.get('time')}] \"{e.get('method','')} {url}\" " \
               f"{e.get('status')} UA={ua}"
        for label, pat in ATTACK_PATTERNS:
            if pat.search(decoded):
                # WebShell 模式误报较多：要求 URL 里是脚本文件或参数名命中
                if label == "WebShell连接" and not re.search(
                        r"\.(php|asp|aspx|jsp|jspx|asa|cer)(\?|/|$)", decoded):
                    continue
                hits_by_ip[e.get("ip")][label].append((i + 1, decoded[:200]))
        if SCANNER_UA.search(ua):
            scanner_ips.add(e.get("ip"))
        if SHELL_NAME.search(url.split("?")[0]):
            hits_by_ip[e.get("ip")]["可疑WebShell文件名"].append((i + 1, url[:200]))
        if re.search(r"flag|ctf", decoded, re.I) and re.search(r"[\{\}]", decoded):
            flag_leaks.append(line[:200])
        fl = scan_flags(decoded.encode("utf-8", "replace"))
        if fl:
            flag_leaks.extend(fl)

    out_dir = out_dir or os.path.join(WORKSPACE, "log_" + safe_name(os.path.basename(path)))
    os.makedirs(out_dir, exist_ok=True)
    total_attacks = sum(len(v) for d in hits_by_ip.values() for v in d.values())
    if total_attacks:
        report.add("warn", "发现攻击请求",
                   f"共 {total_attacks} 条可疑请求，涉及 {len(hits_by_ip)} 个 IP")
    for ip, cats in sorted(hits_by_ip.items(),
                           key=lambda x: -sum(len(v) for v in x[1].values())):
        summary = ", ".join(f"{cat}×{len(lst)}" for cat, lst in cats.items())
        report.add("warn", f"攻击源 {ip}", summary)
        for cat, lst in list(cats.items())[:3]:
            for ln_no, sample in lst[:2]:
                report.add("info", f"{cat} 样例(行{ln_no})", sample)
    if scanner_ips:
        report.add("warn", "扫描器/工具 UA",
                   f"{len(scanner_ips)} 个 IP 使用扫描器 UA: "
                   + ", ".join(sorted(scanner_ips)[:15]))
    if flag_leaks:
        for fl in sorted(set(flag_leaks))[:10]:
            report.add("flag", "日志中发现 flag 泄露", str(fl))

    # 5xx / 4xx 异常
    srv_err = sum(v for k, v in status_cnt.items() if k.startswith("5"))
    not_found = sum(v for k, v in status_cnt.items() if k == "404")
    if srv_err:
        report.add("info", "服务器错误", f"{srv_err} 次 5xx，可能与攻击/漏洞利用有关")
    if not_found > max(50, len(entries) * 0.3):
        report.add("info", "大量 404", f"{not_found} 次，符合目录扫描/爆破特征")

    # 导出可疑请求明细
    detail = []
    for ip, cats in hits_by_ip.items():
        for cat, lst in cats.items():
            for ln_no, sample in lst:
                detail.append(f"行{ln_no}\t{ip}\t{cat}\t{sample}")
    if detail:
        dst = os.path.join(out_dir, "suspicious_requests.tsv")
        save_text(dst, "\n".join(detail))
        report.add("info", "可疑请求明细已导出", dst, dst)
    dst2 = os.path.join(out_dir, "ip_top.txt")
    save_text(dst2, "\n".join(f"{ip}\t{n}" for ip, n in ip_cnt.most_common()))
    report.add("info", "IP 统计已导出", dst2, dst2)
    return out_dir
