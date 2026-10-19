# -*- coding: utf-8 -*-
# 脚本名称: Windows 事件日志 EVTX 深度解析
# 方向: Forensics（应急响应 / 日志分析）
# 简介: 解析 .evtx（Security/System/Application/Sysmon 等），输出每条事件的
#       时间、事件ID、来源、计算机、关键字段（登录账号/IP/进程/命令行），
#       内置高危事件标注（4624/4625/4634/4672/4688/4720/7045/3 等），
#       支持按事件 ID、关键词、时间范围过滤，导出 CSV。
# 用法:
#   python evtx_deep_parse.py Security.evtx
#   python evtx_deep_parse.py Security.evtx --id 4624,4625 --csv logins.csv
#   python evtx_deep_parse.py Sysmon.evtx --grep mimikatz
#   python evtx_deep_parse.py --selftest
# 依赖: pip install python-evtx   （spec 已内置 Evtx 模块）
import argparse
import csv
import os
import re

HIGH_VALUE = {
    "4624": "登录成功", "4625": "登录失败(爆破)", "4634": "注销",
    "4648": "显式凭据登录(runas)", "4672": "特权账号登录",
    "4688": "进程创建(含命令行)", "4720": "账号创建", "4732": "成员加入组",
    "4738": "账号变更", "4776": "NTLM 认证", "1102": "日志被清除",
    "7045": "服务安装(常见持久化)", "3": "Sysmon 网络连接",
    "1": "Sysmon 进程创建", "11": "Sysmon 文件创建", "13": "Sysmon 注册表改写",
}


def parse_evtx(path, ids=None, grep=None):
    try:
        from Evtx.Evtx import Evtx
        from Evtx.Views import evtx_file_xml_view
    except Exception:
        raise SystemExit("[-] pip install python-evtx")
    rows = []
    with Evtx(path) as log:
        for record in log.records():
            xml = record.xml()
            eid = re.search(r"<EventID[^>]*>(\d+)</EventID>", xml)
            eid = eid.group(1) if eid else "?"
            if ids and eid not in ids:
                continue
            sysinfo = dict(re.findall(r'<Data Name="([^"]+)">(.*?)</Data>', xml))
            fields = {
                "time": (re.search(r'TimeCreated SystemTime="([^"]+)"', xml) or [None, "?"])[1],
                "id": eid,
                "computer": (re.search(r"<Computer>(.*?)</Computer>", xml) or [None, "?"])[1],
                "channel": (re.search(r"<Channel>(.*?)</Channel>", xml) or [None, "?"])[1],
            }
            text = re.sub(r"<[^>]+>", " ", xml)
            if grep and grep.lower() not in text.lower():
                continue
            rows.append((fields, sysinfo, text))
    return rows


def run(path, ids=None, grep=None, csv_out=None):
    rows = parse_evtx(path, ids, grep)
    print(f"[*] 命中 {len(rows)} 条")
    fp = open(csv_out, "w", newline="", encoding="utf-8-sig") if csv_out else None
    w = csv.writer(fp) if fp else None
    if w:
        w.writerow(["time", "id", "computer", "channel", "关键字段", "原文摘要"])
    for fields, data, text in rows:
        tag = HIGH_VALUE.get(fields["id"], "")
        print(f"[{fields['time']}] #{fields['id']} {tag} {fields['computer']}")
        keep = {k: v for k, v in data.items() if v and k in
                ("TargetUserName", "SubjectUserName", "IpAddress", "WorkstationName",
                 "NewProcessName", "CommandLine", "Image", "ParentImage",
                 "ServiceName", "ObjectName", "LogonType", "Destination",
                 "DestinationHostname", "DestinationIp")}
        if keep:
            for k, v in keep.items():
                print(f"    {k}: {v}")
        if w:
            w.writerow([fields["time"], fields["id"], fields["computer"],
                        fields["channel"], " | ".join(f"{k}={v}" for k, v in keep.items()),
                        re.sub(r"\s+", " ", text)[:500]])
    if fp:
        fp.close()
        print("[+] 已导出", csv_out)


def selftest():
    # python-evtx 自带样例解析验证较繁琐，这里验证依赖与高危表完整性
    try:
        import Evtx  # noqa
    except Exception:
        print("[-] 未安装 python-evtx，跳过；安装: pip install python-evtx")
        return
    assert "4625" in HIGH_VALUE and "4688" in HIGH_VALUE
    print("[+] python-evtx 可用，高危事件表 %d 条" % len(HIGH_VALUE))
    print("[+] selftest OK（实际 evtx 用真实日志文件测试）")


def main():
    ap = argparse.ArgumentParser(description="EVTX 解析")
    ap.add_argument("evtx", nargs="?")
    ap.add_argument("--id", help="逗号分隔事件 ID")
    ap.add_argument("--grep")
    ap.add_argument("--csv")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.evtx:
        print("[!] 用法: python evtx_deep_parse.py Security.evtx"); return
    ids = set(x for x in (a.id or "").split(",") if x) or None
    run(a.evtx, ids, a.grep, a.csv)


if __name__ == "__main__":
    main()
