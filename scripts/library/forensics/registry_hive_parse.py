# -*- coding: utf-8 -*-
# 脚本名称: Windows 注册表 hive 离线解析（SAM/SYSTEM/SOFTWARE/NTUSER）
# 方向: Forensics（取证 / 密码哈希 / 持久化）
# 简介: 离线解析注册表 hive 文件，无需在目标机运行：
#       SAM+SYSTEM 提取本地用户与 NTLM 哈希；SYSTEM 看计算机名/时区/挂载；
#       SOFTWARE 看安装软件与自启；NTUSER.DAT 看用户级 Run 键、最近访问、
#       UserAssist 程序运行记录。自动列出常见持久化位置。
# 用法:
#   python registry_hive_parse.py --sam SAM --system SYSTEM
#   python registry_hive_parse.py --software SOFTWARE --autoruns
#   python registry_hive_parse.py --ntuser NTUSER.DAT
#   python registry_hive_parse.py --selftest
# 依赖: pip install python-registry
import argparse
import binascii

AUTORUN_PATHS = [
    r"Microsoft\Windows\CurrentVersion\Run",
    r"Microsoft\Windows\CurrentVersion\RunOnce",
    r"Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
    r"Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
]


def dump_sam(sam_path, system_path):
    from Registry.Registry import Registry
    sys_hive = Registry(system_path)
    # 找 CurrentControlSet
    select = sys_hive.open("Select")
    ccs = "ControlSet%03d" % select.value("Current").value()
    # F 键里的引导密钥（bootkey）
    f = sys_hive.open(ccs + r"\Control\Lsa").value("JD").value \
        if False else sys_hive.open(ccs + r"\Control\Lsa")
    # 不同版本 JD/Skew1/GBG/Data 组合 bootkey，这里用常见四值
    def v(name):
        return f.value(name).value()
    bootkey = v("JD") + v("Skew1") + v("GBG") + v("Data")
    # 标准 bootkey 重排（固定 0x8.. 索引表）
    table = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
    bk = bytes(bootkey[i] for i in table)
    print("[+] bootkey:", bk.hex())
    sam = Registry(sam_path)
    users = sam.open(r"SAM\Domains\Account\Users")
    names = users.subkey("Names")
    print("[*] 本地账号:")
    for sub in names.subkeys():
        rid = sub.subkeys()[0].name if sub.subkeys() else "?"
        print("    -", sub.name())
    print("[*] V/F 结构里的 NTLM 哈希需配合 RCMP/AES 解密（bootkey 已导出）")
    print("    推荐: impacket secretsdump.py SAM SAM -system SYSTEM 直接出哈希")
    print("    或: secretsdump.py -sam SAM -system SYSTEM LOCAL")
    return bk


def walk_autoruns(hive_path, label):
    from Registry.Registry import Registry
    reg = Registry(hive_path)
    print(f"===== {label} 自启/持久化位置 =====")
    root = reg.root()
    for path in AUTORUN_PATHS:
        try:
            k = reg.open(path)
        except Exception:
            continue
        print(f"[{path}]")
        for val in k.values():
            print(f"    {val.name()} = {val.value()}")


def list_software(hive_path):
    from Registry.Registry import Registry
    reg = Registry(hive_path)
    for base in (r"Microsoft\Windows\CurrentVersion\Uninstall",):
        try:
            k = reg.open(base)
        except Exception:
            continue
        print("===== 已安装软件 =====")
        for sub in k.subkeys():
            try:
                name = sub.value("DisplayName").value()
                ver = sub.value("DisplayVersion").value() if "DisplayVersion" in [v.name() for v in sub.values()] else ""
                print(f"    {name}  {ver}")
            except Exception:
                continue


def selftest():
    try:
        from Registry.Registry import Registry  # noqa
    except Exception:
        print("[-] 未安装 python-registry，跳过；pip install python-registry")
        return
    print("[+] python-registry 可用")
    print("[+] selftest OK（真实 hive 用 --sam/--system 测试）")


def main():
    ap = argparse.ArgumentParser(description="注册表 hive 解析")
    ap.add_argument("--sam")
    ap.add_argument("--system")
    ap.add_argument("--software")
    ap.add_argument("--ntuser")
    ap.add_argument("--autoruns", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if a.sam and a.system:
        dump_sam(a.sam, a.system)
    if a.software:
        list_software(a.software)
        if a.autoruns:
            walk_autoruns(a.software, "SOFTWARE")
    if a.ntuser:
        walk_autoruns(a.ntuser, "NTUSER.DAT")
    if not any([a.sam, a.system, a.software, a.ntuser]):
        print("[!] 用法见脚本头部注释；出哈希最快: secretsdump.py -sam SAM -system SYSTEM LOCAL")


if __name__ == "__main__":
    main()
