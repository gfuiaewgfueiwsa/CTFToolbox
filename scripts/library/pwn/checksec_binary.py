# -*- coding: utf-8 -*-
# 脚本名称: 二进制保护检查（checksec 批量版 + 利用思路提示）
# 方向: Pwn（信息收集）
# 简介: 批量输出 ELF/PE 的保护机制（NX/Canary/PIE/RELRO/Fortify/动态符号），
#       并根据保护组合直接给出推荐利用路线（ret2text/ret2shellcode/
#       ret2libc/格式化字符串/堆利用），辅助快速定题。
# 用法:
#   python checksec_binary.py ./pwn
#   python checksec_binary.py ./bins/ --json out.json
#   python checksec_binary.py --selftest
# 依赖: pip install pwntools
import argparse
import glob
import json
import os


def analyze(path):
    from pwn import ELF
    e = ELF(path, checksec=False)
    info = {
        "file": path,
        "arch": e.arch,
        "bits": e.bits,
        "NX": e.nx,
        "Canary": e.canary,
        "PIE": e.pie,
        "RELRO": e.relro,
        "statically_linked": e.statically_linked,
        "execstack": getattr(e.execstack, "value", e.execstack),
    }
    return info, e


def suggest(info, e=None):
    tips = []
    if not info["NX"]:
        tips.append("NX 未开 -> 可 ret2shellcode（找 rwx 段/mmap，shellcode 放栈/bss）")
    if not info["Canary"]:
        tips.append("无 Canary -> 栈溢出直接覆盖返回地址")
    else:
        tips.append("有 Canary -> 需先泄露 canary（格式化字符串/栈打印）或 fork 逐字节爆破")
    if not info["PIE"]:
        tips.append("无 PIE -> 程序内 gadget/后门地址固定，优先 ret2text/ret2csu/ret2syscall")
    else:
        tips.append("开 PIE -> 需先泄露程序基址（栈上返回地址/libc 旁泄露）")
    if info["RELRO"] and "Full" in str(info["RELRO"]):
        tips.append("Full RELRO -> GOT 只读，改 GOT 不可行，改返回地址/钩子/栈")
    elif info["RELRO"]:
        tips.append("Partial RELRO -> 可考虑 GOT 表覆写（延迟绑定）")
    if info["statically_linked"]:
        tips.append("静态链接 -> 无 libc 泄露，ret2syscall/SROP，gadget 丰富")
    else:
        tips.append("动态链接 -> ret2libc(puts 泄露真实地址)，ret2system/one_gadget")
    if e is not None:
        syms = {k: v for k, v in e.sym.items()
                if k in ("system", "execve", "backdoor", "getshell", "win")}
        if syms:
            tips.append("发现敏感符号: " + ", ".join(f"{k}@{v:#x}" for k, v in syms.items()))
        if b"/bin/sh" in e.data:
            tips.append("程序内含 /bin/sh 字符串")
    return tips


def show(path):
    info, e = analyze(path)
    print("=" * 64)
    for k, v in info.items():
        print(f"  {k:20s}: {v}")
    print("  利用思路:")
    for t in suggest(info, e):
        print("   -", t)
    return info


def selftest():
    import subprocess
    import tempfile
    d = tempfile.mkdtemp()
    variants = {
        "nx_off": (["-z", "execstack", "-no-pie", "-fno-stack-protector"],
                   ["ret2shellcode", "无 Canary"]),
        "full": (["-no-pie", "-fstack-protector"], ["有 Canary"]),
    }
    for name, (flags, expect) in variants.items():
        src = os.path.join(d, name + ".c")
        binp = os.path.join(d, name)
        open(src, "w").write("void vuln(){char b[32];read(0,b,200);}int main(){vuln();}")
        cc = subprocess.run(["gcc"] + flags + ["-o", binp, src],
                            capture_output=True, text=True)
        if cc.returncode != 0:
            print("[-] 需 gcc，跳过:", cc.stderr[:120]); return
        info = show(binp)
        tips_text = " ".join(suggest(info))
        for ex in expect:
            assert ex in tips_text, (ex, tips_text)
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="checksec 批量+利用建议")
    ap.add_argument("target", nargs="?")
    ap.add_argument("--json", dest="js")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.target:
        print("[!] 用法: python checksec_binary.py ./pwn"); return
    paths = [a.target]
    if os.path.isdir(a.target):
        paths = [p for p in glob.glob(a.target + "/*") if os.path.isfile(p)]
    results = []
    for p in paths:
        try:
            results.append(show(p))
        except Exception as ex:
            print(f"[-] {p}: {ex}")
    if a.js:
        json.dump(results, open(a.js, "w"), indent=2, default=str)
        print("[+] 已写", a.js)


if __name__ == "__main__":
    main()
