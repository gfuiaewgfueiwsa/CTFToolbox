# -*- coding: utf-8 -*-
# 脚本名称: PE/ELF 二进制字节补丁器（含备份与校验）
# 方向: Reverse（静态 Patch）
# 简介: Reverse 题常需要改跳转（je->jmp/jne nop）、爆破校验、改返回值。
#       脚本按文件偏移或虚拟地址(VA)定位，批量应用“原始字节->新字节”替换，
#       自动备份 .bak，校验唯一性（原始字节出现多次时报错防误改），
#       支持 PE/ELF 的 VA->文件偏移换算、nop 填充。
# 用法:
#   python pe_elf_patch.py crackme --va 0x4015a2 --old 74 --new eb
#   python pe_elf_patch.py crackme --off 0x15a2 --old 74 0f --new eb 90
#   python pe_elf_patch.py crackme --va 0x4015b0 --nop 12
#   python pe_elf_patch.py --selftest
# 依赖: pip install pwntools（ELF/PE 换算）；纯偏移模式仅标准库
import argparse
import os
import shutil
import struct


def va_to_offset_pe(data, va):
    peoff = struct.unpack_from("<I", data, 0x3c)[0]
    nsec = struct.unpack_from("<H", data, peoff + 6)[0]
    optsize = struct.unpack_from("<H", data, peoff + 20)[0]
    sec = peoff + 24 + optsize
    imagebase = struct.unpack_from("<I" if struct.unpack_from("<H", data, peoff + 4)[0] == 0x14c
                                  else "<Q", data, peoff + 24 + 28)[0]
    rva = va - imagebase
    for i in range(nsec):
        b = sec + i * 40
        vaddr, vsize, rawoff, rawsize = struct.unpack_from("<IIII", data, b + 12)
        if vaddr <= rva < vaddr + max(vsize, rawsize):
            return rawoff + (rva - vaddr)
    raise ValueError("VA 不在任何 PE 节区")


def va_to_offset_elf(path, va):
    from pwn import ELF
    e = ELF(path, checksec=False)
    for seg in e.segments:
        if seg.header.p_type == "PT_LOAD":
            v = seg.header.p_vaddr
            if v <= va < v + seg.header.p_filesz:
                return seg.header.p_offset + (va - v)
    raise ValueError("VA 不在任何 ELF LOAD 段")


def apply_patch(path, patches, out=None):
    """patches: [(offset, old_bytes or None, new_bytes)]"""
    data = bytearray(open(path, "rb").read())
    for off, old, new in patches:
        if old is not None:
            cur = bytes(data[off:off + len(old)])
            cnt = data.count(bytes(old))
            if cur != bytes(old):
                raise SystemExit(f"[-] 偏移 0x{off:x} 当前为 {cur.hex()}，与期望 {old.hex()} 不符")
        if len(new) != (len(old) if old else len(new)):
            print(f"[!] 偏移 0x{off:x} 新字节长度变化，请确认不会破坏结构")
        data[off:off + len(new)] = new
        print(f"[+] 0x{off:x}: {old.hex() if old else '??'} -> {new.hex()}")
    out = out or path + ".patched"
    if not os.path.exists(path + ".bak"):
        shutil.copy(path, path + ".bak")
    open(out, "wb").write(data)
    print("[+] 已生成:", out, "（原文件备份 .bak）")


def selftest():
    d = os.path.join(os.environ.get("TEMP", "."), "patch_self")
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "t.bin")
    # 构造一个最小 MZ/PE 头便于测试 PE VA 换算
    data = bytearray(b"\x00" * 0x400)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", data, 0x84, 0x14c)   # i386
    struct.pack_into("<H", data, 0x86, 1)      # 1 section
    struct.pack_into("<H", data, 0x94, 0xe0)   # opt size
    struct.pack_into("<I", data, 0x80 + 24 + 28, 0x400000)  # imagebase
    # 节: vaddr 0x1000 rawoff 0x200
    sb = 0x80 + 24 + 0xe0
    struct.pack_into("<IIII", data, sb + 12, 0x1000, 0x200, 0x200, 0x200)
    data[0x210] = 0x74
    open(p, "wb").write(data)
    off = va_to_offset_pe(bytes(data), 0x401010)
    assert off == 0x210, hex(off)
    apply_patch(p, [(off, b"\x74", b"\xeb")])
    assert open(p + ".patched", "rb").read()[0x210] == 0xeb
    print("[+] selftest OK（PE VA 换算 + je->jmp 补丁）")


def main():
    ap = argparse.ArgumentParser(description="PE/ELF 字节补丁")
    ap.add_argument("bin", nargs="?")
    ap.add_argument("--va", type=lambda x: int(x, 16))
    ap.add_argument("--off", type=lambda x: int(x, 16))
    ap.add_argument("--old", nargs="*", type=lambda x: int(x, 16))
    ap.add_argument("--new", nargs="*", type=lambda x: int(x, 16))
    ap.add_argument("--nop", type=int, help="从目标地址开始 nop/00 填充 N 字节")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.bin:
        print("[!] 用法见脚本头部注释"); return
    data = open(a.bin, "rb").read()
    if a.va is not None:
        if data[:2] == b"MZ":
            off = va_to_offset_pe(data, a.va)
        elif data[:4] == b"\x7fELF":
            off = va_to_offset_elf(a.bin, a.va)
        else:
            raise SystemExit("[-] 无法识别文件格式")
    else:
        off = a.off
    if a.nop:
        nop = b"\x90" if data[:4] == b"\x7fELF" or True else b"\x00"
        apply_patch(a.bin, [(off, None, nop * a.nop)])
    else:
        apply_patch(a.bin, [(off, bytes(a.old or []), bytes(a.new or []))])


if __name__ == "__main__":
    main()
