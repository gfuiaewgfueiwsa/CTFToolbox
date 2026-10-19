# -*- coding: utf-8 -*-
"""逆向/Pwn 分析：PE/ELF 信息、查壳、节区熵、敏感 API、checksec、UPX 脱壳、入口反汇编。"""
import os
import re
import time
import struct
import subprocess
from .common import Finding, Report, scan_flags, shannon_entropy, WORKSPACE

PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX",
    ".themida": "Themida", ".winlice": "Themida/WinLicense",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect",
    ".aspack": "ASPack", ".adata": "ASPack",
    ".petite": "Petite", ".nsp0": "NsPack", ".nsp1": "NsPack",
    ".mpress1": "MPRESS", ".mpress2": "MPRESS",
    ".enigma1": "Enigma", ".enigma2": "Enigma",
    ".boom": "可疑壳(PECompact?)", ".pec1": "PECompact", "pec2": "PECompact",
    "yp0j": "Yodas Protector", ".charmve": "潜在壳",
    ".kkrunchy": "kkrunchy", ".mackt": "ImpREC痕迹",
}
SENSITIVE_APIS = [
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "OutputDebugString", "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
    "ReadProcessMemory", "CreateRemoteThread", "LoadLibrary", "GetProcAddress",
    "CreateProcess", "ShellExecute", "WinExec", "URLDownloadToFile",
    "InternetOpen", "socket", "connect", "bind", "recv", "send",
    "CryptEncrypt", "CryptDecrypt", "RegSetValue", "CreateService",
    "SetWindowsHookEx", "DeviceIoControl",
]

def _upx_tool():
    from .toolsmgr import get_tool
    return get_tool("upx")

PE_LARGE = 30 * 1024 * 1024     # 超过 30MB 的 PE 走快速解析（编译器/运行时巨型 DLL 可上百 MB）

def analyze_pe(path, report: Report, outdir: str):
    import pefile
    fsize = os.path.getsize(path)
    large = fsize > PE_LARGE
    try:
        if large:
            # fast_load 后只解析逆向所需目录：导入(1)/TLS(9)/COM(14)，跳过巨大的导出/重定位/资源表
            pe = pefile.PE(path, fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"],
            ])
            report.add("info", "大文件快速模式",
                       f"文件 {fsize/1e6:.0f}MB，已跳过导出表/资源/重定位等重目录的全量解析；"
                       f"完整查看请用 DIE/Ghidra（工具中心）")
        else:
            pe = pefile.PE(path, fast_load=False)
    except Exception as e:
        report.add("warn", "PE 解析失败", str(e))
        return
    mach = {0x14c: "x86(32位)", 0x8664: "x64(64位)", 0x1c0: "ARM",
            0xaa64: "ARM64", 0x1c4: "ARMv7-NT"}.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
    ts = pe.FILE_HEADER.TimeDateStamp
    ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts)) if 0 < ts < 0x80000000 else str(ts)
    sub = {2: "GUI", 3: "控制台"}.get(pe.OPTIONAL_HEADER.Subsystem, str(pe.OPTIONAL_HEADER.Subsystem))
    chars = pe.FILE_HEADER.Characteristics
    is_dll = bool(chars & 0x2000)
    dotnet = hasattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR") and pe.DIRECTORY_ENTRY_COM_DESCRIPTOR is not None
    report.add("info", "PE 基本信息",
               f"架构: {mach}\n编译时间(UTC): {ts_str}\n入口点(RVA): 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}\n"
               f"镜像基址: 0x{pe.OPTIONAL_HEADER.ImageBase:x}\n子系统: {sub}\n"
               f"类型: {'DLL' if is_dll else 'EXE'}\n.NET: {'是' if dotnet else '否'}")

    # 节区
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    sec_lines = []
    packer_hits = set()
    ep_sec = None
    # 大文件不全量读入（re 在 mmap 上会退化到极慢）；PDB 路径只扫头/尾分区
    if large:
        raw = b""
        with open(path, "rb") as f:
            f.seek(0)
            head = f.read(2 * 1024 * 1024)
            f.seek(max(0, fsize - 8 * 1024 * 1024))
            tail = f.read()
        pdb_zone = head + b"\n" + tail
    else:
        raw = open(path, "rb").read()
        pdb_zone = raw
    for s in pe.sections:
        nm = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
        data = s.get_data(length=200000)   # 熵只需头部样本，不提取整节（巨型节可达数十 MB）
        ent = shannon_entropy(data[:200000])
        perms = ("R" if s.Characteristics & 0x40000000 else "-") + \
                ("W" if s.Characteristics & 0x80000000 else "-") + \
                ("X" if s.Characteristics & 0x20000000 else "-")
        sec_lines.append(f"{nm:10s} VA=0x{s.VirtualAddress:08x} VSize=0x{s.Misc_VirtualSize:08x} "
                         f"Raw=0x{s.SizeOfRawData:08x} 熵={ent:.2f} {perms}")
        key = nm.lower()
        if key in PACKER_SECTIONS and PACKER_SECTIONS[key]:
            packer_hits.add(PACKER_SECTIONS[key])
        if s.VirtualAddress <= ep < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            ep_sec = (nm, ent)
    report.add("info", "节区表", "\n".join(sec_lines))
    if ep_sec:
        report.add("info", "入口点所在节", f"{ep_sec[0]}，该节熵={ep_sec[1]:.2f}")
        if ep_sec[1] > 7.2:
            packer_hits.add("入口节高熵(疑似加壳/加密)")

    # 导入表
    dlls, apis = [], []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("latin-1", "replace")
            dlls.append(dll)
            for imp in entry.imports:
                if imp.name:
                    nm = imp.name.decode("latin-1", "replace")
                    if any(k.lower() in nm.lower() for k in SENSITIVE_APIS):
                        apis.append(f"{dll}!{nm}")
    report.add("info", "导入 DLL", ", ".join(dlls)[:1500] or "无导入表(加壳特征)")
    if not dlls:
        packer_hits.add("无导入表")
    if apis:
        report.add("info", "敏感/特征 API", "\n".join(sorted(set(apis)))[:2000])

    # TLS 回调（仅当回调表非空才提示，MinGW 默认的空 TLS 目录不算反调试）
    if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS:
        tls = pe.DIRECTORY_ENTRY_TLS.struct
        try:
            cb_rva = tls.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
            is64 = pe.FILE_HEADER.Machine == 0x8664
            raw_cb = pe.get_data(cb_rva, 8 if is64 else 4)
            first_cb = struct.unpack("<Q" if is64 else "<I", raw_cb)[0]
            if first_cb:
                report.add("warn", "存在 TLS 回调（常见反调试手段）",
                           f"AddressOfCallBacks=0x{tls.AddressOfCallBacks:x}, 首个回调=0x{first_cb:x}")
        except Exception:
            pass

    # PDB（大文件只在头/尾分区搜索，避免全文件正则）
    for m in re.finditer(rb"[ -~]{4,}\.pdb", pdb_zone):
        report.add("info", "PDB 路径", m.group().decode("latin-1"))
        break

    # .NET
    if dotnet:
        report.add("info", ".NET 程序集", "建议用 dnSpy/ILSpy 反编译（工具中心可下载 dnSpy）")

    if packer_hits:
        report.add("warn", "查壳结论", "命中特征: " + ", ".join(sorted(packer_hits)))
        if "UPX" in packer_hits:
            upx = _upx_tool()
            if upx:
                fp = os.path.join(outdir, "unpacked_upx_" + os.path.basename(path))
                r = subprocess.run([upx, "-d", path, "-o", fp, "-f"],
                                   capture_output=True, timeout=120)
                if r.returncode == 0 and os.path.exists(fp):
                    report.add("ok", "UPX 脱壳成功", fp)
                    report.extracted.append(fp)
                else:
                    report.add("warn", "UPX 脱壳失败",
                               (r.stdout + r.stderr).decode("latin-1", "replace")[:300])
            else:
                report.add("warn", "检测到 UPX 但未安装 UPX 工具", "工具中心可一键下载")
    else:
        report.add("ok", "查壳结论", "未发现常见壳特征（仍建议用 DIE 复核）")

    # 入口反汇编
    _disasm_ep(pe, raw, report, machine=pe.FILE_HEADER.Machine, is_elf=False)

def analyze_elf(path, report: Report, outdir: str):
    from elftools.elf.elffile import ELFFile
    with open(path, "rb") as f:
        elf = ELFFile(f)
        arch = elf.get_machine_arch()
        etype = elf.header["e_type"]
        entry = elf.header["e_entry"]
        is64 = elf.elfclass == 64
        report.add("info", "ELF 基本信息",
                   f"架构: {arch} ({'64位' if is64 else '32位'})\n类型: {etype}\n入口点: 0x{entry:x}\n"
                           f"小端: {elf.little_endian}")

        # checksec
        nx = pie = canary = relro_full = relro_partial = fortify = False
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_GNU_STACK":
                nx = not bool(seg["p_flags"] & 1)
            if seg["p_type"] == "PT_GNU_RELRO":
                relro_partial = True
        pie = etype == "ET_DYN"
        sym_names = set()
        for secname in (".dynsym", ".symtab"):
            sec = elf.get_section_by_name(secname)
            if sec:
                for sym in sec.iter_symbols():
                    sym_names.add(sym.name)
        canary = "__stack_chk_fail" in sym_names
        fortify = any(n.endswith("_chk") for n in sym_names)
        # BIND_NOW
        dyn = elf.get_section_by_name(".dynamic")
        if dyn:
            for tag in dyn.iter_tags():
                if tag.entry.d_tag in ("DT_BIND_NOW", "DF_BIND_NOW") or \
                   (tag.entry.d_tag == "DT_FLAGS" and getattr(tag.entry, "d_val", 0) & 8):
                    relro_full = True
        report.add("ok", "Checksec 保护机制",
                   f"NX/DEP: {'开启' if nx else '关闭(可执行栈)'}\n"
                   f"PIE: {'开启' if pie else '关闭(固定基址)'}\n"
                   f"Canary: {'开启' if canary else '关闭'}\n"
                   f"RELRO: {'Full' if relro_full and relro_partial else ('Partial' if relro_partial else '关闭')}\n"
                   f"FORTIFY: {'是' if fortify else '否'}")
        if not nx:
            report.add("info", "Pwn 提示", "栈可执行，考虑 shellcode 题")
        if not canary and not pie:
            report.add("info", "Pwn 提示", "无 Canary 且无 PIE，经典栈溢出配置，ret2text/ret2shellcode 优先")

        sec_lines = []
        for sec in elf.iter_sections():
            if sec["sh_size"] > 0 and sec.name in (".text", ".data", ".bss", ".rodata", ".init_array", ".fini_array", ".got", ".got.plt", ".plt"):
                sec_lines.append(f"{sec.name:14s} addr=0x{sec['sh_addr']:08x} size=0x{sec['sh_size']:x}")
        report.add("info", "关键节区", "\n".join(sec_lines))
        interesting = [s for s in sorted(sym_names)
                       if any(k in s for k in ("system", "execve", "gets", "strcpy", "sprintf", "backdoor", "flag", "win", "shell"))]
        if interesting:
            report.add("ok", "危险/关键符号", "\n".join(interesting[:50]))

    with open(path, "rb") as f:
        raw = f.read()
    _disasm_ep(None, raw, report, machine=arch, is_elf=True, entry=entry, is64=is64)

def _disasm_ep(pe, raw, report, machine=None, is_elf=False, entry=None, is64=True):
    try:
        import capstone
    except Exception:
        return
    try:
        if is_elf:
            md = capstone.Cs(capstone.CS_ARCH_X86 if "x86" in str(machine) or "64" in str(machine) else capstone.CS_ARCH_ARM,
                             capstone.CS_MODE_64 if is64 else capstone.CS_MODE_32)
            # 简单按文件偏移≈VA在 .text 起点反汇编（仅预览）
            from elftools.elf.elffile import ELFFile
            import io
            elf = ELFFile(io.BytesIO(raw))
            text = elf.get_section_by_name(".text")
            if text:
                code = text.data()[:200]
                base = text["sh_addr"]
                lines = [f"0x{a:x}: {mn} {op}" for a, _sz, mn, op in md.disasm_lite(code, base)][:20]
                report.add("info", ".text 反汇编预览", "\n".join(lines))
        else:
            mode = capstone.CS_MODE_64 if machine == 0x8664 else capstone.CS_MODE_32
            md = capstone.Cs(capstone.CS_ARCH_X86, mode)
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            base = pe.OPTIONAL_HEADER.ImageBase + ep
            try:
                code = pe.get_data(ep, 200)   # 按 RVA 直接取，不依赖全量 raw（支持大文件）
            except Exception:
                off = pe.get_offset_from_rva(ep)
                code = raw[off:off + 200]
            lines = [f"0x{a:x}: {mn} {op}" for a, _sz, mn, op in md.disasm_lite(code, base)][:20]
            report.add("info", "入口点反汇编预览", "\n".join(lines))
    except Exception as e:
        report.add("info", "反汇编预览跳过", str(e)[:200])

def analyze(path, report: Report, ftype: str, outdir: str):
    with open(path, "rb") as f:
        head = f.read(4)
    if head == b"MZ" or ftype.startswith("PE"):
        analyze_pe(path, report, outdir)
    elif head == b"\x7fELF" or ftype.startswith("ELF"):
        analyze_elf(path, report, outdir)
    else:
        report.add("info", "二进制分析", "非 PE/ELF，输出熵与字符串")
