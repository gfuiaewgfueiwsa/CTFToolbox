# -*- coding: utf-8 -*-
# 脚本名称: angr 符号执行求解模板（自动求 flag / 绕过校验）
# 方向: Reverse（符号执行）
# 简介: 对“输入正确才打印 Correct/You win”的校验型 crackme，用 angr 符号化输入，
#       find 成功分支地址、avoid 失败分支地址，自动求解满足约束的输入。
#       给出标准模板（scanf/read/gets 输入、长度、字符集约束）与常见报错处理。
# 用法:
#   1) IDA/Ghidra 找到 main 与成功/失败分支地址（0x401xxx）；
#   2) 修改下面 FIND_ADDR / AVOID_ADDR / INPUT_LEN；
#   3) python angr_solver_template.py ./crackme
#   python angr_solver_template.py --selftest
# 依赖: pip install angr（angr 体积大，建议在 Kali/WSL 装；未安装时仅语法可用）
# 参考: https://docs.angr.io/
import argparse
import string
import sys


def solve(binpath, find_addr, avoid_addrs, input_len, start_addr=None,
          stdin_flag=True, charset=None):
    import angr
    import claripy

    proj = angr.Project(binpath, auto_load_libs=True)
    # 符号化输入
    arg = claripy.BVS("flag", input_len * 8)
    if stdin_flag:
        state = proj.factory.entry_state(stdin=angr.SimFile("/dev/stdin", content=arg))
    else:
        # argv[1] 形式: ./crackme <flag>
        state = proj.factory.full_init_state(args=[binpath, arg])

    # 字符集约束：可打印 ASCII，提高求解速度与可读性
    if charset is None:
        charset = string.printable.strip()
    for i in range(input_len):
        ch = arg.get_byte(i)
        state.solver.add(ch >= 0x20, ch <= 0x7e)

    simgr = proj.factory.simulation_manager(state)
    if start_addr:
        # 从指定地址开始（跳过复杂初始化）
        pass
    print(f"[*] find={hex(find_addr)} avoid={[hex(a) for a in avoid_addrs]}")
    simgr.explore(find=find_addr, avoid=avoid_addrs)
    if not simgr.found:
        print("[-] 未找到满足路径，尝试：放宽 avoid、检查地址是否在 plt 后、加大长度")
        print("    deadended:", len(simgr.deadended), "active:", len(simgr.active))
        return None
    found = simgr.found[0]
    if stdin_flag:
        out = found.solver.eval(arg, cast_to=bytes)
    else:
        out = found.solver.eval(arg, cast_to=bytes)
    print("[+] 求解输入:", out)
    return out


# ======================================================================
# 实战时主要改这一段
# ======================================================================
CONFIG = {
    "find": 0x401234,        # 打印 Correct/成功的基本块地址
    "avoid": [0x401250],     # 打印 Wrong/失败的地址，可多个
    "len": 32,               # flag 长度（不确定时先给大值再裁剪）
}


def selftest():
    try:
        import angr  # noqa
    except Exception:
        print("[-] 未安装 angr（pip install angr），模板语法自检跳过实际执行")
        return
    import os
    import subprocess
    import tempfile
    d = tempfile.mkdtemp()
    src = os.path.join(d, "c.c")
    binp = os.path.join(d, "crackme")
    # 一个简单校验：输入前 5 字符等于 "angr{" 才 success
    open(src, "w").write(r'''
#include <stdio.h>
#include <string.h>
int main(){
  char b[64]; int n=read(0,b,63);
  if(n>=5 && b[0]=='a'&&b[1]=='n'&&b[2]=='g'&&b[3]=='r'&&b[4]=='{'){
    puts("Correct!"); return 0;
  }
  puts("Wrong"); return 1;
}
''')
    cc = subprocess.run(["gcc", "-no-pie", "-o", binp, src], capture_output=True, text=True)
    if cc.returncode != 0:
        print("[-] 需 gcc，跳过:", cc.stderr[:120]); return
    # 用符号/字符串地址定位 find/avoid
    from pwn import ELF
    e = ELF(binp, checksec=False)
    # 直接在二进制里找 "Correct!" 引用较繁琐，这里用 main 内地址由 angr 探索成功路径
    # 简化：find 一个 puts("Correct!") 调用后的地址——用 explore 到输出 Correct 的状态
    import angr
    proj = angr.Project(binp)
    arg = proj.factory.cc().arg if False else None
    flag = angr.claripy.BVS("f", 32 * 8)
    st = proj.factory.entry_state(stdin=angr.SimFile("/dev/stdin", content=flag))
    for i in range(32):
        st.solver.add(flag.get_byte(i) >= 0x20, flag.get_byte(i) <= 0x7e)
    sm = proj.factory.simulation_manager(st)
    sm.explore(find=lambda s: b"Correct!" in s.posix.dumps(1),
               avoid=lambda s: b"Wrong" in s.posix.dumps(1))
    assert sm.found, "angr 未找到"
    out = sm.found[0].solver.eval(flag, cast_to=bytes)
    assert out.startswith(b"angr{"), out
    print("[+] selftest OK，求解:", out[:16])


def main():
    ap = argparse.ArgumentParser(description="angr 求解模板")
    ap.add_argument("bin", nargs="?")
    ap.add_argument("--find", type=lambda x: int(x, 16))
    ap.add_argument("--avoid", type=lambda x: [int(i, 16) for i in x.split(",")], default=[])
    ap.add_argument("--len", type=int, default=CONFIG["len"])
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.bin:
        print("[!] 用法: python angr_solver_template.py ./crackme --find 0x401234 --avoid 0x401250")
        return
    solve(a.bin, a.find or CONFIG["find"], a.avoid or CONFIG["avoid"], a.len)


if __name__ == "__main__":
    main()
