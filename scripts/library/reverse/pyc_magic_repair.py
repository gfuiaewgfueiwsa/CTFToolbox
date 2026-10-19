# -*- coding: utf-8 -*-
# 脚本名称: pyc 魔数修复 / 版本识别 / 头部重建
# 方向: Reverse（Python 字节码）
# 简介: pyc 文件头被破坏（magic 被改/前 16 字节缺失）时反编译器无法识别。
#       脚本内置 Python 2.7~3.13 各版本 magic number 表，可：
#       1) 识别当前 pyc magic 对应版本；2) 用指定版本重写 magic；
#       3) 仅给 code object 裸 marshal 数据时补全 16 字节头。
# 用法:
#   python pyc_magic_repair.py task.pyc                 # 识别版本
#   python pyc_magic_repair.py task.pyc --ver 3.8 -o fixed.pyc
#   python pyc_magic_repair.py raw.marshal --ver 3.9 --raw -o fixed.pyc
#   python pyc_magic_repair.py --selftest
# 依赖: 仅标准库（marshal/importlib）
import argparse
import importlib.util
import marshal
import os
import struct
import sys

# magic -> (版本, 说明)；数值为 pyc 头前 2 字节小端整数
MAGICS = {
    425: "2.7", 62211: "3.0", 3180: "3.5", 3350: "3.6", 3390: "3.7",
    3413: "3.8", 3425: "3.8.x", 3439: "3.9", 3495: "3.10", 3531: "3.11",
    3550: "3.11.x", 3571: "3.12", 3592: "3.12.x", 3614: "3.13",
}


def magic_for_version(ver):
    # 当前解释器版本直接取真实 MAGIC_NUMBER，避免表与补丁版本不一致
    cur = "%d.%d" % sys.version_info[:2]
    if ver == cur or cur.startswith(ver):
        return struct.unpack("<H", importlib.util.MAGIC_NUMBER[:2])[0]
    for m, v in MAGICS.items():
        if v.startswith(ver):
            return m
    raise SystemExit(f"[-] 未知版本 {ver}，可用: {sorted(set(MAGICS.values()))}")


def identify(path):
    raw = open(path, "rb").read()
    if len(raw) < 4:
        print("[-] 文件过小"); return
    m = struct.unpack("<H", raw[:2])[0]
    print(f"[*] magic = {m} (0x{m:04x})，后续两字节: {raw[2:4].hex()}")
    print("[+] 版本:", MAGICS.get(m, f"未知（查 importlib._bootstrap_external.MAGIC_NUMBER）"))
    return m


def rebuild(path, ver, raw_marshal=False, out=None):
    m = magic_for_version(ver)
    body = open(path, "rb").read()
    if raw_marshal:
        head = struct.pack("<Hcc", m, b"\r", b"\n") + b"\x00" * 12
    else:
        head = struct.pack("<Hcc", m, b"\r", b"\n") + b"\x00" * 12
        body = body[16:] if len(body) >= 16 else body
    out = out or os.path.splitext(path)[0] + "_fixed.pyc"
    open(out, "wb").write(head + body)
    print("[+] 已重建头部 ->", out)
    # 尝试 marshal 加载验证 code object
    try:
        code = marshal.loads(open(out, "rb").read()[16:])
        print("[+] marshal 解析成功，顶层 code:", code.co_name,
              "，可再用 pycdc/decompyle3/uncompyle6 反编译")
    except Exception as e:
        print("[!] marshal 解析失败（版本不匹配或数据损坏）:", e)


def selftest():
    d = os.path.join(os.environ.get("TEMP", "."), "pyc_self")
    os.makedirs(d, exist_ok=True)
    code = compile("print('flag{pyc_magic_ok}')", "x.py", "exec")
    blob = marshal.dumps(code)
    cur = struct.unpack("<H", importlib.util.MAGIC_NUMBER[:2])[0]
    p = os.path.join(d, "t.pyc")
    open(p, "wb").write(importlib.util.MAGIC_NUMBER + b"\x00" * 12 + blob)
    assert identify(p) == cur
    # 破坏 magic 后修复
    broken = os.path.join(d, "broken.pyc")
    data = bytearray(open(p, "rb").read())
    data[0] = 0x00
    open(broken, "wb").write(data)
    ver = "%d.%d" % sys.version_info[:2]
    rebuild(broken, ver, out=os.path.join(d, "fixed.pyc"))
    f = open(os.path.join(d, "fixed.pyc"), "rb").read()
    assert f[:4] == importlib.util.MAGIC_NUMBER
    print("[+] selftest OK，当前解释器版本", ver)


def main():
    ap = argparse.ArgumentParser(description="pyc magic 修复")
    ap.add_argument("pyc", nargs="?")
    ap.add_argument("--ver")
    ap.add_argument("--raw", action="store_true", help="输入是裸 marshal 数据")
    ap.add_argument("-o", "--out")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.pyc:
        print("[!] 用法: python pyc_magic_repair.py task.pyc"); return
    if a.ver:
        rebuild(a.pyc, a.ver, a.raw, a.out)
    else:
        identify(a.pyc)


if __name__ == "__main__":
    main()
