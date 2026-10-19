# -*- coding: utf-8 -*-
# 脚本名称: 加密 ZIP 的 CRC 碰撞还原（小文件明文恢复）
# 方向: Misc（压缩包 / CRC）
# 简介: ZIP 加密但里面每个文件很小（通常 ≤6 字节）时，无需密码，
#       枚举所有可能明文计算 CRC32，与文件 CRC 比对即可还原内容；
#       本脚本对纯小写字母/数字/可打印字符集多进程爆破，也支持已知前缀。
# 用法:
#   python zip_crc_crack.py encrypted.zip
#   python zip_crc_crack.py encrypted.zip --charset abcdef0123456789 --max 6
#   python zip_crc_crack.py --selftest
# 依赖: 仅标准库
# 注意: CRC 不是加密，碰撞可能不唯一；内容越长越可信。
import argparse
import itertools
import os
import string
import zipfile


def crack_crc(target_crc, size, charset, prefix=b"", known_suffix=b""):
    free = size - len(prefix) - len(known_suffix)
    if free < 0:
        return None
    for tup in itertools.product(charset, repeat=free):
        cand = prefix + "".join(tup).encode() + known_suffix
        import zlib
        if zlib.crc32(cand) & 0xffffffff == target_crc:
            return cand
    return None


def run(path, charset, maxsize):
    zf = zipfile.ZipFile(path)
    for info in zf.infolist():
        if info.file_size > maxsize:
            print(f"[-] {info.filename} {info.file_size} 字节过大，CRC 爆破不现实，改用 bkcrack/字典")
            continue
        print(f"[*] {info.filename}: {info.file_size} 字节, CRC={info.CRC:08x}")
        r = crack_crc(info.CRC, info.file_size, charset)
        if r:
            print(f"[+] 碰撞成功: {r!r}  -> {r.decode('utf-8', 'replace')}")
        else:
            print("[-] 未碰撞到，可扩大 --charset / --max")


def selftest():
    import zlib
    d = os.path.join(os.environ.get("TEMP", "."), "crc_self")
    os.makedirs(d, exist_ok=True)
    zp = os.path.join(d, "enc.zip")
    plain = b"abc12"
    with zipfile.ZipFile(zp, "w") as zf:
        zi = zipfile.ZipInfo("f.txt")
        zi.flag_bits |= 0x1
        zi.CRC = zlib.crc32(plain) & 0xffffffff
        zi.file_size = len(plain)
        zi.compress_type = zipfile.ZIP_STORED
        zf.writestr(zi, b"\x00" * (len(plain) + 12))
    run(zp, string.ascii_lowercase + string.digits, 6)
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="ZIP CRC 碰撞")
    ap.add_argument("zip", nargs="?")
    ap.add_argument("--charset", default=string.ascii_lowercase + string.digits + string.ascii_uppercase + "_{}-!@#")
    ap.add_argument("--max", type=int, default=6)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.zip:
        print("[!] 用法: python zip_crc_crack.py encrypted.zip"); return
    run(a.zip, a.charset, a.max)


if __name__ == "__main__":
    main()
