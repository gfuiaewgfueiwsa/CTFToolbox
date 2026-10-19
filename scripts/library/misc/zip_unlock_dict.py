# -*- coding: utf-8 -*-
# 脚本名称: ZIP/RAR/7z 压缩包字典爆破 + ZIP 伪加密检测修复
# 方向: Misc（压缩包）
# 简介: 1) 检测并一键修复 ZIP 伪加密（本地文件头/中央目录加密标志位被置位）；
#       2) 对真加密 ZIP 用字典逐口令尝试（zipfile 原生，多线程加速）；
#       RAR/7z 自动调用软件目录或系统中的 7z/UnRAR。
# 用法:
#   python zip_unlock_dict.py archive.zip -w rockyou.txt
#   python zip_unlock_dict.py archive.zip --fix-fake            # 修复伪加密
#   python zip_unlock_dict.py --selftest
# 依赖: ZIP 仅标准库；RAR/7z 需要系统安装 7-Zip（软件 tools/portable/7z 自带）
import argparse
import os
import shutil
import subprocess
import threading
import zipfile

FAKE_MARKS = []


def check_fake_encryption(path):
    """返回 (是否伪加密, 详情)。伪加密：中央目录未加密但本地头置位，或反之。"""
    raw = open(path, "rb").read()
    local_flags = []
    pos = 0
    while True:
        i = raw.find(b"PK\x03\x04", pos)
        if i < 0:
            break
        import struct
        flag = struct.unpack("<H", raw[i + 6:i + 8])[0]
        local_flags.append(flag)
        pos = i + 4
    central_flags = []
    pos = 0
    while True:
        i = raw.find(b"PK\x01\x02", pos)
        if i < 0:
            break
        import struct
        flag = struct.unpack("<H", raw[i + 8:i + 10])[0]
        central_flags.append(flag)
        pos = i + 4
    fake = any(f & 1 for f in local_flags) and not any(f & 1 for f in central_flags)
    return fake, (local_flags, central_flags)


def fix_fake(path, out=None):
    raw = open(path, "rb").read()
    # 清掉所有本地文件头与中央目录头的加密位（bit 0）
    out_bytes = bytearray(raw)
    for mark, off_flag in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        pos = 0
        while True:
            i = out_bytes.find(mark, pos)
            if i < 0:
                break
            flag = out_bytes[i + off_flag]
            out_bytes[i + off_flag] = flag & 0xFE
            pos = i + 4
    out = out or os.path.splitext(path)[0] + "_nofake.zip"
    open(out, "wb").write(out_bytes)
    print("[+] 已清除加密标志位 ->", out)
    return out


def crack_zip(path, wordlist, threads=8):
    zf = zipfile.ZipFile(path)
    names = zf.namelist()
    target = names[0]
    found = [None]
    lock = threading.Lock()
    stop = threading.Event()

    def worker(words):
        for w in words:
            if stop.is_set():
                return
            try:
                zf.extract(target, path=None, pwd=w.encode())
            except Exception:
                continue
            with lock:
                found[0] = w
                stop.set()
                return

    # 分片给线程
    all_words = [w.strip() for w in open(wordlist, encoding="utf-8", errors="replace") if w.strip()]
    chunks = [all_words[i::threads] for i in range(threads)]
    ts = [threading.Thread(target=worker, args=(c,)) for c in chunks]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return found[0]


def crack_7z_family(path, wordlist, bin7z):
    if not bin7z:
        return None
    for w in open(wordlist, encoding="utf-8", errors="replace"):
        w = w.strip()
        r = subprocess.run([bin7z, "t", "-p" + w, path], capture_output=True)
        if r.returncode == 0:
            return w
    return None


def selftest():
    import struct
    d = os.path.join(os.environ.get("TEMP", "."), "zip_self")
    os.makedirs(d, exist_ok=True)
    zp = os.path.join(d, "a.zip")
    with zipfile.ZipFile(zp, "w") as z:
        z.writestr("flag.txt", "flag{zip_dict_ok}")
    raw = bytearray(open(zp, "rb").read())
    i = raw.find(b"PK\x03\x04")
    raw[i + 6] |= 1     # 置位本地头加密标志，制造伪加密
    fake_p = os.path.join(d, "fake.zip")
    open(fake_p, "wb").write(bytes(raw))
    isfake, _ = check_fake_encryption(fake_p)
    assert isfake, "伪加密检测失败"
    fixed = fix_fake(fake_p)
    with zipfile.ZipFile(fixed) as z:
        assert z.read("flag.txt") == b"flag{zip_dict_ok}"
    # 字典爆破真加密
    encp = os.path.join(d, "enc.zip")
    with zipfile.ZipFile(encp, "w") as z:
        z.writestr("f.txt", b"hi", compress_type=zipfile.ZIP_DEFLATED)
    zf = zipfile.ZipFile(encp)
    zf.setpassword(b"123456")
    # 重新用 pyzipper 风格不可得，改用 zipfile 命令加密测试跳过；验证伪加密流程即可
    print("[+] selftest OK（伪加密检测+修复）")


def main():
    ap = argparse.ArgumentParser(description="压缩包字典爆破/伪加密修复")
    ap.add_argument("archive", nargs="?")
    ap.add_argument("-w", "--wordlist")
    ap.add_argument("--fix-fake", action="store_true")
    ap.add_argument("--7z", dest="sevenz", help="7z.exe 路径（RAR/7z 时）")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.archive:
        print("[!] 用法: python zip_unlock_dict.py a.zip -w rockyou.txt"); return
    fake, _ = check_fake_encryption(a.archive) if a.archive.lower().endswith(".zip") else (False, None)
    if fake:
        print("[!] 检测到 ZIP 伪加密！")
        if a.fix_fake:
            fix_fake(a.archive); return
    if a.fix_fake:
        fix_fake(a.archive); return
    if not a.wordlist:
        print("[!] 真加密需要 -w 字典；仅检测伪加密可加 --fix-fake"); return
    if a.archive.lower().endswith(".zip"):
        r = crack_zip(a.archive, a.wordlist)
    else:
        bin7z = a.sevenz or shutil.which("7z") or shutil.which("7za")
        r = crack_7z_family(a.archive, a.wordlist, bin7z)
    print("[+] 密码:", r) if r else print("[-] 字典未命中")


if __name__ == "__main__":
    main()
