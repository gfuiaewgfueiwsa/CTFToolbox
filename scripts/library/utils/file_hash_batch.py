# -*- coding: utf-8 -*-
# 脚本名称: 批量文件哈希计算 / 完整性校验
# 方向: Util（取证 / 完整性）
# 简介: 递归计算目录下所有文件的 MD5/SHA1/SHA256（或指定算法），
#       可导出清单、按清单校验（报告新增/缺失/改动）、找重复文件。
#       取证固定证据、比对样本、检测篡改时使用。
# 用法:
#   python file_hash_batch.py D:\dir                 # 默认 sha256
#   python file_hash_batch.py D:\dir -a md5 -o list.csv
#   python file_hash_batch.py D:\dir --check list.csv
#   python file_hash_batch.py D:\dir --dupes
#   python file_hash_batch.py --selftest
# 依赖: 仅标准库
import argparse
import csv
import hashlib
import os


def hash_file(path, algo):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def walk(root):
    for base, dirs, files in os.walk(root):
        for n in files:
            yield os.path.join(base, n)


def make_manifest(root, algo, out=None):
    rows = []
    for p in walk(root):
        rel = os.path.relpath(p, root)
        try:
            rows.append((rel, os.path.getsize(p), hash_file(p, algo)))
        except Exception as e:
            print("[!] 跳过", rel, e)
    print(f"[*] 共 {len(rows)} 个文件，算法 {algo}")
    if out:
        with open(out, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["path", "size", algo])
            w.writerows(rows)
        print("[+] 清单已写", out)
    else:
        for rel, size, hv in rows:
            print(f"{hv}  {size:>10d}  {rel}")
    return rows


def check(root, manifest):
    saved = {}
    with open(manifest, encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            algo = [k for k in row if k not in ("path", "size")][0]
            saved[row["path"]] = (row.get("size"), row[algo], algo)
    current = {os.path.relpath(p, root): p for p in walk(root)}
    changed, missing, added = [], [], []
    for rel, (size, hv, algo) in saved.items():
        if rel not in current:
            missing.append(rel); continue
        cur = hash_file(current[rel], algo)
        if cur != hv:
            changed.append(rel)
    for rel in current:
        if rel not in saved:
            added.append(rel)
    print(f"[*] 改动 {len(changed)}，缺失 {len(missing)}，新增 {len(added)}")
    for x in changed: print("  [CHANGED]", x)
    for x in missing: print("  [MISSING]", x)
    for x in added:   print("  [ADDED]  ", x)
    return not (changed or missing)


def dupes(root, algo):
    seen = {}
    for p in walk(root):
        hv = hash_file(p, algo)
        seen.setdefault(hv, []).append(p)
    found = False
    for hv, ps in seen.items():
        if len(ps) > 1:
            found = True
            print(f"[重复 {hv}]")
            for p in ps:
                print("   ", p)
    if not found:
        print("[*] 无重复文件")


def selftest():
    import tempfile
    d = tempfile.mkdtemp()
    open(os.path.join(d, "a.txt"), "w").write("hello")
    sub = os.path.join(d, "sub"); os.makedirs(sub)
    open(os.path.join(sub, "b.txt"), "w").write("world")
    open(os.path.join(sub, "a_copy.txt"), "w").write("hello")
    mf = os.path.join(d, "m.csv")
    rows = make_manifest(d, "md5", mf)
    assert len(rows) == 3
    assert check(d, mf)
    open(os.path.join(d, "a.txt"), "w").write("tampered")
    assert not check(d, mf)
    print("[+] selftest OK（清单/篡改检测正常）")


def main():
    ap = argparse.ArgumentParser(description="批量哈希/完整性校验")
    ap.add_argument("root", nargs="?")
    ap.add_argument("-a", "--algo", default="sha256")
    ap.add_argument("-o", "--out")
    ap.add_argument("--check")
    ap.add_argument("--dupes", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.root:
        print("[!] 用法: python file_hash_batch.py <目录>"); return
    if a.check:
        check(a.root, a.check)
    elif a.dupes:
        dupes(a.root, a.algo)
    else:
        make_manifest(a.root, a.algo, a.out)


if __name__ == "__main__":
    main()
