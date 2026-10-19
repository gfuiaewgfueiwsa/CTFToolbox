# -*- coding: utf-8 -*-
# 脚本名称: PDF 隐藏内容提取（JS/URI/动作/附件/表单/隐藏文本层）
# 方向: Misc（文档隐写）
# 简介: 不依赖第三方库，直接解析 PDF 对象，提取：JavaScript、OpenAction、
#       URI 链接、嵌入式文件（/EmbeddedFile）、表单字段、注释、元数据，
#       以及各内容流里的文本绘制操作符 Tj/TJ 中的 flag；并把附件落盘。
# 用法:
#   python pdf_hidden_extract.py secret.pdf
#   python pdf_hidden_extract.py secret.pdf -o out_dir
#   python pdf_hidden_extract.py --selftest
# 依赖: 仅标准库（zlib 解压 FlateDecode 流）
import argparse
import os
import re
import zlib

FLAG_RE = re.compile(r"(?i)(?:flag|ctf|key|secret)\{[^}]{1,200}\}")


def streams(raw):
    """迭代 (stream 在文件中的起始偏移, 原始字节, 解码后字节或原始)。"""
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", raw, re.S):
        body = m.group(1)
        try:
            yield m.start(), body, zlib.decompress(body)
        except Exception:
            yield m.start(), body, body


def extract_pdf_text(decoded):
    """提取 Tj/TJ 文本操作符中的可见字符串。"""
    out = []
    for m in re.finditer(rb"\((.*?)\)\s*Tj", decoded, re.S):
        out.append(m.group(1))
    for m in re.finditer(rb"\[(.*?)\]\s*TJ", decoded, re.S):
        for s in re.findall(rb"\((.*?)\)", m.group(1), re.S):
            out.append(s)
    return b" ".join(out)


def run(path, outdir):
    raw = open(path, "rb").read()
    os.makedirs(outdir, exist_ok=True)
    print(f"[*] PDF 大小 {len(raw)}")
    # 元数据
    for key in (b"/Title", b"/Author", b"/Subject", b"/Keywords", b"/Creator", b"/Producer"):
        m = re.search(key + rb"\s*\((.*?)\)", raw, re.S)
        if m:
            print(f"[属性] {key.decode()[1:]}: {m.group(1).decode('utf-8','replace')[:200]}")
    # JS / 动作 / URI
    for pat, name in ((rb"/JavaScript\s*\((.*?)\)", "JavaScript(字面量)"),
                      (rb"/JS\s*\((.*?)\)", "JS"),
                      (rb"/URI\s*\((.*?)\)", "URI"),
                      (rb"/OpenAction", "OpenAction(打开即执行)"),
                      (rb"/EmbeddedFile", "嵌入式文件"),
                      (rb"/JavaScript", "JavaScript 引用")):
        for m in re.finditer(pat, raw, re.S):
            print(f"[!] 发现 {name}: {m.group(1)[:200] if m.groups() else b''!r}")
    # 表单与注释
    fields = re.findall(rb"/T\s*\((.*?)\)", raw)
    if fields:
        print("[*] 表单字段/注释标题:", [f.decode("utf-8", "replace") for f in fields[:30]])
    # 内容流文本与 flag
    for i, (soff, body, dec) in enumerate(streams(raw)):
        text = extract_pdf_text(dec)
        if text:
            t = text.decode("utf-8", "replace")
            if t.strip():
                print(f"[文本流 {i}] {t[:300]}")
        scan = dec.decode("latin-1", "replace")
        for m in FLAG_RE.findall(scan):
            print(f"[!!!] 流 {i} 中 flag: {m}")
        # JS 流落盘（流对象字典在 stream 关键字之前）
        if b"JavaScript" in raw[max(0, soff - 500):soff + 50]:
            dst = os.path.join(outdir, f"stream_{i}.js")
            open(dst, "wb").write(dec)
            print("[+] JS 流已导出:", dst)
    # 嵌入式文件：扫描 /EF /F 与 file 内容流（启发式：导出所有含 EmbeddedFile 附近流）
    idx = 0
    for m in re.finditer(rb"/EmbeddedFile", raw):
        tail = raw[m.end():m.end() + 400]
        sm = re.search(rb"stream\r?\n(.*?)\r?\nendstream", tail, re.S)
        if sm:
            payload = sm.group(1)
            try:
                payload = zlib.decompress(payload)
            except Exception:
                pass
            dst = os.path.join(outdir, f"embedded_{idx}.bin")
            open(dst, "wb").write(payload)
            print("[+] 附件已导出:", dst)
            idx += 1


def selftest():
    d = os.path.join(os.environ.get("TEMP", "."), "pdf_self")
    os.makedirs(d, exist_ok=True)
    content = b"BT /F1 12 Tf 100 700 Td (flag{inside_pdf_stream}) Tj ET"
    comp = zlib.compress(content)
    objs = [b"%PDF-1.4\n",
            b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n",
            b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n",
            b"3 0 obj<</Type/Page/Parent 2 0 R/Contents 4 0 R>>endobj\n",
            b"4 0 obj<</Length " + str(len(comp)).encode() + b"/Filter/FlateDecode>>stream\n"
            + comp + b"\nendstream endobj\n",
            b"trailer<</Root 1 0 R>>\n%%EOF"]
    p = os.path.join(d, "t.pdf")
    open(p, "wb").write(b"".join(objs))
    run(p, os.path.join(d, "out"))
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="PDF 隐藏内容提取")
    ap.add_argument("pdf", nargs="?")
    ap.add_argument("-o", "--out")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.pdf:
        print("[!] 用法: python pdf_hidden_extract.py secret.pdf"); return
    out = a.out or os.path.join(os.path.dirname(a.pdf) or ".",
                                os.path.splitext(os.path.basename(a.pdf))[0] + "_pdf_out")
    run(a.pdf, out)


if __name__ == "__main__":
    main()
