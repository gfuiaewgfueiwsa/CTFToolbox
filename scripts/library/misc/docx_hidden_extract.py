# -*- coding: utf-8 -*-
# 脚本名称: Office(docx/xlsx/pptx) 隐藏内容提取
# 方向: Misc（文档隐写）
# 简介: Office 新格式本质是 ZIP。脚本批量提取：隐藏文字(vanish)、白字、
#       批注、修订、文档属性(作者/最后保存者)、备注、内嵌媒体与 OLE 对象、
#       自定义 XML 部件，并对全部 XML 文本做 flag 扫描。
# 用法:
#   python docx_hidden_extract.py secret.docx
#   python docx_hidden_extract.py secret.xlsx -o out_dir
#   python docx_hidden_extract.py --selftest
# 依赖: 仅标准库（zipfile/re）
import argparse
import os
import re
import zipfile

FLAG_RE = re.compile(r"(?i)(?:flag|ctf|key|secret)\{[^}]{1,200}\}")
TEXT_RE = re.compile(r"<[^>]+>")


def xml_text(xml):
    return TEXT_RE.sub("", xml.decode("utf-8", "replace"))


def run(path, outdir):
    zf = zipfile.ZipFile(path)
    os.makedirs(outdir, exist_ok=True)
    names = zf.namelist()
    print(f"[*] {len(names)} 个部件")
    for n in names:
        low = n.lower()
        data = zf.read(n)
        # 1) 隐藏属性 / 白字 / 批注 / 修订
        if low.endswith(".xml"):
            text = data.decode("utf-8", "replace")
            flags = []
            if 'w:vanish' in text:
                flags.append("含隐藏文字 w:vanish")
            if re.search(r'w:color\s+w:val="(?:FFFFFF|white|auto)"', text, re.I):
                flags.append("含白色字体")
            if "w:ins" in text or "w:del" in text:
                flags.append("含修订痕迹(插入/删除)")
            if "commentReference" in text or low.startswith("word/comments"):
                flags.append("含批注")
            plain = xml_text(data).strip()
            for f in flags:
                print(f"[!] {n}: {f}")
            if plain:
                for m in FLAG_RE.findall(plain):
                    print("[!!!] flag:", m)
                if any(k in f for k in flags) and plain:
                    print(f"    文本: {plain[:300]}")
        # 2) 文档属性
        if low in ("docprops/core.xml", "docprops/app.xml", "docprops/custom.xml"):
            print(f"[属性] {n}:\n    {xml_text(data)[:400]}")
        # 3) 内嵌媒体 / 对象
        if low.startswith(("word/media/", "xl/media/", "ppt/media/")) or \
           low.endswith((".bin", ".emf", ".ole")) or "embeddings" in low:
            dst = os.path.join(outdir, os.path.basename(n))
            open(dst, "wb").write(data)
            print(f"[+] 提取内嵌对象: {n} -> {dst}")
    # 4) 全量 flag 扫描
    for n in names:
        try:
            txt = zf.read(n).decode("utf-8", "ignore")
            for m in FLAG_RE.findall(txt):
                print(f"[!!!] {n} 中发现: {m}")
        except Exception:
            pass


def selftest():
    import io
    d = os.path.join(os.environ.get("TEMP", "."), "office_self")
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "t.docx")
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("[Content_Types].xml", "<x/>")
        z.writestr("word/document.xml",
                   '<?xml version="1.0"?><w:document xmlns:w="w">'
                   '<w:r><w:rPr><w:vanish/></w:rPr><w:t>flag{hidden_in_docx}</w:t></w:r></w:document>')
        z.writestr("docProps/core.xml", "<dc:creator>hacker</dc:creator>")
    run(p, os.path.join(d, "out"))
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="Office 隐藏内容提取")
    ap.add_argument("doc", nargs="?")
    ap.add_argument("-o", "--out")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.doc:
        print("[!] 用法: python docx_hidden_extract.py secret.docx"); return
    out = a.out or os.path.join(os.path.dirname(a.doc) or ".",
                                os.path.splitext(os.path.basename(a.doc))[0] + "_office_out")
    run(a.doc, out)


if __name__ == "__main__":
    main()
