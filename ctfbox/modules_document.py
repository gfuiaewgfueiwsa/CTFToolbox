# -*- coding: utf-8 -*-
"""文档深度分析：Office(docx/xlsx/pptx) 元数据/批注/宏/嵌入对象，PDF 动作/JS/表单/嵌入文件。"""
import os
import re
import zlib
import zipfile
from .common import Report, scan_flags, extract_strings

# ----------------------------------------------------------------------------
# Office（docx / xlsx / pptx，本质 ZIP）
# ----------------------------------------------------------------------------
def _xml_text(raw: bytes) -> str:
    """粗略提取 XML 文本节点与属性值。"""
    try:
        txt = raw.decode("utf-8", errors="replace")
    except Exception:
        txt = raw.decode("latin-1", errors="replace")
    parts = re.findall(r">([^<>]+)<", txt)          # 文本节点
    parts += re.findall(r'"([^"]{2,})"', txt)       # 属性值
    return "\n".join(p.strip() for p in parts if p.strip())

def analyze_office(path: str, report: Report, outdir: str):
    try:
        zf = zipfile.ZipFile(path)
    except Exception as e:
        report.add("warn", "Office 文档打开失败", str(e))
        return
    names = zf.namelist()
    kind = ("Word" if any(n.startswith("word/") for n in names) else
            "Excel" if any(n.startswith("xl/") for n in names) else
            "PPT" if any(n.startswith("ppt/") for n in names) else "Office(zip)")
    report.add("info", f"{kind} 文档结构", f"{len(names)} 个部件: " +
               ", ".join(n for n in names if n.count("/") <= 1)[:300])

    def read(n):
        try:
            return zf.read(n)
        except Exception:
            return b""

    # 核心元数据（作者/时间/标题等高频藏 flag 位置）
    for meta in ("docProps/core.xml", "docProps/app.xml", "docProps/custom.xml"):
        raw = read(meta)
        if raw:
            txt = _xml_text(raw)
            if txt.strip():
                report.add("ok", f"元数据 {meta}", txt[:1500])
                for fl in scan_flags(txt.encode("utf-8", "ignore")):
                    report.add("flag", f"{meta} 中发现 flag", fl)

    # 正文 / 共享字符串 / 幻灯片 / 批注 / 脚注
    body_priority = [
        r"^word/document\d*\.xml$", r"^word/comments\.xml$",
        r"^word/(footnotes|endnotes|header\d*|footer\d*)\.xml$",
        r"^xl/sharedStrings\.xml$", r"^xl/comments\d*\.xml$",
        r"^ppt/slides/slide\d+\.xml$", r"^ppt/comments/comment\d+\.xml$",
        r"^ppt/notesSlides/notesSlide\d+\.xml$",
    ]
    for n in names:
        if any(re.search(p, n) for p in body_priority):
            txt = _xml_text(read(n))
            if txt.strip():
                label = "批注" if "comment" in n else ("正文" if "document" in n or "slide" in n else "内容")
                report.add("info", f"{label} {n}", txt[:2000])
                for fl in scan_flags(txt.encode("utf-8", "ignore")):
                    report.add("flag", f"{n} 中发现 flag", fl)

    # 宏 vbaProject.bin
    vba = [n for n in names if n.lower().endswith("vbaproject.bin")]
    if vba:
        report.add("warn", "文档含 VBA 宏(vbaProject.bin)",
                   "宏病毒/恶意文档常见载体，已提取字符串分析；建议用 oletools/olevba 深入")
        emb_dir = os.path.join(outdir, "office_embedded")
        os.makedirs(emb_dir, exist_ok=True)
        for n in vba:
            data = read(n)
            fp = os.path.join(emb_dir, os.path.basename(n))
            with open(fp, "wb") as f:
                f.write(data)
            report.extracted.append(fp)
            joined = "\n".join(extract_strings(data, 4))
            for fl in scan_flags(joined.encode("latin-1", "ignore")):
                report.add("flag", "宏字符串中发现 flag", fl)
            for kw in ("AutoOpen", "Auto_Open", "Document_Open", "Shell", "WScript.Shell",
                       "CreateObject", "URLDownloadToFile", "PowerShell", "cmd.exe", "MsgBox"):
                if kw.encode() in data:
                    report.add("warn", f"宏中出现敏感行为: {kw}", "")

    # 外部关系（远程模板/外链，钓鱼文档特征）
    for n in names:
        if n.endswith(".rels"):
            raw = read(n).decode("utf-8", errors="replace")
            for m in re.finditer(r'TargetMode="External"[^>]*Target="([^"]+)"|Target="([^"]+)"[^>]*TargetMode="External"', raw):
                url = m.group(1) or m.group(2)
                report.add("warn", f"外部关系链接 {n}", url)

    # 嵌入对象（OLE/嵌入 xlsx 等）
    emb_dir = os.path.join(outdir, "office_embedded")
    for n in names:
        if "/embeddings/" in n or n.lower().endswith((".ole", ".bin", ".xlsx", ".docx", ".pptx")):
            data = read(n)
            if len(data) < 16:
                continue
            os.makedirs(emb_dir, exist_ok=True)
            fp = os.path.join(emb_dir, os.path.basename(n).replace("oleObject", "ole_"))
            if not os.path.exists(fp):
                with open(fp, "wb") as f:
                    f.write(data)
                report.extracted.append(fp)
                report.add("ok", f"发现嵌入对象 {n}", f"{len(data)} 字节 -> {fp}（将递归分析）")
    zf.close()

# ----------------------------------------------------------------------------
# PDF
# ----------------------------------------------------------------------------
def analyze_pdf(path: str, raw: bytes, report: Report, outdir: str):
    head = raw[:4096]
    if b"%PDF" not in head:
        report.add("warn", "PDF 头异常", "未以 %PDF 开头，可能文件头损坏（可用文件头修复）")
    # 元数据
    metas = {
        "标题": rb"/Title\s*\(([^)]{0,300})\)", "作者": rb"/Author\s*\(([^)]{0,300})\)",
        "主题": rb"/Subject\s*\(([^)]{0,300})\)", "关键词": rb"/Keywords\s*\(([^)]{0,300})\)",
        "生成器": rb"/Producer\s*\(([^)]{0,300})\)", "创建工具": rb"/Creator\s*\(([^)]{0,300})\)",
        "创建时间": rb"/CreationDate\s*\(([^)]{0,100})\)", "修改时间": rb"/ModDate\s*\(([^)]{0,100})\)",
    }
    for label, pat in metas.items():
        m = re.search(pat, raw, re.S)
        if m and m.group(1).strip():
            val = m.group(1).decode("latin-1", "replace")
            report.add("info", f"PDF {label}", val[:300])
            for fl in scan_flags(val.encode("latin-1", "ignore")):
                report.add("flag", f"PDF {label}中发现 flag", fl)
    pages = len(re.findall(rb"/Type\s*/Page(?!s)", raw))
    if pages:
        report.add("info", "PDF 页数", str(pages))

    # JavaScript
    js = []
    for m in re.finditer(rb"/JS\s*(\((?:[^()\\]|\\.)*\)|<[^>]*>)", raw, re.S):
        js.append(m.group(1))
    for m in re.finditer(rb"/JavaScript\s*>>?\s*stream\r?\n(.*?)\r?\nendstream", raw, re.S):
        js.append(m.group(1))
    if js or b"/JavaScript" in raw or b"/JS" in raw:
        txt = "\n".join(j.decode("latin-1", "replace") for j in js)[:1500] or "存在 /JS 标记"
        report.add("warn", "PDF 含 JavaScript", txt)
    # 动作
    for act, desc in ((r"/OpenAction", "打开即执行(OpenAction)"), (r"/AA\b", "附加动作(AA)"),
                      (r"/Launch\b", "启动外部程序(Launch)"), (r"/GoToR", "跳转远程(GoToR)"),
                      (r"/EmbeddedFile", "内嵌文件(EmbeddedFile)"), (r"/SubmitForm", "提交表单(SubmitForm)")):
        if re.search(act.encode(), raw):
            report.add("warn", f"PDF 动作: {desc}", "")
    # URI
    uris = sorted(set(re.findall(rb"/URI\s*\(([^)]+)\)", raw)))
    if uris:
        report.add("info", "PDF 链接", "\n".join(u.decode("latin-1", "replace") for u in uris[:30]))
    # 表单字段
    fields = sorted(set(re.findall(rb"/T\s*\(([^)]{1,200})\)", raw)))
    if fields:
        report.add("info", "PDF 表单字段", "\n".join(f.decode("latin-1", "replace") for f in fields[:50]))

    # 提取 stream（先尝试 FlateDecode 解压），扫描 flag 与内嵌文件
    emb_dir = os.path.join(outdir, "pdf_streams")
    os.makedirs(emb_dir, exist_ok=True)
    n_emb = 0
    for i, m in enumerate(re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", raw, re.S)):
        body = m.group(1)
        candidates = [body]
        if b"FlateDecode" in raw[max(0, m.start() - 400):m.start()]:
            try:
                candidates.append(zlib.decompress(body))
            except Exception:
                pass
        for c in candidates:
            for fl in scan_flags(c[:4 * 1024 * 1024]):
                report.add("flag", "PDF 内容流中发现 flag", fl)
            # 内嵌文件魔数
            for mg, ext in ((b"\x89PNG\r\n\x1a\n", ".png"), (b"\xff\xd8\xff", ".jpg"),
                            (b"PK\x03\x04", ".zip"), (b"MZ", ".exe"), (b"%PDF", ".pdf")):
                k = c.find(mg)
                if k >= 0 and n_emb < 12:
                    fp = os.path.join(emb_dir, f"stream{i:03d}{ext}")
                    with open(fp, "wb") as f:
                        f.write(c[k:k + 30 * 1024 * 1024])
                    report.extracted.append(fp)
                    report.add("ok", f"PDF 流中发现内嵌 {ext}", fp + "（将递归分析）")
                    n_emb += 1
                    break
    # 纯文本括号字符串兜底
    texts = re.findall(rb"\(([ -~]{4,})\)\s*Tj", raw)
    joined = b" ".join(texts)
    for fl in scan_flags(joined):
        report.add("flag", "PDF 可见文本中发现 flag", fl)
