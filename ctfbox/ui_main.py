# -*- coding: utf-8 -*-
"""CTFToolbox 主界面。"""
import os
import sys
import queue
import threading
import subprocess
import customtkinter as ctk
from tkinter import filedialog, messagebox

from .common import (WORKSPACE, TOOLS_DIR, REPORTS_DIR, EXPORTS_DIR, Report,
                     human_size, safe_name, external_python)
from .dispatcher import Dispatcher
from . import toolsmgr
from . import webtools
from . import modules_text
from . import modules_archive
from .modules_text import auto_decode, hash_text, identify_hash, crack_hash
from .ui_ssh import SSHTab
from .ui_scripts import ScriptsLibraryFrame

try:
    import windnd
except Exception:
    windnd = None

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

LEVEL_COLORS = {
    "flag": "#ff4d4f",
    "ok": "#3ecf8e",
    "warn": "#faad14",
    "info": "#b8c0cc",
    "tool": "#69b1ff",
}


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CTFToolbox 万能CTF集合工具箱 v2.3  | 仅限CTF/授权测试")
        self.geometry("1320x880")
        self.minsize(1100, 720)
        self.q = queue.Queue()
        self.last_report = None
        self.current_file = None
        self.wordlist = None
        self._file_queue = []    # 批量分析待处理文件
        self._busy = False
        self._run_token = 0     # 每次分析递增；停止后旧任务结果被丢弃

        self.tabs = ctk.CTkTabview(self, command=self._on_tab)
        self.tabs.pack(fill="both", expand=True, padx=8, pady=8)
        self.t_ana = self.tabs.add("一键分析")
        self.t_code = self.tabs.add("编码/密码")
        self.t_cipher = self.tabs.add("密文加解密")
        self.t_util = self.tabs.add("实用小工具")
        self.t_tool = self.tabs.add("专项工具")
        self.t_web = self.tabs.add("Web / Pwn")
        self.t_lib = self.tabs.add("📚 脚本库")
        self.t_ssh = self.tabs.add("SSH 终端")
        self.t_center = self.tabs.add("工具中心")
        self.t_media = self.tabs.add("媒体中心")
        self.t_nav = self.tabs.add("网页导航")

        self._build_analysis()
        self._build_code()
        self._build_cipher()
        self._build_util()
        self._build_tools()
        self._build_web()
        self.scripts_lib = ScriptsLibraryFrame(self.t_lib)
        self.scripts_lib.pack(fill="both", expand=True)
        self.ssh = SSHTab(self.t_ssh)
        self.ssh.pack(fill="both", expand=True)
        self._build_center()
        self._build_media()
        self._build_webnav()

        if windnd:
            windnd.hook_dropfiles(self, func=self._on_drop)
        self.after(100, self._drain)
        self._center_log("提示：把题目文件直接拖入窗口，或点「选择文件」→「开始分析」\n")

    # ===================================================================
    # 一键分析页
    # ===================================================================
    def _build_analysis(self):
        top = ctk.CTkFrame(self.t_ana)
        top.pack(fill="x", padx=6, pady=(6, 4))
        ctk.CTkButton(top, text="选择文件", width=90, command=self._pick_file).pack(side="left", padx=6, pady=6)
        self.file_entry = ctk.CTkEntry(top, placeholder_text="题目文件路径（支持拖入任意后缀文件）")
        self.file_entry.pack(side="left", fill="x", expand=True, pady=6)
        ctk.CTkLabel(top, text="递归深度").pack(side="left", padx=(8, 2))
        self.depth = ctk.CTkOptionMenu(top, values=["1", "2", "3", "4", "5", "6"], width=70)
        self.depth.set("4")
        self.depth.pack(side="left")
        self.ana_btn = ctk.CTkButton(top, text="开始分析", width=100,
                                     fg_color="#d4380d", hover_color="#ad250b",
                                     command=self._start_analysis)
        self.ana_btn.pack(side="left", padx=(6, 3))
        self.stop_btn = ctk.CTkButton(top, text="停止", width=70, state="disabled",
                                      fg_color="#595959", hover_color="#434343",
                                      command=self._stop_analysis)
        self.stop_btn.pack(side="left", padx=3)
        ctk.CTkButton(top, text="导出报告", width=90, fg_color="#1d6fa5", hover_color="#15547d",
                      command=self._export_report).pack(side="left", padx=3)
        ctk.CTkButton(top, text="报告/导出目录", width=110, fg_color="#444", hover_color="#555",
                      command=self._open_output_dirs).pack(side="left", padx=3)

        body = ctk.CTkFrame(self.t_ana)
        body.pack(fill="both", expand=True, padx=6, pady=4)

        left = ctk.CTkFrame(body, width=330)
        left.pack(side="left", fill="y", padx=(6, 3), pady=6)
        left.pack_propagate(False)
        ctk.CTkLabel(left, text="文件信息", font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w", padx=10, pady=(10, 4))
        self.info_box = ctk.CTkTextbox(left, width=300, height=260, font=ctk.CTkFont(family="Consolas", size=12))
        self.info_box.pack(fill="x", padx=8)
        ctk.CTkLabel(left, text="外部工具打开", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(12, 4))
        for name, tname in [("Ghidra 反编译", "ghidra"), ("x64dbg 动态调试", "x64dbg"),
                            ("dnSpy(.NET)", "dnspy"), ("DIE 查壳", "die"),
                            ("radare2", "radare2"), ("ExifTool 元数据", "exiftool")]:
            ctk.CTkButton(left, text=name, height=28,
                          command=lambda t=tname: self._open_in_tool(t)).pack(fill="x", padx=10, pady=2)
        ctk.CTkButton(left, text="打开工作区(提取文件目录)", height=28,
                      fg_color="#444", hover_color="#555",
                      command=lambda: os.startfile(WORKSPACE)).pack(fill="x", padx=10, pady=(10, 2))

        right = ctk.CTkTabview(body)
        right.pack(side="left", fill="both", expand=True, padx=(3, 6), pady=6)
        right.add("分析报告")
        right.add("提取的文件")
        right.add("实时日志")
        self.report_box = ctk.CTkTextbox(right.tab("分析报告"),
                                         font=ctk.CTkFont(family="Microsoft YaHei UI", size=13))
        self.report_box.pack(fill="both", expand=True)
        self.extract_box = ctk.CTkTextbox(right.tab("提取的文件"),
                                          font=ctk.CTkFont(family="Consolas", size=12))
        self.extract_box.pack(fill="both", expand=True)
        logbar = ctk.CTkFrame(right.tab("实时日志"))
        logbar.pack(fill="x")
        ctk.CTkButton(logbar, text="清空", width=70, height=26,
                      command=lambda: self._clear_box(self.ana_log)).pack(side="right", padx=4, pady=3)
        self.ana_log = ctk.CTkTextbox(right.tab("实时日志"),
                                      font=ctk.CTkFont(family="Consolas", size=12))
        self.ana_log.pack(fill="both", expand=True)
        self.progress = ctk.CTkProgressBar(self.t_ana, mode="indeterminate", height=3)
        self.progress.set(0)

    def _pick_file(self):
        p = filedialog.askopenfilename(title="选择题目文件（任意后缀）")
        if p:
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, p)
            self.current_file = p

    def _decode_dropped(self, paths):
        out = []
        for x in paths or []:
            if isinstance(x, bytes):
                x = x.decode("gbk", errors="replace")
            if x and os.path.isfile(x):
                out.append(x)
        return out

    def _on_drop(self, paths):
        files = self._decode_dropped(paths)
        if not files:
            return
        self._enqueue(files, clear=True)

    def _start_analysis(self):
        path = self.file_entry.get().strip().strip('"')
        if not path or not os.path.isfile(path):
            messagebox.showwarning("提示", "请先选择有效文件")
            return
        self._enqueue([path], clear=not self._busy)

    def _enqueue(self, files, clear=True):
        files = [f for f in files if os.path.isfile(f)]
        if not files:
            return
        if clear:
            self._file_queue = list(dict.fromkeys(files))
            self._batch_first = True
        else:
            for f in files:
                if f not in self._file_queue:
                    self._file_queue.append(f)
        self.file_entry.delete(0, "end")
        self.file_entry.insert(0, self._file_queue[0])
        if not self._busy:
            self._next_file()

    def _next_file(self):
        if self._busy:
            return
        if not self._file_queue:
            self.ana_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            self.progress.stop()
            self.progress.pack_forget()
            self._busy = False
            return
        path = self._file_queue.pop(0)
        self.current_file = path
        self.file_entry.delete(0, "end")
        self.file_entry.insert(0, path)
        if getattr(self, "_batch_first", True):
            self.report_box.configure(state="normal")
            self.report_box.delete("1.0", "end")
            self.extract_box.delete("1.0", "end")
            self._batch_first = False
        else:
            self.report_box.insert("end", "\n\n" + "=" * 90 + "\n")
        self._busy = True
        self._run_token += 1
        token = self._run_token
        self.ana_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.progress.pack(fill="x", side="bottom")
        self.progress.start()
        depth = int(self.depth.get())

        def work():
            d = Dispatcher(log_cb=lambda m: self.q.put(("log", (m, token))), max_depth=depth)
            try:
                rep = d.run(path)
                self.q.put(("report", (rep, token)))
            except Exception as e:
                import traceback
                self.q.put(("log", (f"[!] 分析失败: {e}\n{traceback.format_exc()}", token)))
            finally:
                self.q.put(("done", token))
        threading.Thread(target=work, daemon=True).start()

    def _stop_analysis(self):
        self._run_token += 1            # 使在跑任务的结果失效
        self._file_queue.clear()
        self._busy = False
        self.ana_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.progress.stop()
        self.progress.pack_forget()
        self.q.put(("log", ("[!] 已请求停止：界面已恢复，后台任务结果将被丢弃（CPU 任务会自行结束）\n",
                            self._run_token)))

    def _open_output_dirs(self):
        """打开软件目录下的报告/导出文件夹。"""
        try:
            os.makedirs(REPORTS_DIR, exist_ok=True)
            os.startfile(REPORTS_DIR)
        except Exception:
            pass

    def _export_report(self):
        """静默导出：报告直接写入软件所在目录 reports\\，不再弹保存对话框/提示框。"""
        if not self.last_report:
            self.ana_log.insert("end", "[!] 还没有可导出的分析报告\n")
            self.ana_log.see("end")
            return
        try:
            import time as _time
            import html as _html
            os.makedirs(REPORTS_DIR, exist_ok=True)
            stem = safe_name(os.path.splitext(os.path.basename(self.last_report.path))[0]) or "report"
            ts = _time.strftime("%Y%m%d_%H%M%S")
            tp = os.path.join(REPORTS_DIR, f"{stem}_{ts}.txt")
            hp = os.path.join(REPORTS_DIR, f"{stem}_{ts}.html")

            lines = []

            def walk_txt(r, d=0):
                lines.append("    " * d + f"[{r.ftype}] {r.path}")
                for fnd in r.findings:
                    lines.append("    " * d + f"  ({fnd.level}) {fnd.title}")
                    if fnd.detail:
                        for ln in str(fnd.detail).splitlines():
                            lines.append("    " * d + f"      {ln}")
                for c in r.children:
                    walk_txt(c, d + 1)
            walk_txt(self.last_report)
            with open(tp, "w", encoding="utf-8") as f:
                f.write("CTFToolbox v2.3 分析报告\n" + "=" * 70 + "\n" + "\n".join(lines))

            parts = ["<html><head><meta charset='utf-8'><title>CTFToolbox 报告</title>",
                     "<style>body{font-family:'Microsoft YaHei UI',sans-serif;background:#1e1e1e;"
                     "color:#ddd;margin:24px;line-height:1.6}.flag{color:#ff7875;font-weight:bold}"
                     ".ok{color:#52c41a}.warn{color:#faad14}.info{color:#b8c0cc}"
                     ".title{color:#69b1ff;font-weight:bold;font-size:16px;margin-top:18px}"
                     ".detail{margin-left:20px;white-space:pre-wrap;font-family:Consolas}</style></head><body>",
                     "<h2>CTFToolbox v2.3 分析报告</h2>"]

            def walk_html(r, d=0):
                parts.append(f"<div class='title'>{'&nbsp;'*d*4}├ {_html.escape(os.path.basename(r.path))} "
                             f"[{_html.escape(r.ftype)}]</div>")
                for fnd in r.findings:
                    parts.append(f"<div class='{fnd.level}'>● {_html.escape(fnd.title)}</div>")
                    if fnd.detail:
                        parts.append(f"<div class='detail {fnd.level}_d'>{_html.escape(str(fnd.detail))}</div>")
                for c in r.children:
                    walk_html(c, d + 1)
            walk_html(self.last_report)
            parts.append("</body></html>")
            with open(hp, "w", encoding="utf-8") as f:
                f.write("\n".join(parts))
            self.ana_log.insert("end", f"[+] 报告已静默导出到软件目录：\n    {hp}\n    {tp}\n")
            self.ana_log.see("end")
        except Exception as e:
            self.ana_log.insert("end", f"[!] 报告导出失败: {e}\n")
            self.ana_log.see("end")

    def _render_report(self, rep: Report, depth=0):
        def w(text, tag=None, bold=False):
            self.report_box.insert("end", text, tag)
        if depth == 0:
            from .identifier import identify
            try:
                info = identify(rep.path)
                self.info_box.delete("1.0", "end")
                self.info_box.insert("end",
                    f"路径: {rep.path}\n\n类型: {rep.ftype}\n大类: {rep.category}\n"
                    f"大小: {human_size(info.size)}\n熵值: {info.entropy:.4f}\n"
                    f"扩展名: {info.ext or '(无)'}\n")
                if info.extra:
                    self.info_box.insert("end", "\n特征: " + ", ".join(
                        f"{k}={v}" for k, v in info.extra.items()))
            except Exception:
                pass
        indent = "    " * depth
        w(f"{indent}┌─ {os.path.basename(rep.path)}  [{rep.ftype}]\n", "title")
        for fnd in rep.findings:
            color = LEVEL_COLORS.get(fnd.level, "#ccc")
            w(f"{indent}│  ● {fnd.title}\n", fnd.level)
            if fnd.detail:
                for line in str(fnd.detail).splitlines()[:80]:
                    w(f"{indent}│      {line}\n", fnd.level + "_d")
        if not rep.findings:
            w(f"{indent}│  （无结果）\n", "info_d")
        for child in rep.children:
            self._render_report(child, depth + 1)
        if depth == 0:
            w("\n")

    def _open_in_tool(self, tname):
        path = self.file_entry.get().strip().strip('"')
        if not path:
            messagebox.showinfo("提示", "请先选择文件")
            return
        ok, msg = toolsmgr.launch(tname, filepath=path)
        if not ok:
            if "未安装" in msg:
                messagebox.showinfo("提示", f"{tname} 未安装，请到「工具中心」下载/安装")
                self.tabs.set("工具中心")
            else:
                messagebox.showerror("错误", msg)

    # ===================================================================
    # 编码/密码页
    # ===================================================================
    def _build_code(self):
        top = ctk.CTkFrame(self.t_code)
        top.pack(fill="both", expand=True, padx=6, pady=6)
        libbar = ctk.CTkFrame(top)
        libbar.pack(fill="x", padx=8, pady=(6, 0))
        ctk.CTkLabel(libbar, text="需要可复制的完整解题脚本？", text_color="#9fb4c8").pack(side="left", padx=6)
        ctk.CTkButton(libbar, text="📚 Crypto/编码脚本库", width=170,
                      fg_color="#444", hover_color="#555",
                      command=lambda: self._goto_scripts("crypto")).pack(side="right", padx=4, pady=4)
        ctk.CTkLabel(top, text="输入（密文/编码文本/哈希）", anchor="w").pack(fill="x", padx=10, pady=(8, 2))
        self.code_in = ctk.CTkTextbox(top, height=170, font=ctk.CTkFont(family="Consolas", size=13))
        self.code_in.pack(fill="x", padx=10)

        grid = ctk.CTkFrame(top)
        grid.pack(fill="x", padx=10, pady=8)
        btns = [
            ("自动解码(全家桶)", self._code_auto),
            ("Base64", lambda: self._code_single("Base64")),
            ("Base32", lambda: self._code_single("Base32")),
            ("Hex", lambda: self._code_single("HEX")),
            ("Base58", lambda: self._code_single("Base58")),
            ("Base85", lambda: self._code_single("Base85(b85)")),
            ("Base91", lambda: self._code_single("Base91")),
            ("URL编码", lambda: self._code_single("URL编码")),
            ("Unicode/HTML", lambda: self._code_single("HTML实体")),
            ("ROT13", lambda: self._code_single("ROT13")),
            ("ROT47", lambda: self._code_single("ROT47")),
            ("凯撒全爆破", self._code_caesar),
            ("栅栏全爆破", self._code_fence),
            ("摩斯解码", lambda: self._code_single("摩斯密码")),
            ("Brainfuck", lambda: self._code_single("Brainfuck")),
            ("JWT解码", lambda: self._code_single("JWT")),
            ("核心价值观解码", self._code_cv_dec),
            ("核心价值观编码", self._code_cv_enc),
            ("与佛论禅解码", self._code_tudou_dec),
            ("与佛论禅编码", self._code_tudou_enc),
            ("UUencode解码", self._code_uu),
            ("XXencode解码", self._code_xx),
            ("Jother解码", self._code_jother),
            ("Hex字节倒序", self._code_revhex),
            ("文本倒序", self._code_revtext),
            ("计算哈希", self._code_hash),
            ("识别哈希类型", self._code_hashid),
            ("哈希弱口令爆破", self._code_crackhash),
        ]
        for i, (txt, cmd) in enumerate(btns):
            r, c = divmod(i, 5)
            ctk.CTkButton(grid, text=txt, width=150, height=30, command=cmd).grid(
                row=r, column=c, padx=4, pady=4, sticky="ew")
        for c in range(5):
            grid.grid_columnconfigure(c, weight=1)

        ctk.CTkLabel(top, text="结果", anchor="w").pack(fill="x", padx=10)
        self.code_out = ctk.CTkTextbox(top, font=ctk.CTkFont(family="Consolas", size=13))
        self.code_out.pack(fill="both", expand=True, padx=10, pady=(2, 10))

    def _code_input(self):
        return self.code_in.get("1.0", "end").strip("\n")

    def _code_put(self, text):
        self.code_out.delete("1.0", "end")
        self.code_out.insert("1.0", text)

    def _code_auto(self):
        t = self._code_input()
        res = auto_decode(t, depth=3)
        if not res:
            self._code_put("未尝试出任何结果")
            return
        lines = []
        for chain, val, score in res[:40]:
            mark = "★" if score >= 6 else " "
            lines.append(f"{mark} [{chain}]  (可读分 {score:.1f})\n{val[:500]}\n{'-'*70}")
        self._code_put("\n".join(lines))

    def _code_single(self, want):
        t = self._code_input()
        res = auto_decode(t, depth=1)
        hit = [r for r in res if r[0] == want]
        if not hit:
            self._code_put(f"{want} 解码失败（输入可能不是该编码）")
        else:
            self._code_put(hit[0][1])

    def _code_caesar(self):
        t = self._code_input()
        from .modules_text import caesar
        self._code_put("\n".join(f"偏移{sh:>2}: {caesar(t, sh)}" for sh in range(26)))

    def _code_fence(self):
        t = self._code_input().replace(" ", "").replace("\n", "")
        from .modules_text import fence_decode
        out = []
        for rails in range(2, min(10, len(t))):
            out.append(f"{rails}栏: {fence_decode(t, rails)}")
        self._code_put("\n".join(out))

    def _code_hash(self):
        t = self._code_input()
        d = hash_text(t)
        self._code_put("\n".join(f"{k}: {v}" for k, v in d.items()))

    def _code_hashid(self):
        t = self._code_input()
        out = []
        for token in set(x.strip() for x in t.replace(",", " ").split()):
            if token:
                out.append(f"{token}\n  -> " + "; ".join(identify_hash(token)))
        self._code_put("\n".join(out))

    def _code_crackhash(self):
        t = self._code_input().strip().split()[0]
        self.code_out.delete("1.0", "end")
        self.code_out.insert("end", f"正在用内置弱口令表爆破 {t} …\n")
        wl = self.wordlist

        def work():
            r = crack_hash(t, wl)
            self.q.put(("code", f"\n明文: {r[0]}\n算法: {r[1]}" if r else "\n内置字典未命中，可在专项工具页挂载大字典(rockyou)"))
        threading.Thread(target=work, daemon=True).start()

    def _code_cv_dec(self):
        try:
            self._code_put(modules_text.core_values_decode(self._code_input()))
        except Exception as e:
            self._code_put(f"核心价值观解码失败: {e}")

    def _code_cv_enc(self):
        try:
            self._code_put(modules_text.core_values_encode(self._code_input()))
        except Exception as e:
            self._code_put(f"核心价值观编码失败: {e}")

    def _code_tudou_dec(self):
        try:
            self._code_put(modules_text.tudou_decode(self._code_input()))
        except Exception as e:
            self._code_put(f"与佛论禅解码失败: {e}")

    def _code_tudou_enc(self):
        try:
            self._code_put(modules_text.tudou_encode(self._code_input()))
        except Exception as e:
            self._code_put(f"与佛论禅编码失败: {e}")

    def _code_uu(self):
        from . import modules_morecode as mm
        try:
            self._code_put(mm.uu_decode(self._code_input()).decode("utf-8", "replace"))
        except Exception as e:
            self._code_put(f"UUencode 解码失败: {e}")

    def _code_xx(self):
        from . import modules_morecode as mm
        try:
            self._code_put(mm.xx_decode(self._code_input()).decode("utf-8", "replace"))
        except Exception as e:
            self._code_put(f"XXencode 解码失败: {e}")

    def _code_jother(self):
        from . import modules_morecode as mm
        try:
            self._code_put(mm.jother_decode(self._code_input()))
        except Exception as e:
            self._code_put(f"Jother 解码失败: {e}")

    def _code_revhex(self):
        from . import modules_morecode as mm
        try:
            self._code_put(mm.reverse_hex(self._code_input()))
        except Exception as e:
            self._code_put(f"Hex 倒序失败: {e}")

    def _code_revtext(self):
        from . import modules_morecode as mm
        self._code_put(mm.reverse_text(self._code_input()))

    # ===================================================================
    # 密文加解密页
    # ===================================================================
    def _build_cipher(self):
        from . import modules_codes as mc
        from . import modules_morecode as mm
        top = ctk.CTkFrame(self.t_cipher)
        top.pack(fill="both", expand=True, padx=6, pady=6)
        libbar = ctk.CTkFrame(top)
        libbar.pack(fill="x", padx=8, pady=(6, 0))
        ctk.CTkLabel(libbar, text="需要可复制的完整解题脚本？", text_color="#9fb4c8").pack(side="left", padx=6)
        ctk.CTkButton(libbar, text="📚 Crypto 密码学脚本库", width=180,
                      fg_color="#444", hover_color="#555",
                      command=lambda: self._goto_scripts("crypto")).pack(side="right", padx=4, pady=4)
        ctk.CTkLabel(top, text="输入（密文 / 明文 / 数据，XOR 与对称加密支持 Hex 或 Base64）",
                     anchor="w").pack(fill="x", padx=10, pady=(8, 2))
        self.ci_in = ctk.CTkTextbox(top, height=150, font=ctk.CTkFont(family="Consolas", size=13))
        self.ci_in.pack(fill="x", padx=10)
        prow = ctk.CTkFrame(top)
        prow.pack(fill="x", padx=10, pady=6)
        ctk.CTkLabel(prow, text="密钥/参数").pack(side="left")
        self.ci_key = ctk.CTkEntry(prow, placeholder_text="维吉尼亚/Playfair/AES 密钥；仿射填 a,b；对称填 算法:模式:密钥 如 AES:CBC:123456")
        self.ci_key.pack(side="left", fill="x", expand=True, padx=6)
        self.ci_hex = ctk.StringVar(value="off")
        ctk.CTkCheckBox(prow, text="密钥为Hex", variable=self.ci_hex,
                        onvalue="on", offvalue="off", width=90).pack(side="left")

        grid = ctk.CTkScrollableFrame(top, height=300)
        grid.pack(fill="both", expand=True, padx=8, pady=4)

        def out(res):
            self.ci_out.delete("1.0", "end")
            self.ci_out.insert("1.0", str(res))

        def T(fn):
            def w():
                try:
                    out(fn(self.ci_in.get("1.0", "end").strip("\n"),
                            self.ci_key.get().strip()))
                except Exception as e:
                    out(f"失败: {type(e).__name__}: {e}")
            return w

        def enc_dec(algo, decrypt):
            def w():
                import base64
                raw = self.ci_in.get("1.0", "end").strip("\n")
                spec = self.ci_key.get().strip()
                # 参数格式：密钥  或  算法:模式:密钥[:IV]，例如 AES:CBC:123456 或 SM4:ECB:key
                parts = spec.split(":")
                iv = ""
                if len(parts) >= 3 and parts[0].upper() in ("AES", "DES", "3DES", "RC4", "SM4"):
                    algo, mode, key = parts[0], parts[1], parts[2]
                    if len(parts) >= 4:
                        iv = parts[3]
                else:
                    mode = "ECB"
                    key = spec
                hexkey = self.ci_hex.get() == "on"
                try:
                    if decrypt:
                        data = bytes.fromhex(raw) if hexkey else \
                            base64.b64decode(raw + "=" * (-len(raw) % 4))
                    else:
                        data = raw.encode()
                    r = mc.symmetric_crypt(algo, mode, data, key, iv, decrypt, key_hex=hexkey)
                    if decrypt:
                        out(r.decode("utf-8", "replace"))
                    else:
                        out(base64.b64encode(r).decode())
                except Exception as e:
                    out(f"失败: {type(e).__name__}: {e}（参数示例 AES:CBC:密钥 或直接填密钥）")
            return w

        btns = [
            ("兽音→明文", T(lambda t, k: mc.roar_decode(t))),
            ("明文→兽音", T(lambda t, k: mc.roar_encode(t))),
            ("盲文→明文", T(lambda t, k: mc.braille_decode(t))),
            ("明文→盲文", T(lambda t, k: mc.braille_encode(t))),
            ("云影→明文", T(lambda t, k: mc.yunying_decode(t))),
            ("明文→云影", T(lambda t, k: mc.yunying_encode(t))),
            ("QWE→明文", T(lambda t, k: mc.qwe_decode(t))),
            ("明文→QWE", T(lambda t, k: mc.qwe_encode(t))),
            ("Base100→明文", T(lambda t, k: mc.base100_decode(t))),
            ("明文→Base100", T(lambda t, k: mc.base100_encode(t))),
            ("敲击码→明文", T(lambda t, k: mc.tapcode_decode(t))),
            ("当铺密码→明文", T(lambda t, k: mc.dangpu_decode(t))),
            ("五笔编码→明文", T(lambda t, k: mc.wubi_decode(t))),
            ("AA/JS/JJ混淆解码", T(lambda t, k: mc.js_obfuscation_decode(t))),
            ("维吉尼亚解密", T(lambda t, k: mc.vigenere(t, k or "key", True))),
            ("维吉尼亚加密", T(lambda t, k: mc.vigenere(t, k or "key", False))),
            ("维吉尼亚自动破解", T(lambda t, k: self._fmt_vig(mc.vigenere_crack(t)))),
            ("仿射解密(a,b)", T(lambda t, k: self._affine(t, k, True))),
            ("仿射自动破解", T(lambda t, k: self._fmt_affine(mc.affine_crack(t)))),
            ("Playfair解密", T(lambda t, k: mc.playfair(t, k or "key", True))),
            ("列移位破解", T(lambda t, k: self._fmt_col(mc.columnar_crack(t)))),
            ("单字节XOR破解", T(lambda t, k: self._fmt_xor1(mc.xor_single_crack(self._input_bytes(t))))),
            ("重复密钥XOR破解", T(lambda t, k: self._fmt_xorr(mc.xor_repeating_crack(self._input_bytes(t))))),
            ("Base64隐写提取", T(lambda t, k: mc.base64_steg_extract(t))),
            ("JWT检查/弱密钥", T(lambda t, k: self._fmt_jwt(mc.jwt_inspect(t)))),
            ("Flask Session解码", T(lambda t, k: self._fmt_flask(mc.flask_session_decode(t, self.wordlist)))),
            ("对称解密(AES/DES/3DES/RC4/SM4)", enc_dec("AES", True)),
            ("对称加密(输出Base64)", enc_dec("AES", False)),
            ("Rabbit解密", self._ci_rabbit_dec),
            ("Rabbit加密", self._ci_rabbit_enc),
            ("猪圈→明文", T(lambda t, k: mm.pigpen_decode(t))),
            ("明文→猪圈", T(lambda t, k: mm.pigpen_encode(t))),
            ("生成二维码", self._ci_qr),
        ]
        for i, (txt, cmd) in enumerate(btns):
            r, c = divmod(i, 4)
            ctk.CTkButton(grid, text=txt, height=30, command=cmd).grid(
                row=r, column=c, padx=4, pady=4, sticky="ew")
        for c in range(4):
            grid.grid_columnconfigure(c, weight=1)
        ctk.CTkLabel(top, text="结果", anchor="w").pack(fill="x", padx=10)
        self.ci_out = ctk.CTkTextbox(top, height=150, font=ctk.CTkFont(family="Consolas", size=13))
        self.ci_out.pack(fill="both", expand=True, padx=10, pady=(2, 10))

    def _input_bytes(self, t):
        import binascii, base64
        try:
            return bytes.fromhex(t.strip())
        except Exception:
            try:
                return base64.b64decode(t.strip() + "=" * (-len(t.strip()) % 4))
            except Exception:
                return t.encode()

    def _fmt_vig(self, res):
        if not res:
            return "未破解（文本可能过短或非维吉尼亚）"
        return "\n".join(f"密钥={k!r} 可读分={s:.1f}\n{v[:300]}" for v, k, s in res[:8])

    def _affine(self, t, k, dec):
        from . import modules_codes as mc
        a, b = (int(x) for x in k.replace(" ", "").split(","))
        return mc.affine(t, a, b, dec)

    def _fmt_affine(self, res):
        if not res:
            return "未破解"
        return "\n".join(f"a={a},b={b} 可读分={s:.1f}\n{v[:300]}" for v, a, b, s in res[:8])

    def _fmt_col(self, res):
        if not res:
            return "未破解"
        return "\n".join(f"列数={c}\n{v[:300]}" for v, c, s in res[:8])

    def _fmt_xor1(self, res):
        if not res:
            return "未发现可读单字节 XOR 明文"
        return "\n".join(f"密钥 0x{k:02x} 评分={s:.1f}\n{txt[:300]}" for k, txt, s in res)

    def _fmt_xorr(self, res):
        if not res:
            return "未破解"
        return "\n".join(f"密钥={k!r} 评分={s:.1f}\n{txt[:300]}" for k, txt, s in res[:6])

    def _fmt_jwt(self, res):
        import json
        header, payload, cracked, notes = res
        return (f"Header: {json.dumps(header, ensure_ascii=False)}\n"
                f"Payload: {json.dumps(payload, ensure_ascii=False)}\n{notes}"
                + (f"\n弱密钥: {cracked!r}" if cracked else ""))

    def _fmt_flask(self, res):
        payload, cracked = res
        return f"Session 内容:\n{payload}" + (f"\n弱密钥: {cracked!r}" if cracked else "\n(内置弱密钥未命中)")

    def _rabbit_key_iv(self):
        from . import modules_morecode as mm
        spec = self.ci_key.get().strip()
        parts = spec.split(":")
        kb = parts[0].encode("utf-8", "replace")
        key = (kb + b"\0" * 16)[:16]
        iv = None
        if len(parts) >= 2 and parts[1]:
            ib = parts[1].encode("utf-8", "replace")
            iv = (ib + b"\0" * 8)[:8]
        return key, iv

    def _ci_rabbit_dec(self):
        from . import modules_morecode as mm
        import base64 as _b64
        try:
            raw = self.ci_in.get("1.0", "end").strip("\n").strip()
            key, iv = self._rabbit_key_iv()
            try:
                data = bytes.fromhex(raw)
            except Exception:
                data = _b64.b64decode(raw + "=" * (-len(raw) % 4))
            out = mm.rabbit_crypt(data, key, iv)
            self.ci_out.delete("1.0", "end")
            self.ci_out.insert("1.0", out.decode("utf-8", "replace"))
        except Exception as e:
            self.ci_out.delete("1.0", "end")
            self.ci_out.insert("1.0", f"Rabbit 解密失败: {type(e).__name__}: {e}")

    def _ci_rabbit_enc(self):
        from . import modules_morecode as mm
        import base64 as _b64
        try:
            raw = self.ci_in.get("1.0", "end").strip("\n").encode("utf-8")
            key, iv = self._rabbit_key_iv()
            out = mm.rabbit_crypt(raw, key, iv)
            self.ci_out.delete("1.0", "end")
            self.ci_out.insert("1.0", _b64.b64encode(out).decode())
        except Exception as e:
            self.ci_out.delete("1.0", "end")
            self.ci_out.insert("1.0", f"Rabbit 加密失败: {type(e).__name__}: {e}")

    def _ci_qr(self):
        from . import modules_codes as mc
        t = self.ci_in.get("1.0", "end").strip("\n")
        fp = mc.qr_encode(t)
        self.ci_out.delete("1.0", "end")
        self.ci_out.insert("1.0", "二维码已生成: " + fp)
        try:
            os.startfile(fp)
        except Exception:
            pass

    # ===================================================================
    # 实用小工具页
    # ===================================================================
    def _build_util(self):
        from . import modules_util as mu
        from . import modules_morecode as mm
        top = ctk.CTkFrame(self.t_util)
        top.pack(fill="both", expand=True, padx=6, pady=6)
        libbar = ctk.CTkFrame(top)
        libbar.pack(fill="x", padx=8, pady=(6, 0))
        ctk.CTkLabel(libbar, text="需要可复制的完整解题脚本？", text_color="#9fb4c8").pack(side="left", padx=6)
        ctk.CTkButton(libbar, text="📚 Utils 实用脚本库", width=170,
                      fg_color="#444", hover_color="#555",
                      command=lambda: self._goto_scripts("utils")).pack(side="right", padx=4, pady=4)
        ctk.CTkLabel(top, text="输入", anchor="w").pack(fill="x", padx=10, pady=(8, 2))
        self.u_in = ctk.CTkTextbox(top, height=130, font=ctk.CTkFont(family="Consolas", size=13))
        self.u_in.pack(fill="x", padx=10)
        prow = ctk.CTkFrame(top)
        prow.pack(fill="x", padx=10, pady=6)
        ctk.CTkLabel(prow, text="参数").pack(side="left")
        self.u_param = ctk.CTkEntry(prow, placeholder_text="正则表达式 / 替换文本 等（按需）")
        self.u_param.pack(side="left", fill="x", expand=True, padx=6)
        grid = ctk.CTkFrame(top)
        grid.pack(fill="x", padx=10)

        def out(res):
            self.u_out.delete("1.0", "end")
            self.u_out.insert("1.0", str(res))

        def T(fn):
            def w():
                try:
                    out(fn(self.u_in.get("1.0", "end").strip("\n"),
                            self.u_param.get().strip()))
                except Exception as e:
                    out(f"失败: {type(e).__name__}: {e}")
            return w

        def kv(res):
            if isinstance(res, dict):
                return "\n".join(f"{k}: {v}" for k, v in res.items())
            if isinstance(res, (list, tuple)) and res and isinstance(res[0], tuple):
                return "\n".join(f"{k}: {v}" for k, v in res)
            return str(res)

        btns = [
            ("时间戳互转", T(lambda t, p: kv(mu.convert_timestamp(t)))),
            ("进制互转(2/8/10/16)", T(lambda t, p: kv(mu.convert_number(t)))),
            ("浮点→Hex(double)", T(lambda t, p: kv(mu.float_to_hex(t, 64)))),
            ("浮点→Hex(float)", T(lambda t, p: kv(mu.float_to_hex(t, 32)))),
            ("Hex→浮点(double)", T(lambda t, p: kv(mu.hex_to_float(t, 64)))),
            ("Hex→浮点(float)", T(lambda t, p: kv(mu.hex_to_float(t, 32)))),
            ("大小端交换", T(lambda t, p: kv(mu.endian_swap(t)))),
            ("JSON美化", T(lambda t, p: mu.json_format(t))),
            ("正则提取", T(lambda t, p: self._fmt_regex(mu.regex_extract(p, t)))),
            ("字符频率统计", T(lambda t, p: kv(mu.char_frequency(t)))),
            ("编码探测", T(lambda t, p: kv(mu.detect_encoding(t.encode("utf-8", "replace"))))),
            ("子网/掩码计算", T(lambda t, p: mm.subnet_calc(t))),
            ("生成密码字典", self._u_wordlist),
        ]
        for i, (txt, cmd) in enumerate(btns):
            r, c = divmod(i, 4)
            ctk.CTkButton(grid, text=txt, height=30, width=180, command=cmd).grid(
                row=r, column=c, padx=4, pady=4, sticky="ew")
        for c in range(4):
            grid.grid_columnconfigure(c, weight=1)
        ctk.CTkLabel(top, text="结果", anchor="w").pack(fill="x", padx=10)
        self.u_out = ctk.CTkTextbox(top, font=ctk.CTkFont(family="Consolas", size=13))
        self.u_out.pack(fill="both", expand=True, padx=10, pady=(2, 10))

    def _fmt_ts(self, res):
        if not res:
            return "无法识别该时间格式"
        return "\n".join(f"{k}: {v}" for k, v in res.items())

    def _fmt_regex(self, res):
        if not res:
            return "无匹配"
        if isinstance(res[0], tuple):
            return "\n".join(str(m) for m in res[:200])
        return "\n".join(res[:500])

    def _u_wordlist(self):
        from . import modules_util as mu
        words = [w.strip() for w in self.u_in.get("1.0", "end").replace(",", "\n").splitlines() if w.strip()]
        if not words:
            self.u_out.delete("1.0", "end")
            self.u_out.insert("1.0", "请在输入中给出姓名/拼音/单词，每行或逗号分隔")
            return
        wl = mu.generate_passwords(words)
        fp, n = mu.save_wordlist(wl)
        self.u_out.delete("1.0", "end")
        self.u_out.insert("1.0", f"已生成 {n} 条口令: {fp}\n\n" + "\n".join(wl[:200]))

    # ===================================================================
    # 专项工具页
    # ===================================================================
    def _build_tools(self):
        libbar = ctk.CTkFrame(self.t_tool)
        libbar.pack(fill="x", padx=6, pady=(6, 0))
        ctk.CTkLabel(libbar, text="脚本库：", text_color="#9fb4c8").pack(side="left", padx=(6, 2))
        for txt, cat in [("📚 Misc杂项", "misc"), ("📁 Reverse逆向", "reverse"),
                         ("🔍 Forensics取证", "forensics")]:
            ctk.CTkButton(libbar, text=txt, width=140, fg_color="#444", hover_color="#555",
                          command=lambda c=cat: self._goto_scripts(c)).pack(side="left", padx=4, pady=4)
        bar = ctk.CTkFrame(self.t_tool)
        bar.pack(fill="x", padx=6, pady=6)
        ctk.CTkButton(bar, text="选择文件", width=90, command=self._pick_tool_file).pack(side="left", padx=6, pady=6)
        self.tool_file = ctk.CTkEntry(bar, placeholder_text="目标文件")
        self.tool_file.pack(side="left", fill="x", expand=True, pady=6)
        ctk.CTkButton(bar, text="选择字典", width=90, command=self._pick_wordlist).pack(side="left", padx=6)
        self.wl_label = ctk.CTkLabel(bar, text="字典: 内置弱口令表", width=200, anchor="w")
        self.wl_label.pack(side="left")

        grid = ctk.CTkFrame(self.t_tool)
        grid.pack(fill="x", padx=6)
        btns = [
            ("压缩包弱口令+解压", self._m_archive),
            ("压缩包大字典爆破", self._m_archive_big),
            ("CRC套件批量还原(选目录)", self._m_crcsuite),
            ("损坏ZIP容错雕刻", self._m_carvebroken),
            ("bkcrack明文攻击向导", self._m_bkcrack),
            ("文件雕刻(提取内嵌)", self._m_carve),
            ("strings 字符串", self._m_strings),
            ("图片隐写全套", self._m_image),
            ("图片马/Polyglot扫描", self._m_polyglot),
            ("steghide隐写链", self._m_steghide),
            ("盲水印提取", self._m_bwm),
            ("流量包分析", self._m_traffic),
            ("PE/ELF 逆向分析", self._m_reverse),
            ("UPX 脱壳", self._m_upx),
            ("PE 文件头修复", self._m_pe_repair),
            ("PE资源提取", self._m_peres),
            ("PyInstaller解包", self._m_pyi),
            ("pyc 反编译", self._m_pyc),
            ("asar 解包", self._m_asar),
            ("音频隐写全套(MP3/WAV/OGG/FLAC/M4A)", self._m_audio),
            ("DTMF拨号音解码", self._m_dtmf),
            ("Office/PDF文档分析", self._m_document),
            ("文件头修复/伪加密", self._m_repair),
            ("零宽字符隐写", self._m_zerowidth),
            ("RSA密钥分析/分解", self._m_rsa),
            ("NTFS ADS数据流", self._m_ads),
            ("vim swap恢复", self._m_swap),
            ("分片自动合并", self._m_merge),
            ("磁盘镜像(vmdk/vhd/dd)", self._m_disk),
            ("路由器配置/内嵌流", self._m_router),
            ("注册表hive分析", self._m_reg),
            ("Windows evtx日志", self._m_evtx),
            ("Web访问日志分析", self._m_weblog),
            ("一键完整分析", lambda: (self.file_entry.delete(0, "end"),
                                      self.file_entry.insert(0, self.tool_file.get()),
                                      self._start_analysis())),
        ]
        for i, (txt, cmd) in enumerate(btns):
            r, c = divmod(i, 3)
            ctk.CTkButton(grid, text=txt, height=34, command=cmd).grid(
                row=r, column=c, padx=5, pady=5, sticky="ew")
        for c in range(3):
            grid.grid_columnconfigure(c, weight=1)

        self.tool_out = ctk.CTkTextbox(self.t_tool, font=ctk.CTkFont(family="Consolas", size=12))
        self.tool_out.pack(fill="both", expand=True, padx=6, pady=6)

    def _pick_tool_file(self):
        p = filedialog.askopenfilename()
        if p:
            self.tool_file.delete(0, "end")
            self.tool_file.insert(0, p)

    def _pick_wordlist(self):
        p = filedialog.askopenfilename(title="选择字典（如 rockyou.txt）")
        if p:
            self.wordlist = p
            self.wl_label.configure(text="字典: " + os.path.basename(p))

    def _tool_file_path(self):
        return self.tool_file.get().strip().strip('"')

    def _run_module(self, fn):
        p = self._tool_file_path()
        if not p or not os.path.isfile(p):
            messagebox.showwarning("提示", "请先选择文件")
            return
        self.tool_out.delete("1.0", "end")

        def work():
            rep = Report(path=p)
            outdir = os.path.join(WORKSPACE, "manual_" + os.path.basename(p).replace(".", "_"))
            os.makedirs(outdir, exist_ok=True)
            try:
                fn(p, rep, outdir)
            except Exception as e:
                import traceback
                rep.add("warn", "执行异常", f"{e}\n{traceback.format_exc()[:800]}")
            self.q.put(("manual", rep))
        threading.Thread(target=work, daemon=True).start()

    def _m_archive(self, big=False):
        from .identifier import identify
        wl = self.wordlist if big else None

        def fn(p, rep, outdir):
            info = identify(p)
            if wl:
                # 大字典直接走 7z
                ok, pwd, exdir = modules_archive._crack_7z(p, outdir, wl)
                if ok:
                    rep.add("flag", f"大字典命中密码: {pwd}", exdir)
                else:
                    rep.add("warn", "大字典未命中", "")
            else:
                modules_archive.analyze(p, rep, info.ftype, outdir)
        self._run_module(fn)

    def _m_archive_big(self):
        if not self.wordlist:
            messagebox.showinfo("提示", "请先选择字典文件（rockyou.txt 等）")
            return
        self._m_archive(big=True)

    def _m_carve(self):
        from .modules_carve import scan_and_carve
        self._run_module(lambda p, r, o: scan_and_carve(p, r, o))

    def _m_strings(self):
        from .modules_carve import strings_scan
        def fn(p, rep, outdir):
            strs = strings_scan(p, rep)
            rep.add("info", f"全部字符串({len(strs)}条)前200", "\n".join(strs[:200]))
        self._run_module(fn)

    def _m_image(self):
        from .modules_image import analyze
        self._run_module(lambda p, r, o: analyze(p, r))

    def _m_traffic(self):
        from .modules_traffic import analyze
        self._run_module(lambda p, r, o: analyze(p, r, o))

    def _m_reverse(self):
        from .identifier import identify
        from .modules_reverse import analyze
        def fn(p, r, o):
            info = identify(p)
            analyze(p, r, info.ftype, o)
        self._run_module(fn)

    def _m_upx(self):
        def fn(p, rep, outdir):
            upx = toolsmgr.get_tool("upx")
            if not upx:
                rep.add("warn", "未安装 UPX", "工具中心可一键下载")
                return
            fp = os.path.join(outdir, "unpacked_" + os.path.basename(p))
            r = subprocess.run([upx, "-d", p, "-o", fp, "-f"], capture_output=True, timeout=120)
            if r.returncode == 0:
                rep.add("ok", "UPX 脱壳成功", fp)
            else:
                rep.add("warn", "脱壳失败", (r.stdout + r.stderr).decode("latin-1", "replace")[:500])
        self._run_module(fn)

    def _m_audio(self):
        from . import modules_audio

        def fn(p, rep, outdir):
            modules_audio.analyze(p, rep, os.path.join(outdir, "audio"), do_carve=True)
        self._run_module(fn)

    def _m_wav(self):
        # 兼容旧入口：统一走音频隐写全套
        self._m_audio()

    def _m_document(self):
        from .modules_document import analyze_office, analyze_pdf
        def fn(p, rep, outdir):
            with open(p, "rb") as f:
                head = f.read(16)
            if head[:2] == b"PK":
                analyze_office(p, rep, outdir)
            elif head[:4] == b"%PDF":
                with open(p, "rb") as f:
                    raw = f.read(60 * 1024 * 1024)
                analyze_pdf(p, raw, rep, outdir)
            else:
                rep.add("warn", "不是 Office/PDF", f"文件头: {head!r}")
        self._run_module(fn)

    def _m_repair(self):
        from .modules_stego import repair_file
        def fn(p, rep, outdir):
            ok = repair_file(p, rep, outdir)
            if not ok:
                rep.add("info", "文件头修复", "未发现可自动修复的问题（垃圾头/magic损坏/ZIP伪加密）")
        self._run_module(fn)

    def _m_zerowidth(self):
        from .modules_stego import analyze_zero_width
        def fn(p, rep, outdir):
            raw = open(p, "rb").read(2 * 1024 * 1024)
            text = raw.decode("utf-8", errors="replace")
            analyze_zero_width(text, rep)
        self._run_module(fn)

    def _m_rsa(self):
        from .modules_crypto import analyze_rsa
        def fn(p, rep, outdir):
            with open(p, "rb") as f:
                analyze_rsa(f.read(20 * 1024 * 1024), rep)
        self._run_module(fn)

    # ---- 取证 / 逆向 / 日志 等新增专项 ----
    def _m_ads(self):
        from .modules_forensics import extract_ads
        self._run_module(lambda p, r, o: extract_ads(p, r, o))

    def _m_swap(self):
        from .modules_forensics import recover_vim_swap
        self._run_module(lambda p, r, o: recover_vim_swap(p, r, o))

    def _m_merge(self):
        from .modules_forensics import detect_fragment_dir, merge_fragments

        def fn(p, rep, outdir):
            folder = os.path.dirname(os.path.abspath(p))
            groups = detect_fragment_dir(folder)
            if not groups:
                rep.add("warn", "分片合并", "该目录未发现成组的连续编号分片(.001/part1/out0)")
                return
            for gi, grp in enumerate(groups):
                op = os.path.join(outdir, f"merged_{gi}.bin")
                merge_fragments(grp, op, rep)
        self._run_module(fn)

    def _m_polyglot(self):
        from .modules_forensics import scan_polyglot
        self._run_module(lambda p, r, o: scan_polyglot(p, r, o))

    def _m_pe_repair(self):
        from .modules_forensics import repair_pe
        self._run_module(lambda p, r, o: repair_pe(p, r, o))

    def _m_router(self):
        from .modules_forensics import extract_embedded_streams
        self._run_module(lambda p, r, o: extract_embedded_streams(p, r, o))

    def _m_disk(self):
        from .modules_forensics import extract_disk_image
        self._run_module(lambda p, r, o: extract_disk_image(p, r, o))

    def _m_pyi(self):
        from .modules_pyre import extract_pyinstaller
        self._run_module(lambda p, r, o: extract_pyinstaller(p, r, o))

    def _m_pyc(self):
        from .modules_pyre import decompile_pyc
        self._run_module(lambda p, r, o: decompile_pyc(p, r, o))

    def _m_asar(self):
        from .modules_pyre import extract_asar
        self._run_module(lambda p, r, o: extract_asar(p, r, o))

    def _m_peres(self):
        from .modules_pyre import extract_pe_resources
        self._run_module(lambda p, r, o: extract_pe_resources(p, r, o))

    def _m_dtmf(self):
        from .modules_forensics import dtmf_decode_wav
        self._run_module(lambda p, r, o: dtmf_decode_wav(p, r))

    def _m_reg(self):
        from .modules_forensics import analyze_registry_hive
        self._run_module(lambda p, r, o: analyze_registry_hive(p, r, o))

    def _m_evtx(self):
        from .modules_forensics import analyze_evtx
        self._run_module(lambda p, r, o: analyze_evtx(p, r, o))

    def _m_weblog(self):
        from .modules_log import analyze_weblog
        self._run_module(lambda p, r, o: analyze_weblog(p, r, o))

    def _m_steghide(self):
        from .modules_forensics import steghide_chain

        def fn(p, rep, outdir):
            words = None
            if self.wordlist:
                try:
                    words = [w.strip() for w in open(self.wordlist, errors="ignore") if w.strip()]
                except Exception:
                    words = None
            steghide_chain(p, rep, words, outdir)
        self._run_module(fn)

    def _m_bwm(self):
        from .modules_forensics import blind_watermark_decode

        def fn(p, rep, outdir):
            op = os.path.join(outdir, "blind_wm.png")
            blind_watermark_decode(p, out_path=op, report=rep)
        self._run_module(fn)

    def _m_carvebroken(self):
        from .modules_archive import carve_broken

        def fn(p, rep, outdir):
            raw = open(p, "rb").read()
            carve_broken(raw, outdir, rep)
        self._run_module(fn)

    def _m_bkcrack(self):
        enc = filedialog.askopenfilename(title="选择【加密】zip")
        if not enc:
            return
        plain = filedialog.askopenfilename(title="选择含已知明文的【未加密】zip（可用 7z 对部分文件明文打包）")
        if not plain:
            return
        self.tool_out.delete("1.0", "end")

        def work():
            rep = Report(path=enc)
            outdir = os.path.join(WORKSPACE, "bkcrack_" + os.path.basename(enc).replace(".", "_"))
            os.makedirs(outdir, exist_ok=True)
            try:
                modules_archive.bkcrack_attack(enc, plain, rep, outdir,
                                               log=lambda m: self.q.put(("manual_log", str(m))))
            except Exception as e:
                import traceback
                rep.add("warn", "执行异常", f"{e}\n{traceback.format_exc()[:800]}")
            self.q.put(("manual", rep))
        threading.Thread(target=work, daemon=True).start()

    def _m_crcsuite(self):
        folder = filedialog.askdirectory(title="选择包含一批加密小 zip（out0.zip、out1.zip…）的目录")
        if not folder:
            return
        self.tool_out.delete("1.0", "end")

        def work():
            import glob
            paths = sorted(glob.glob(os.path.join(folder, "*.zip")))
            rep = Report(path=folder)
            outdir = os.path.join(WORKSPACE, "crcsuite_" + os.path.basename(folder))
            os.makedirs(outdir, exist_ok=True)
            if len(paths) < 2:
                rep.add("warn", "CRC 套件", "目录中不足 2 个 zip")
            else:
                try:
                    modules_archive.analyze_crc_suite(paths, rep, outdir)
                except Exception as e:
                    import traceback
                    rep.add("warn", "执行异常", f"{e}\n{traceback.format_exc()[:800]}")
            self.q.put(("manual", rep))
        threading.Thread(target=work, daemon=True).start()

    # ===================================================================
    # Web / Pwn 页
    # ===================================================================
    def _build_web(self):
        wrap = ctk.CTkFrame(self.t_web)
        wrap.pack(fill="both", expand=True, padx=6, pady=6)

        libbar = ctk.CTkFrame(wrap)
        libbar.pack(fill="x", padx=6, pady=(6, 0))
        ctk.CTkLabel(libbar, text="可复制脚本库：", text_color="#9fb4c8").pack(side="left", padx=(6, 2))
        ctk.CTkButton(libbar, text="📚 Web 脚本/payload", width=170, fg_color="#444", hover_color="#555",
                      command=lambda: self._goto_scripts("web")).pack(side="left", padx=4, pady=4)
        ctk.CTkButton(libbar, text="📚 Pwn 利用脚本", width=150, fg_color="#444", hover_color="#555",
                      command=lambda: self._goto_scripts("pwn")).pack(side="left", padx=4, pady=4)

        wf = ctk.CTkFrame(wrap)
        wf.pack(fill="x", padx=6, pady=6)
        ctk.CTkLabel(wf, text="◎ Web  目标 URL / 主机", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=8)
        row = ctk.CTkFrame(wf)
        row.pack(fill="x", padx=6, pady=4)
        self.web_url = ctk.CTkEntry(row, placeholder_text="http://target/ 或 10.10.10.10")
        self.web_url.pack(side="left", fill="x", expand=True, padx=4)
        ctk.CTkButton(row, text="HTTP探测", width=100, command=self._w_probe).pack(side="left", padx=3)
        ctk.CTkButton(row, text="目录扫描", width=100, command=self._w_dirs).pack(side="left", padx=3)
        ctk.CTkButton(row, text="sqlmap", width=100, fg_color="#a8071a",
                      hover_color="#870809", command=self._w_sqlmap).pack(side="left", padx=3)
        row2 = ctk.CTkFrame(wf)
        row2.pack(fill="x", padx=6, pady=4)
        ctk.CTkLabel(row2, text="端口范围(空=常见1000)").pack(side="left", padx=4)
        self.port_range = ctk.CTkEntry(row2, width=140, placeholder_text="1-65535")
        self.port_range.pack(side="left")
        ctk.CTkButton(row2, text="端口扫描(nmap优先)", width=170, command=self._w_ports).pack(side="left", padx=6)

        pf = ctk.CTkFrame(wrap)
        pf.pack(fill="x", padx=6, pady=6)
        ctk.CTkLabel(pf, text="◎ Pwn  二进制 / 远程", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=8)
        pr = ctk.CTkFrame(pf)
        pr.pack(fill="x", padx=6, pady=4)
        ctk.CTkButton(pr, text="选择ELF并checksec", width=170, command=self._w_checksec).pack(side="left", padx=4)
        ctk.CTkLabel(pr, text="IP").pack(side="left", padx=(10, 2))
        self.pwn_host = ctk.CTkEntry(pr, width=130)
        self.pwn_host.insert(0, "127.0.0.1")
        self.pwn_host.pack(side="left")
        ctk.CTkLabel(pr, text="端口").pack(side="left", padx=(6, 2))
        self.pwn_port = ctk.CTkEntry(pr, width=80)
        self.pwn_port.insert(0, "9999")
        self.pwn_port.pack(side="left")
        ctk.CTkButton(pr, text="生成 pwntools exp 模板", width=180, command=self._w_exp).pack(side="left", padx=8)

        self.web_out = ctk.CTkTextbox(wrap, font=ctk.CTkFont(family="Consolas", size=12))
        self.web_out.pack(fill="both", expand=True, padx=6, pady=6)

    def _wlog(self, m):
        self.q.put(("web", str(m) + "\n"))

    def _w_probe(self):
        u = self.web_url.get().strip()
        threading.Thread(target=lambda: webtools.http_probe(u, self._wlog), daemon=True).start()

    def _w_dirs(self):
        u = self.web_url.get().strip()
        threading.Thread(target=lambda: webtools.dir_scan(u, self._wlog), daemon=True).start()

    def _w_ports(self):
        u = self.web_url.get().strip().replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        pr = self.port_range.get().strip() or None
        threading.Thread(target=lambda: webtools.port_scan(u, pr, self._wlog), daemon=True).start()

    def _w_sqlmap(self):
        u = self.web_url.get().strip()
        if not u.startswith("http"):
            messagebox.showinfo("提示", "sqlmap 需要完整 URL（含参数的页面）")
            return
        threading.Thread(target=lambda: webtools.sqlmap_run(u, self._wlog), daemon=True).start()

    def _w_checksec(self):
        p = filedialog.askopenfilename(title="选择 ELF 二进制")
        if not p:
            return
        def work():
            from .modules_reverse import analyze_elf
            rep = Report(path=p)
            outdir = os.path.join(WORKSPACE, "pwn_" + os.path.basename(p))
            os.makedirs(outdir, exist_ok=True)
            try:
                analyze_elf(p, rep, outdir)
            except Exception as e:
                rep.add("warn", "异常", str(e))
            self.q.put(("web_report", rep))
        threading.Thread(target=work, daemon=True).start()

    def _w_exp(self):
        p = filedialog.askopenfilename(title="选择本地 ELF（可取消，默认文件名 pwn）")
        name = os.path.basename(p) if p else "pwn"
        fp = webtools.make_exp(name, self.pwn_host.get().strip(), int(self.pwn_port.get()))
        self._wlog(f"[+] exp 模板已生成: {fp}\n    本地调试: python {fp}\n    远程: python {fp} r")

    # ===================================================================
    # 工具中心
    # ===================================================================
    def _build_center(self):
        top = ctk.CTkFrame(self.t_center)
        top.pack(fill="x", padx=6, pady=6)
        ctk.CTkLabel(top, text="便携工具统一放在 tools/portable/，仅从官方 GitHub/官网下载；"
                               "商业软件(IDA/Xshell)请自备正版，逆向推荐 Ghidra/x64dbg。",
                     text_color="#faad14", wraplength=1100, justify="left").pack(anchor="w", padx=10, pady=6)
        ctk.CTkButton(top, text="一键预置全部工具与运行时", width=230,
                      fg_color="#a8071a", hover_color="#870809",
                      command=self._predownload_all).pack(side="right", padx=4)
        ctk.CTkButton(top, text="补全便携运行时(JRE/Node/FFmpeg)", width=270,
                      fg_color="#1d6fa5", hover_color="#15547d",
                      command=self._bootstrap_runtime).pack(side="right", padx=4)
        ctk.CTkButton(top, text="刷新检测状态", width=130, command=self._refresh_center).pack(side="right", padx=8)

        self.center_scroll = ctk.CTkScrollableFrame(self.t_center)
        self.center_scroll.pack(fill="both", expand=True, padx=6)
        self.center_rows = {}
        logf = ctk.CTkFrame(self.t_center)
        logf.pack(fill="both", padx=6, pady=6)
        ctk.CTkLabel(logf, text="安装日志").pack(anchor="w", padx=8)
        self.center_log = ctk.CTkTextbox(logf, height=160, font=ctk.CTkFont(family="Consolas", size=12))
        self.center_log.pack(fill="x", padx=8, pady=(0, 8))
        self._refresh_center()

    def _clog(self, m):
        self.q.put(("center", str(m) + "\n"))

    def _refresh_center(self):
        for w in self.center_scroll.winfo_children():
            w.destroy()
        self.center_rows.clear()
        status = toolsmgr.detect_all()
        for key, (cn, desc, kind) in toolsmgr.TOOL_META.items():
            row = ctk.CTkFrame(self.center_scroll)
            row.pack(fill="x", pady=3, padx=2)
            p = status.get(key)
            dot = "● 已就绪" if p else "○ 未安装"
            color = "#3ecf8e" if p else "#8c8c8c"
            ctk.CTkLabel(row, text=dot, text_color=color, width=90).pack(side="left", padx=(8, 4))
            ctk.CTkLabel(row, text=cn, width=150, anchor="w",
                         font=ctk.CTkFont(weight="bold")).pack(side="left")
            ctk.CTkLabel(row, text=desc, anchor="w", text_color="#aab2bd").pack(side="left", fill="x", expand=True)
            if p:
                ctk.CTkButton(row, text="启动", width=80,
                              command=lambda k=key: self._launch_center(k)).pack(side="right", padx=6, pady=3)
            else:
                if kind == "portable":
                    ctk.CTkButton(row, text="一键下载安装", width=120,
                                  command=lambda k=key: self._install_center(k)).pack(side="right", padx=6, pady=3)
                elif kind.startswith("winget:"):
                    pkg = kind.split(":", 1)[1]
                    ctk.CTkButton(row, text=f"winget 安装", width=120,
                                  command=lambda x=pkg: self._winget_center(x)).pack(side="right", padx=6, pady=3)
                elif kind.startswith("pip:"):
                    pkg = kind.split(":", 1)[1]
                    ctk.CTkButton(row, text="pip 安装", width=120,
                                  command=lambda x=pkg: self._pip_center(x)).pack(side="right", padx=6, pady=3)
                elif kind == "wsl":
                    ctk.CTkButton(row, text="安装 Kali(WSL2)", width=140,
                                  command=self._kali_install).pack(side="right", padx=6, pady=3)
                    ctk.CTkButton(row, text="Kali 装全套CTF工具", width=160,
                                  command=self._kali_suite).pack(side="right", padx=2, pady=3)
                elif kind.startswith("runtime:"):
                    rt = kind.split(":", 1)[1]
                    ctk.CTkButton(row, text="下载便携运行时", width=130,
                                  command=lambda x=rt: self._install_runtime(x)).pack(side="right", padx=6, pady=3)
                elif kind.startswith("guide"):
                    url = kind.split(":", 1)[1] if ":" in kind else ""
                    ctk.CTkButton(row, text="打开官网指引", width=120,
                                  command=lambda u=url: self._open_url(u)).pack(side="right", padx=6, pady=3)
                elif kind == "path":
                    ctk.CTkLabel(row, text="（安装后自动识别 PATH）", text_color="#8c8c8c").pack(side="right", padx=10)
            self.center_rows[key] = (row, p)

    def _launch_center(self, key):
        if key == "kali":
            # Kali 是用户显式打开的交互式控制台，需保留独立窗口
            subprocess.Popen(["wsl", "-d", "kali-linux"],
                             creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0x10))
            return
        if key.startswith("volatility") or key == "binwalk":
            self.q.put(("center", "[i] 该工具为命令行/pip 模块，在终端中调用，软件分析时会自动调用\n"))
            return
        if key in ("ffmpeg", "ffprobe", "wabt", "java", "node"):
            p = toolsmgr.detect_one(key)
            self.q.put(("center", f"[i] {key} 为命令行运行时，已就绪并由软件内部静默调用：\n{p}\n"))
            return
        ok, msg = toolsmgr.launch(key)
        if not ok:
            self.q.put(("center", f"[!] 启动失败: {msg}\n"))

    def _install_runtime(self, rt):
        def work():
            self._clog(f"[*] 下载便携运行时 {rt} …")
            ok, msg = toolsmgr.install_runtime(rt, log=lambda m: self._clog(m),
                                               progress=lambda d, t: self._clog(f"\r下载中 {d*100//t}%"))
            self._clog(("[+] " if ok else "[!] ") + msg)
            self.q.put(("refresh", None))
        threading.Thread(target=work, daemon=True).start()

    def _bootstrap_runtime(self):
        if not messagebox.askyesno("确认", "将把 JRE21 / Node / FFmpeg 便携版下载到软件主目录 tools/runtime，\n"
                                          "用于在没有环境的电脑上即开即用，是否继续？"):
            return

        def work():
            rep = toolsmgr.bootstrap_runtimes(log=lambda m: self._clog(m),
                                              progress=lambda d, t: self._clog(f"\r下载中 {d*100//t}%"))
            ok_all = all(v[0] for v in rep.values())
            self._clog("[+] 便携运行时全部就绪" if ok_all else "[!] 部分运行时未就绪，见上方日志")
            self.q.put(("refresh", None))
        threading.Thread(target=work, daemon=True).start()

    def _predownload_all(self):
        if not messagebox.askyesno("确认",
                                   "将一次性下载【全部开源便携工具 + JRE/Node/FFmpeg 运行时】到软件目录，\n"
                                   "总量约 1～2 GB（含 Ghidra），耗时取决于网速，失败项会跳过并记录。\n"
                                   "是否现在开始？"):
            return

        def work():
            self._clog("############ 开始一键预置（后台进行，可切换页面）############")
            rep = toolsmgr.predownload_all(log=lambda m: self._clog(m),
                                           progress=lambda d, t: self._clog(f"\r下载中 {d*100//t}%"))
            rt_ok = sum(1 for v in rep["runtime"].values() if v[0])
            tk_ok = sum(1 for v in rep["tools"].values() if v[0])
            self._clog(f"############ 预置结束：运行时 {rt_ok}/{len(rep['runtime'])}，"
                       f"工具 {tk_ok}/{len(rep['tools'])} ############")
            self.q.put(("refresh", None))
        threading.Thread(target=work, daemon=True).start()

    def _install_center(self, key):
        def work():
            self._clog(f"[*] 开始下载 {key} …")
            ok, msg = toolsmgr.install_portable(key, log=lambda m: self._clog(m),
                                                progress=lambda d, t: self._clog(
                                                    f"\r下载中 {d*100//t}%"))
            self._clog(("[+] 安装成功" if ok else "[!] 安装失败") + f": {msg}")
            self.q.put(("refresh", None))
        threading.Thread(target=work, daemon=True).start()

    def _winget_center(self, pkg):
        def work():
            self._clog(f"[*] winget 安装 {pkg}（可能弹出 UAC，请确认）…")
            ok, out = toolsmgr.winget_install(pkg)
            self._clog(("[+] 完成" if ok else "[!] 失败") + "\n" + out[-1500:])
            self.q.put(("refresh", None))
        threading.Thread(target=work, daemon=True).start()

    def _pip_center(self, pkg):
        def work():
            self._clog(f"[*] pip 安装 {pkg} …")
            ok, out = toolsmgr.pip_install(pkg)
            self._clog(("[+] 完成" if ok else "[!] 失败") + "\n" + out[-1500:])
            self.q.put(("refresh", None))
        threading.Thread(target=work, daemon=True).start()

    def _kali_install(self):
        def work():
            ok, out = toolsmgr.wsl_install_kali(log=self._clog)
            self._clog(("[+] 完成" if ok else "[!] 失败/需重启") + "\n" + out)
            self.q.put(("refresh", None))
        threading.Thread(target=work, daemon=True).start()

    def _kali_suite(self):
        def work():
            self._clog("[*] 在 Kali 中安装全套 CTF 工具，耗时较长…")
            ok, out = toolsmgr.wsl_kali_setup_tools(log=self._clog)
            self._clog(("[+] 完成" if ok else "[!] 失败") + "\n" + out[-2000:])
        threading.Thread(target=work, daemon=True).start()

    def _open_url(self, url):
        if url:
            os.startfile(url)

    # ===================================================================
    # 媒体中心
    # ===================================================================
    def _build_media(self):
        from .ui_media import MediaFrame
        self.media = MediaFrame(self.t_media)
        self.media.pack(fill="both", expand=True)

    # ===================================================================
    # 网页导航（离线镜像优先）
    # ===================================================================
    def _build_webnav(self):
        from . import webnav
        wrap = ctk.CTkScrollableFrame(self.t_nav)
        wrap.pack(fill="both", expand=True, padx=6, pady=6)
        ctk.CTkLabel(wrap, text="绿色=已镜像到软件目录、断网可用；灰色=在线打开（仅收录正当 CTF/学习工具）",
                     text_color="#3ecf8e", anchor="w").pack(fill="x", padx=8, pady=(6, 8))
        for cat, items in webnav.DATA.items():
            cf = ctk.CTkFrame(wrap)
            cf.pack(fill="x", padx=6, pady=6)
            ctk.CTkLabel(cf, text=cat, font=ctk.CTkFont(size=14, weight="bold"),
                         anchor="w").pack(fill="x", padx=10, pady=(8, 2))
            for name, url, okey, desc in items:
                row = ctk.CTkFrame(cf, fg_color="transparent")
                row.pack(fill="x", padx=10, pady=2)
                off = webnav.offline_path(okey) if okey else None
                if off:
                    ctk.CTkButton(row, text="● 离线打开", width=110, fg_color="#237804",
                                  hover_color="#135200",
                                  command=lambda p=off: os.startfile(p)).pack(side="left")
                    ctk.CTkButton(row, text=name, width=200, fg_color="#2f3a4a", hover_color="#3a475a",
                                  command=lambda u=url: os.startfile(u)).pack(side="left", padx=6)
                else:
                    ctk.CTkButton(row, text="在线打开", width=110, fg_color="#1d6fa5",
                                  hover_color="#15547d",
                                  command=lambda u=url: os.startfile(u)).pack(side="left")
                    ctk.CTkLabel(row, text=name, width=200, anchor="w").pack(side="left", padx=6)
                ctk.CTkLabel(row, text=desc, text_color="#9aa4b2", anchor="w").pack(side="left", fill="x", expand=True)
        ctk.CTkButton(wrap, text="重新镜像离线网页（CyberChef 等，需联网）", width=300,
                      fg_color="#595959", hover_color="#434343",
                      command=self._remirror_web).pack(pady=10)

    def _remirror_web(self):
        def work():
            self.q.put(("center", "[*] 开始重新镜像离线网页工具…\n"))
            import subprocess
            from .common import IS_FROZEN, APP_DIR
            if IS_FROZEN:
                script = os.path.join(APP_DIR, "_mirror_webtools.py")
            else:
                script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                      "_mirror_webtools.py")
            if not os.path.exists(script):
                self.q.put(("center", f"[!] 镜像脚本缺失: {script}（打包不完整），无法重新镜像。\n"))
                return
            py = external_python()
            if not py:
                self.q.put(("center", "[!] 未找到可用的 Python 解释器（随包便携 Python 缺失且系统未装 Python），无法镜像。\n"))
                return
            r = subprocess.run([py, script], capture_output=True, text=True,
                               errors="replace", cwd=os.path.dirname(script))
            out = (r.stdout or "")[-2500:] + (r.stderr or "")[-800:]
            self.q.put(("center", out + "\n[+] 镜像结束，可重新打开本页查看离线状态\n"))
            self.q.put(("rebuild_nav", None))
        threading.Thread(target=work, daemon=True).start()

    # ===================================================================
    # 队列分发
    # ===================================================================
    def _on_tab(self):
        pass

    def _goto_scripts(self, cat="all"):
        """跳转到脚本库标签页并预选方向。"""
        self.tabs.set("📚 脚本库")
        self.scripts_lib.select_category(cat)

    def _clear_box(self, box):
        box.delete("1.0", "end")

    def _center_log(self, m):
        self.center_log.insert("end", m)
        self.center_log.see("end")

    def _render_manual(self, rep):
        self.tool_out.delete("1.0", "end")
        for fnd in rep.findings:
            self.tool_out.insert("end", f"● {fnd.title}\n", fnd.level)
            if fnd.detail:
                self.tool_out.insert("end", f"    {fnd.detail}\n\n", fnd.level + "_d")
        if rep.extracted:
            self.tool_out.insert("end", "\n提取/生成的文件:\n", "ok")
            for p in rep.extracted:
                self.tool_out.insert("end", f"  {p}\n", "info_d")

    def _drain(self):
        try:
            while True:
                kind, val = self.q.get_nowait()
                if kind == "log":
                    m, token = val
                    if token == self._run_token:
                        self.ana_log.insert("end", m + "\n")
                        self.ana_log.see("end")
                elif kind == "report":
                    rep, token = val
                    if token != self._run_token:
                        continue
                    self._configure_tags()
                    self._render_report(rep)
                    self.last_report = rep
                    files = []
                    def walk(r):
                        for fp in r.extracted:
                            files.append(fp)
                        for c in r.children:
                            walk(c)
                    walk(rep)
                    existing = self.extract_box.get("1.0", "end")
                    for fp in dict.fromkeys(files):
                        if fp not in existing:
                            self.extract_box.insert("end", fp + "\n")
                elif kind == "done":
                    token = val
                    if token == self._run_token:
                        self._busy = False
                        self._next_file()
                elif kind == "code":
                    self.code_out.insert("end", val)
                elif kind == "manual":
                    self._configure_tags()
                    self._render_manual(val)
                elif kind == "manual_log":
                    self.tool_out.insert("end", val + "\n")
                    self.tool_out.see("end")
                elif kind == "web":
                    self.web_out.insert("end", val)
                    self.web_out.see("end")
                elif kind == "web_report":
                    self.web_out.delete("1.0", "end")
                    for fnd in val.findings:
                        self.web_out.insert("end", f"● {fnd.title}\n", fnd.level)
                        if fnd.detail:
                            self.web_out.insert("end", f"    {fnd.detail}\n\n", fnd.level + "_d")
                elif kind == "center":
                    self._center_log(val)
                elif kind == "refresh":
                    self._refresh_center()
                elif kind == "rebuild_nav":
                    for w in self.t_nav.winfo_children():
                        w.destroy()
                    self._build_webnav()
        except queue.Empty:
            pass
        self.after(100, self._drain)

    def _configure_tags(self):
        # 注意：CTkTextbox.tag_config 禁止 font 参数（与缩放不兼容），仅用颜色区分
        for box in (self.report_box, self.tool_out, self.web_out):
            box.tag_config("flag", foreground="#ff7875")
            box.tag_config("ok", foreground="#52c41a")
            box.tag_config("warn", foreground="#faad14")
            box.tag_config("info", foreground="#d9d9d9")
            box.tag_config("tool", foreground="#69b1ff")
            box.tag_config("flag_d", foreground="#ff9c97")
            box.tag_config("ok_d", foreground="#95de64")
            box.tag_config("warn_d", foreground="#ffd666")
            box.tag_config("info_d", foreground="#aeb8c2")
            box.tag_config("title", foreground="#69b1ff")


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
