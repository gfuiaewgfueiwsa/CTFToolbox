# -*- coding: utf-8 -*-
"""CTFToolbox 启动入口。
用法：
  双击/无参数          启动图形界面
  CTFToolbox.exe --cli <文件> [文件...]   命令行批量分析（报告写入 workspace/cli_report.txt）
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 最早期安装崩溃保护（必须在重型库 import 之前）
try:
    from ctfbox.crashguard import install as _install_crashguard
    _install_crashguard()
except Exception:
    pass


def run_cli(files):
    from ctfbox.dispatcher import Dispatcher
    from ctfbox.common import WORKSPACE

    lines = []
    d = Dispatcher(log_cb=lambda m: lines.append(m))
    for f in files:
        if not os.path.isfile(f):
            lines.append(f"[!] 文件不存在: {f}")
            continue
        lines.append(f"\n########## 分析: {f} ##########")
        try:
            rep = d.run(os.path.abspath(f))
        except Exception as e:
            import traceback
            lines.append(f"[!] 分析失败: {e}\n{traceback.format_exc()}")
            continue

        def walk(r, depth=0):
            indent = "    " * depth
            lines.append(f"{indent}== {r.path} [{r.ftype}]")
            for fnd in r.findings:
                icon = {"flag": "!!!", "ok": "+", "warn": "!", "info": "*"}.get(fnd.level, "*")
                lines.append(f"{indent} [{icon}] {fnd.title}")
                if fnd.detail:
                    for ln in str(fnd.detail).splitlines()[:40]:
                        lines.append(f"{indent}     {ln}")
            for c in r.children:
                walk(c, depth + 1)
        walk(rep)
        lines.append("")

    out = os.path.join(WORKSPACE, "cli_report.txt")
    os.makedirs(WORKSPACE, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines))
    return out


if __name__ == "__main__":
    # Windows(spawn) + PyInstaller 下 CRC 多进程批量碰撞必需，且必须尽早调用
    try:
        import multiprocessing
        multiprocessing.freeze_support()
    except Exception:
        pass

    if len(sys.argv) > 1 and sys.argv[1] in ("--cli", "-c"):
        # CLI 模式统一 UTF-8 输出，避免 PowerShell/cmd 默认 GBK 代码页下中文乱码
        # （报告文件本身始终为 UTF-8，这里只修控制台/重定向输出层）。
        if sys.platform.startswith("win"):
            try:
                os.system("chcp 65001 >nul 2>nul")
            except Exception:
                pass
        for _s in (sys.stdout, sys.stderr):
            try:
                _s.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass
        report_path = run_cli(sys.argv[2:])
        try:
            if sys.stdout:
                print("report written to:", report_path)
        except Exception:
            pass
    else:
        try:
            from ctfbox.ui_main import main
            main()
        except Exception:
            # 兜底：启动期异常写入 crash.log 并弹框，避免双击后窗口一闪而过
            import traceback, time
            try:
                from ctfbox.common import WORKSPACE
                os.makedirs(WORKSPACE, exist_ok=True)
                with open(os.path.join(WORKSPACE, "crash.log"), "a", encoding="utf-8") as fp:
                    fp.write(f"\n[STARTUP FAILURE {time.strftime('%Y-%m-%d %H:%M:%S')}]\n")
                    fp.write(traceback.format_exc())
                from tkinter import Tk, messagebox
                r = Tk(); r.withdraw()
                messagebox.showerror("CTFToolbox 启动失败",
                                     "启动出错，详情见 workspace/crash.log\n\n" + traceback.format_exc()[-800:])
            except Exception:
                raise
