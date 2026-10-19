# -*- coding: utf-8 -*-
"""全局崩溃保护：faulthandler 抓 C 级段错误栈，excepthook 抓未处理异常，
全部写入 workspace/crash.log，避免 windowed 打包后静默闪退、无迹可查。"""
import sys
import os
import time
import faulthandler
import threading
import traceback

_log_fp = None
LOG_PATH = None


def _write(banner, msg):
    global _log_fp
    if _log_fp is None:
        return
    try:
        _log_fp.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] {banner}\n{msg}\n")
        _log_fp.flush()
    except Exception:
        pass


def install():
    global _log_fp, LOG_PATH
    try:
        from .common import WORKSPACE
        os.makedirs(WORKSPACE, exist_ok=True)
        LOG_PATH = os.path.join(WORKSPACE, "crash.log")
        _log_fp = open(LOG_PATH, "a", encoding="utf-8")
        _log_fp.write(f"\n\n================ session {time.strftime('%Y-%m-%d %H:%M:%S')} "
                      f"python {sys.version.split()[0]} frozen={getattr(sys, 'frozen', False)} ================\n")
        _log_fp.flush()
        faulthandler.enable(file=_log_fp, all_threads=True)
    except Exception:
        LOG_PATH = None

    def excepthook(etype, value, tb):
        msg = "".join(traceback.format_exception(etype, value, tb))
        _write("UNCAUGHT MAIN THREAD", msg)
        try:
            import tkinter as tk
            from tkinter import messagebox
            try:
                root = tk.Tk(); root.withdraw(); root.after(0, root.destroy)
            except Exception:
                pass
            messagebox.showerror(
                "CTFToolbox 出错",
                f"发生未捕获异常，详情已记录到：\n{LOG_PATH or 'workspace/crash.log'}\n\n"
                f"{etype.__name__}: {str(value)[:600]}")
        except Exception:
            pass

    def thread_hook(args):
        msg = "".join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback))
        _write(f"UNCAUGHT THREAD {args.thread.name}", msg)

    sys.excepthook = excepthook
    threading.excepthook = thread_hook
    return LOG_PATH
