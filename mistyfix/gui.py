"""MistyFix 图形界面（tkinter/ttk，随 Python 自带，零额外依赖）。

用法::

    mistyfix gui [binary]        # 推荐
    mistyfix-gui [binary]        # 安装后的独立入口
    python -m mistyfix.gui [binary]

界面结构：顶部目标文件栏 + 信息条，中部按功能分标签页
（概览 / 修复 read / 修复 free / 符号改名 / 整数比较 / 合规检测 /
功能测试 / 沙箱研究），底部类终端日志。所有耗时操作在后台线程
执行，经队列回到 UI 线程，界面不会卡死。
"""

from __future__ import annotations

import os
import queue
import sys
import threading
import traceback
from pathlib import Path
from typing import Callable

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

if __package__ in ("mistyfix", None):  # 作为包模块导入
    from . import __version__
    from .checker import CheckResult, ComplianceChecker, FunctionalTester, replay_exp
    from .elf_utils import ELFBinary, ELFError
    from .injector import apply_install, plan_install
    from .patcher import Patcher, PatchError
    from .sandbox import build_seccomp_stub, parse_syscall_list, rules_warning
    from .strategies import (
        PatchPlan,
        dynstr_rename,
        fix_int_compare,
        fix_read_length,
        true_fix_free,
    )
else:  # python mistyfix/gui.py 直接运行
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from mistyfix import __version__
    from mistyfix.checker import CheckResult, ComplianceChecker, FunctionalTester, replay_exp
    from mistyfix.elf_utils import ELFBinary, ELFError
    from mistyfix.injector import apply_install, plan_install
    from mistyfix.patcher import Patcher, PatchError
    from mistyfix.sandbox import build_seccomp_stub, parse_syscall_list, rules_warning
    from mistyfix.strategies import (
        PatchPlan,
        dynstr_rename,
        fix_int_compare,
        fix_read_length,
        true_fix_free,
    )

__all__ = ["MistyFixGUI", "run_gui", "main"]


# ---------------------------------------------------------------------------
# 外观常量
# ---------------------------------------------------------------------------
_UI_FONT = ("Microsoft YaHei UI", 10)
_UI_FONT_BOLD = ("Microsoft YaHei UI", 10, "bold")
_UI_FONT_SMALL = ("Microsoft YaHei UI", 9)
_MONO_FONT = ("Consolas", 10)
_MONO_FONT_SMALL = ("Consolas", 9)

_ACCENT = "#2563eb"          # 主色（按钮/链接）
_ACCENT_HOVER = "#1d4ed8"
_PASS = "#15803d"            # PASS 绿
_PASS_BG = "#eaf7ec"
_FAIL = "#dc2626"            # FAIL 红
_FAIL_BG = "#fdecec"
_WARN = "#b45309"            # WARN 琥珀
_WARN_BG = "#fff7e6"
_BG = "#f5f6f8"
_BORDER = "#d9dce1"

_LOG_BG = "#161b22"
_LOG_FG = "#c9d1d9"
_LOG_TAGS = {
    "info": "#79b8ff",    # [*]
    "ok": "#7ee787",      # [+]
    "err": "#ff7b72",     # [!]
    "warn": "#e3b341",    # WARN
    "dim": "#8b949e",     # 提示/分隔
}

# fix-read 可选的输入类函数（策略改写其长度参数立即数）
_READ_FUNCS = ("read", "recv", "recvfrom", "fgets", "fread")

_SCRIPT_TEMPLATE = """\
# 交互脚本：模拟正常业务流程（按题目实际情况修改）
# 可用对象: p(进程) / send / sendline / recv / recvline / recvuntil / time / os
recvuntil(b"choice")
sendline(b"1")
recvline()
"""


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------
def parse_addr(text: str) -> int | None:
    """解析地址/立即数：支持 0x 前缀十六进制、十进制、纯十六进制数字。"""
    text = text.strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        pass
    try:  # "4011a3" 这类无前缀十六进制
        return int(text, 16)
    except ValueError:
        return None


def _fmt_hex(value: int, width: int = 12) -> str:
    return f"0x{value:0{width}x}"


def _disasm_around(elf: ELFBinary, center: int, back: int = 48, fwd: int = 16):
    """反汇编 center 前后的指令。返回 [(addr, text, is_target)]。

    向前回扫时逐字节微调起点，直到解码流恰好结束在 center（与真实指令
    边界对齐），避免从指令中间开始解码导致的错位。
    """
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

    md = Cs(CS_ARCH_X86, CS_MODE_64 if elf.arch == "amd64" else CS_MODE_32)

    def insns_at(start: int, end: int):
        off = elf.vaddr_to_offset(start)
        code = bytes(elf.data[off : off + (end - start)])
        return list(md.disasm(code, start))

    pre: list = []
    start = max(0, center - back)
    for nudge in range(back):
        cand = insns_at(start + nudge, center)
        if cand and cand[-1].address + cand[-1].size == center:
            pre = cand
            break
    off = elf.vaddr_to_offset(center)
    post = list(md.disasm(bytes(elf.data[off : off + fwd]), center))

    rows = []
    for i in pre[-8:]:
        rows.append((i.address, f"{i.mnemonic} {i.op_str}".strip(), False))
    for i in post[:6]:
        rows.append((i.address, f"{i.mnemonic} {i.op_str}".strip(), True))
    return rows


# ---------------------------------------------------------------------------
# 可勾选的调用点清单（批量修复选择器）
# ---------------------------------------------------------------------------
class _SiteList:
    """扫描到的调用点列表：勾选参与批量修复，支持手动补充地址。

    Treeview 无原生复选框，第一列用 ☑/☐ 文本模拟（点击切换）；
    选中行触发 on_select(vaddr) 供指令预览刷新。
    """

    def __init__(self, parent: ttk.Frame, insn_lookup: Callable[[int], str],
                 on_select: Callable[[int], None] | None = None,
                 on_change: Callable[[], None] | None = None) -> None:
        self.insn_lookup = insn_lookup
        self.on_select = on_select
        self.on_change = on_change
        self.checked: set[str] = set()
        self.addrs: dict[str, int] = {}

        bar = ttk.Frame(parent)
        bar.pack(fill="x", pady=(2, 4))
        ttk.Button(bar, text="全选", width=6,
                   command=lambda: self.set_all(True)).pack(side="left")
        ttk.Button(bar, text="全不选", width=7,
                   command=lambda: self.set_all(False)).pack(side="left", padx=(6, 0))
        # 内联地址输入：输入 vaddr 回车或点「＋添加」直接入列（无需弹窗）
        self.addr_var = tk.StringVar()
        addr_entry = ttk.Entry(bar, textvariable=self.addr_var, width=16)
        addr_entry.pack(side="left", padx=(12, 0))
        addr_entry.bind("<Return>", lambda _e: self.add_from_entry())
        ttk.Button(bar, text="＋添加", width=7,
                   command=self.add_from_entry).pack(side="left", padx=(6, 0))
        ttk.Label(bar, text="勾选要修复的调用点，可批量执行；地址支持 0x/十进制/纯十六进制",
                  style="DimCard.TLabel").pack(side="left", padx=10)

        frame = ttk.Frame(parent)
        self.tree = ttk.Treeview(frame, columns=["sel", "vaddr", "insn"],
                                 show="headings", height=6, selectmode="browse")
        for cid, text, width, anchor in (("sel", "修", 40, "center"),
                                         ("vaddr", "地址", 110, "e"),
                                         ("insn", "指令", 340, "w")):
            self.tree.heading(cid, text=text)
            self.tree.column(cid, width=width, anchor=anchor, stretch=(cid == "insn"))
        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        frame.pack(fill="x", pady=(0, 2))

        self.tree.bind("<Button-1>", self._on_click)
        self.tree.bind("<<TreeviewSelect>>", self._on_selected)

    # ------------------------------------------------------------------
    def clear(self) -> None:
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.checked.clear()
        self.addrs.clear()
        self._notify()

    def set_sites(self, hits: list[int]) -> None:
        """用扫描结果重建列表，默认全部勾选。"""
        self.clear()
        for vaddr in hits:
            self._insert(vaddr, True)
        self._notify()
        children = self.tree.get_children()
        if children:
            self.tree.selection_set(children[0])

    def add_from_entry(self) -> None:
        """把内联地址输入框的内容解析后加入清单（勾选状态）。"""
        text = self.addr_var.get().strip()
        if not text:
            messagebox.showinfo("提示", "请先在输入框中填写调用点地址。")
            return
        vaddr = parse_addr(text)
        if vaddr is None:
            messagebox.showerror("错误", f"无效的地址: {text!r}")
            return
        iid = hex(vaddr)
        if iid in self.addrs:
            messagebox.showinfo("提示", f"0x{vaddr:x} 已在列表中。")
            return
        self._insert(vaddr, True)
        self.tree.see(iid)
        self.tree.selection_set(iid)
        self.addr_var.set("")
        self._notify()

    def add_manual(self) -> None:
        """通过对话框手动添加调用点（内联输入框的弹窗后备）。"""
        text = simpledialog.askstring(
            "手动添加调用点", "调用点 vaddr（支持 0x / 十进制 / 纯十六进制）：")
        if not text:
            return
        self.addr_var.set(text)
        self.add_from_entry()

    def set_all(self, state: bool) -> None:
        for iid in self.addrs:
            if state:
                self.checked.add(iid)
            else:
                self.checked.discard(iid)
            self.tree.set(iid, "sel", "☑" if state else "☐")
        self._notify()

    def checked_addrs(self) -> list[int]:
        return [self.addrs[iid] for iid in self.tree.get_children() if iid in self.checked]

    # ------------------------------------------------------------------
    def _insert(self, vaddr: int, checked: bool) -> None:
        iid = hex(vaddr)
        self.addrs[iid] = vaddr
        if checked:
            self.checked.add(iid)
        self.tree.insert("", "end", iid=iid, values=(
            "☑" if checked else "☐", _fmt_hex(vaddr, 6), self.insn_lookup(vaddr)))

    def _on_click(self, event: tk.Event) -> None:
        if self.tree.identify("region", event.x, event.y) != "cell":
            return
        if self.tree.identify_column(event.x) != "#1":  # 仅「修」列切换勾选
            return
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        if iid in self.checked:
            self.checked.discard(iid)
            self.tree.set(iid, "sel", "☐")
        else:
            self.checked.add(iid)
            self.tree.set(iid, "sel", "☑")
        self._notify()

    def _on_selected(self, _event: tk.Event) -> None:
        sel = self.tree.selection()
        if sel and self.on_select:
            self.on_select(self.addrs[sel[0]])

    def _notify(self) -> None:
        if self.on_change:
            self.on_change()


# ---------------------------------------------------------------------------
# 主界面
# ---------------------------------------------------------------------------
class MistyFixGUI:
    def __init__(self, root: tk.Tk, initial_binary: str | None = None) -> None:
        self.root = root
        self.elf: ELFBinary | None = None
        self.elf_path: str = ""

        self._queue: queue.Queue[Callable[[], None]] = queue.Queue()
        self._busy_count = 0
        self.last_fix_stats: dict = {"applied": 0, "total": 0, "label": ""}

        self._setup_window()
        self._setup_style()
        self._build_menu()
        self._build_header()
        self._build_file_bar()
        self._build_info_bar()
        self._build_notebook()
        self._build_log_panel()

        self.root.after(60, self._poll_queue)
        self.log("info", f"MistyFix {__version__} 图形界面已就绪（tkinter {tk.TkVersion}）")
        self.log("dim", "提示: 先在顶部选择目标 ELF 文件，再使用下方各功能标签页。")

        if initial_binary:
            self._set_binary_path(initial_binary)
            self.load_binary()

    # ------------------------------------------------------------------ 窗口
    def _setup_window(self) -> None:
        self.root.title("MistyFix — AWDP PWN 合规修复工作台")
        self.root.geometry("1120x780")
        self.root.minsize(940, 660)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        try:
            self.root.tk.call("tk", "scaling", 1.25)
        except tk.TclError:
            pass

    def _on_close(self) -> None:
        """退出前释放 LIEF 对象，避免 lief/nanobind 在解释器关闭时报泄漏。"""
        import gc

        self.elf = None
        gc.collect()
        self.root.destroy()

    def _setup_style(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(".", font=_UI_FONT, background=_BG)
        style.configure("TFrame", background=_BG)
        style.configure("TLabel", background=_BG, foreground="#24292f")
        style.configure("Card.TFrame", background="#ffffff", relief="solid", borderwidth=1)
        style.configure("Card.TLabel", background="#ffffff", foreground="#24292f")
        style.configure("H1.TLabel", font=("Microsoft YaHei UI", 15, "bold"),
                        foreground="#111418")
        style.configure("Dim.TLabel", foreground="#6e7781", font=_UI_FONT_SMALL)
        style.configure("DimCard.TLabel", background="#ffffff", foreground="#6e7781",
                        font=_UI_FONT_SMALL)
        style.configure("Mono.TLabel", font=_MONO_FONT)

        style.configure("TButton", padding=(12, 5))
        style.configure("Accent.TButton", foreground="#ffffff", background=_ACCENT,
                        padding=(14, 5), font=_UI_FONT_BOLD, borderwidth=0)
        style.map("Accent.TButton",
                  background=[("active", _ACCENT_HOVER), ("disabled", "#9db8f0")],
                  foreground=[("disabled", "#eef2fb")])
        style.configure("Danger.TButton", foreground="#ffffff", background=_FAIL,
                        padding=(14, 5), font=_UI_FONT_BOLD, borderwidth=0)
        style.map("Danger.TButton",
                  background=[("active", "#b91c1c"), ("disabled", "#e5a3a3")])

        style.configure("TNotebook", background=_BG, borderwidth=0, tabmargins=(8, 6, 0, 0))
        style.configure("TNotebook.Tab", font=_UI_FONT, padding=(14, 7))
        style.map("TNotebook.Tab",
                  background=[("selected", "#ffffff"), ("!selected", "#e7e9ee")],
                  foreground=[("selected", _ACCENT), ("!selected", "#57606a")])

        style.configure("Treeview", font=_UI_FONT_SMALL, rowheight=26,
                        background="#ffffff", fieldbackground="#ffffff")
        style.configure("Treeview.Heading", font=_UI_FONT_BOLD, padding=(6, 4))
        style.map("Treeview", background=[("selected", "#dbe7fb")],
                  foreground=[("selected", "#111418")])

        style.configure("TLabelframe", background="#ffffff", bordercolor=_BORDER)
        style.configure("TLabelframe.Label", background="#ffffff",
                        font=_UI_FONT_BOLD, foreground="#374151")

    # ------------------------------------------------------------------ 菜单
    def _build_menu(self) -> None:
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=False)
        file_menu.add_command(label="打开 ELF…  Ctrl+O", command=self.browse_binary)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.root.destroy)
        menubar.add_cascade(label="文件", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=False)
        help_menu.add_command(label="使用说明", command=self._show_help)
        help_menu.add_command(label="环境检查 (doctor)", command=self._run_doctor)
        help_menu.add_command(label="关于 MistyFix", command=self._show_about)
        menubar.add_cascade(label="帮助", menu=help_menu)

        self.root.config(menu=menubar)
        self.root.bind("<Control-o>", lambda e: self.browse_binary())

    # ------------------------------------------------------------------ 顶部
    def _build_header(self) -> None:
        bar = ttk.Frame(self.root, padding=(14, 10, 14, 2))
        bar.pack(fill="x")
        ttk.Label(bar, text="MistyFix", style="H1.TLabel").pack(side="left")
        ttk.Label(bar, text=f"  v{__version__}", style="Dim.TLabel").pack(side="left")
        ttk.Label(
            bar,
            text="AWDP 合规修复 · 等长替换 · code cave 注入 · 真修复拒绝 NOP",
            style="Dim.TLabel",
        ).pack(side="right")

    def _build_file_bar(self) -> None:
        bar = ttk.Frame(self.root, padding=(14, 6))
        bar.pack(fill="x")
        ttk.Label(bar, text="目标文件").pack(side="left", padx=(0, 6))
        self.path_var = tk.StringVar()
        self.path_entry = ttk.Entry(bar, textvariable=self.path_var, font=_MONO_FONT_SMALL)
        self.path_entry.pack(side="left", fill="x", expand=True, ipady=3, padx=(0, 6))
        self.path_entry.bind("<Return>", lambda e: self.load_binary())
        ttk.Button(bar, text="浏览…", command=self.browse_binary).pack(side="left", padx=(0, 6))
        self.load_btn = ttk.Button(bar, text="加载", style="Accent.TButton",
                                   command=self.load_binary)
        self.load_btn.pack(side="left", padx=(0, 12))
        self.autochain_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            bar, text="修复后自动加载产物（便于叠加修复）",
            variable=self.autochain_var).pack(side="left")

    def _build_info_bar(self) -> None:
        bar = ttk.Frame(self.root, padding=(14, 2, 14, 8))
        bar.pack(fill="x")
        self.info_vars: dict[str, tk.StringVar] = {
            k: tk.StringVar(value=v) for k, v in {
                "status": "状态: 未加载", "arch": "架构: —", "pie": "PIE: —",
                "entry": "入口: —", "size": "大小: —",
                "secs": "节: —", "caves": "cave(≥32B): —",
            }.items()
        }
        for name in ("arch", "pie", "entry", "size", "secs", "caves"):
            ttk.Label(bar, textvariable=self.info_vars[name], style="Dim.TLabel").pack(
                side="left", padx=(0, 14))
        self.status_label = ttk.Label(bar, textvariable=self.info_vars["status"],
                                      font=_UI_FONT_SMALL)
        self.status_label.pack(side="right")

    # ------------------------------------------------------------------ 基础组件
    def _form_row(self, parent: ttk.Frame, label: str,
                  make_widget: Callable[[ttk.Frame], ttk.Widget],
                  tooltip: str | None = None) -> ttk.Widget:
        """建「标签 + 输入控件」一行并返回该控件。

        make_widget(row) 必须以 row 为父容器创建控件——不能用 in_= 把
        别处的控件排进来：in_= 打包的控件不参与 row 的点击命中测试
        （点击会被堆叠序更高的兄弟行框架截住），导致看起来正常但
        无法通过点击获得焦点、无法输入。
        """
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=3)
        ttk.Label(row, text=label, width=12, anchor="e").pack(side="left", padx=(0, 8))
        widget = make_widget(row)
        widget.pack(side="left", fill="x", expand=True)
        if tooltip:
            ttk.Label(parent, text=tooltip, style="DimCard.TLabel").pack(
                fill="x", padx=(96, 0), pady=(0, 2))
        return widget

    def _path_row(self, parent: ttk.Frame, label: str, var: tk.StringVar,
                 save: bool = False) -> None:
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=3)
        ttk.Label(row, text=label, width=12, anchor="e").pack(side="left", padx=(0, 8))
        ttk.Entry(row, textvariable=var, font=_MONO_FONT_SMALL).pack(
            side="left", fill="x", expand=True, padx=(0, 6), ipady=2)
        ttk.Button(row, text="…", width=3,
                   command=lambda: self._browse_for(var, save)).pack(side="left")

    @staticmethod
    def _browse_for(var: tk.StringVar, save: bool = False) -> None:
        if save:
            path = filedialog.asksaveasfilename(title="选择输出文件")
        else:
            path = filedialog.askopenfilename(
                title="选择文件", filetypes=[("所有文件", "*.*"), ("ELF 相关", "*.elf;*.bin;*.so;*.so.*")])
        if path:
            var.set(path)

    def _make_tree(self, parent: ttk.Frame, columns: list[tuple[str, str, int, str]],
                   height: int = 10) -> ttk.Treeview:
        """建一个带滚动条的 Treeview。columns: [(id, 标题, 宽度, anchor)]"""
        frame = ttk.Frame(parent)
        tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings",
                            height=height, selectmode="browse")
        for cid, text, width, anchor in columns:
            tree.heading(cid, text=text)
            tree.column(cid, width=width, anchor=anchor, stretch=True)
        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        frame.pack(fill="both", expand=True, pady=2)
        return tree

    # ------------------------------------------------------------------ 标签页
    def _build_notebook(self) -> None:
        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=(10, 10), pady=(0, 6))

        self._build_tab_overview()
        self._build_tab_fix_read()
        self._build_tab_fix_free()
        self._build_tab_rename()
        self._build_tab_fix_cmp()
        self._build_tab_check()
        self._build_tab_test()
        self._build_tab_patch()
        self._build_tab_sandbox()

    # ---- 概览 ------------------------------------------------------------
    def _build_tab_overview(self) -> None:
        tab = ttk.Frame(self.nb, padding=10)
        self.nb.add(tab, text="  概览  ")

        left = ttk.Labelframe(tab, text="节列表 (Section Table)", padding=6)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))
        self.sections_tree = self._make_tree(
            left,
            [("name", "名称", 150, "w"), ("vaddr", "vaddr", 130, "e"),
             ("size", "size", 90, "e"), ("offset", "offset", 90, "e")],
            height=16)

        right = ttk.Labelframe(tab, text="Code Cave（可执行段空隙，注入优先 .eh_frame）", padding=6)
        right.pack(side="left", fill="both", expand=True)
        ctl = ttk.Frame(right)
        ctl.pack(fill="x", pady=(0, 4))
        ttk.Label(ctl, text="最小字节数", style="DimCard.TLabel").pack(side="left")
        self.cave_min_var = tk.IntVar(value=32)
        ttk.Spinbox(ctl, from_=16, to=4096, increment=16, width=7,
                    textvariable=self.cave_min_var).pack(side="left", padx=6)
        ttk.Button(ctl, text="刷新", command=self.refresh_caves).pack(side="left")
        ttk.Label(ctl, text="stub 注入候选区", style="DimCard.TLabel").pack(
            side="left", padx=8)
        self.caves_tree = self._make_tree(
            right,
            [("section", "所在节", 120, "w"), ("vaddr", "vaddr", 130, "e"),
             ("foffset", "文件偏移", 90, "e"), ("size", "大小(B)", 80, "e")],
            height=16)

    def refresh_caves(self) -> None:
        if not self.elf:
            messagebox.showinfo("提示", "请先加载目标 ELF 文件。")
            return
        self._run_bg("扫描 cave", lambda: self.elf.caves(min_size=self.cave_min_var.get()),
                     self._fill_caves)

    def _fill_caves(self, caves: list) -> None:
        self.caves_tree.delete(*self.caves_tree.get_children())
        for i, c in enumerate(caves):
            self.caves_tree.insert("", "end", iid=str(i), values=(
                c.section, _fmt_hex(c.vaddr), hex(c.file_offset), c.size))
        self.info_vars["caves"].set(f"cave(≥{self.cave_min_var.get()}B): {len(caves)}")

    # ---- 修复 read --------------------------------------------------------
    def _build_tab_fix_read(self) -> None:
        tab = ttk.Frame(self.nb, padding=10)
        self.nb.add(tab, text="  修复 read（栈溢出）  ")

        card = ttk.Frame(tab, style="Card.TFrame", padding=14)
        card.pack(fill="both", expand=True)
        ttk.Label(card, text="把 call read/recv/fgets 前设置长度参数的立即数等长替换，"
                             "不改指令长度与控制流。勾选多个调用点可一次批量修复。",
                  style="DimCard.TLabel").pack(anchor="w", pady=(0, 8))

        row = ttk.Frame(card)
        row.pack(fill="x", pady=3)
        ttk.Label(row, text="目标函数", width=12, anchor="e").pack(side="left", padx=(0, 8))
        self.read_func_var = tk.StringVar(value="read")
        ttk.Combobox(row, textvariable=self.read_func_var, values=list(_READ_FUNCS),
                     width=14).pack(side="left", padx=(0, 8))
        self.scan_read_btn = ttk.Button(row, text="扫描调用点",
                                        command=lambda: self.scan_calls("read"))
        self.scan_read_btn.pack(side="left")
        self.scan_read_hint = ttk.Label(card, text="尚未扫描（也可在下方清单手动输入地址添加）",
                                        style="DimCard.TLabel")
        self.scan_read_hint.pack(anchor="w", padx=(96, 0), pady=(0, 2))

        self.read_sites = _SiteList(
            card, self._insn_at, on_select=self._preview_read_site,
            on_change=lambda: self._update_action_btn(self.read_run_btn, self.read_sites))

        row2 = ttk.Frame(card)
        row2.pack(fill="x", pady=(8, 3))
        ttk.Label(row2, text="新长度", width=12, anchor="e").pack(side="left", padx=(0, 8))
        self.read_len_var = tk.StringVar(value="0x100")
        ttk.Entry(row2, textvariable=self.read_len_var, width=14).pack(side="left")
        ttk.Label(row2, text="立即数装不下会拒绝改写（等长原则）",
                  style="DimCard.TLabel").pack(side="left", padx=10)

        self.read_out_var = tk.StringVar()
        self._path_row(card, "输出文件", self.read_out_var, save=True)

        ttk.Label(card, text="指令预览（点击列表行查看）", style="DimCard.TLabel").pack(
            anchor="w", pady=(10, 2))
        self.read_preview = tk.Text(card, height=8, font=_MONO_FONT_SMALL, state="disabled",
                                    background="#f6f8fa", relief="solid", borderwidth=1,
                                    padx=8, pady=4)
        self.read_preview.pack(fill="x", pady=(0, 4))
        self.read_preview.tag_configure("target", background="#fff3c4")

        self.read_run_btn = ttk.Button(card, text="执行修复", style="Accent.TButton",
                                       state="disabled", command=self.run_fix_read)
        self.read_run_btn.pack(anchor="w", padx=(96, 0), pady=(6, 0))

    def _insn_at(self, vaddr: int) -> str:
        """vaddr 处第一条指令的文本（供调用点列表展示）。"""
        if not self.elf:
            return ""
        try:
            rows = _disasm_around(self.elf, vaddr, back=0, fwd=16)
            return rows[0][1] if rows else ""
        except Exception:
            return ""

    @staticmethod
    def _update_action_btn(btn: ttk.Button, sites: _SiteList) -> None:
        n = len(sites.checked_addrs())
        btn.configure(text=f"执行修复（{n} 处）", state="normal" if n else "disabled")

    def scan_calls(self, which: str) -> None:
        """后台扫描 call <func>@plt 调用点，结果填入对应调用点清单（默认全选）。"""
        if not self.elf:
            messagebox.showinfo("提示", "请先加载目标 ELF 文件。")
            return
        func = (self.read_func_var if which == "read" else None)
        name = func.get().strip() if func else "free"
        if not name:
            messagebox.showerror("错误", "函数名不能为空。")
            return

        hint_lbl = self.scan_read_hint if which == "read" else self.scan_free_hint
        site_list = self.read_sites if which == "read" else self.free_sites
        hint_lbl.config(text=f"正在扫描 call {name}@plt …")

        def done(hits: list[int]):
            site_list.set_sites(hits)
            if hits:
                hint_lbl.config(text=f"找到 {len(hits)} 处 call {name}@plt，已默认全选")
                self.log("info", f"扫描到 {len(hits)} 处 call {name}@plt: "
                                 + ", ".join(_fmt_hex(v, 6) for v in hits))
            else:
                hint_lbl.config(text=f"未找到 call {name}@plt（可「手动添加」输入地址）")
                self.log("warn", f"未找到 call {name}@plt，请手动添加 vaddr")

        self._run_bg(f"扫描 call {name}@plt", lambda: self.elf.find_calls_to(name), done)

    def _render_preview(self, text_widget: tk.Text, vaddr) -> None:
        text_widget.configure(state="normal")
        text_widget.delete("1.0", "end")
        if isinstance(vaddr, str):
            vaddr = parse_addr(vaddr)
        if vaddr is None or not self.elf:
            text_widget.insert("end", "（点击左侧调用点列表可在此预览周围指令）")
        else:
            try:
                rows = _disasm_around(self.elf, vaddr)
                for _, (a, txt, is_target) in enumerate(rows):
                    line = f"{a:#010x}   {txt}\n"
                    if is_target:
                        text_widget.insert("end", line, "target")
                    else:
                        text_widget.insert("end", line)
            except Exception as exc:
                text_widget.insert("end", f"无法反汇编 0x{vaddr:x}: {exc}")
        text_widget.configure(state="disabled")

    def _preview_read_site(self, vaddr: int) -> None:
        self._render_preview(self.read_preview, vaddr)

    def _require_elf(self) -> bool:
        if not self.elf:
            messagebox.showwarning("未加载文件", "请先在顶部加载目标 ELF 文件。")
            return False
        return True

    def run_fix_read(self) -> None:
        if not self._require_elf() or self._require_idle():
            return
        addrs = self.read_sites.checked_addrs()
        new_len = parse_addr(self.read_len_var.get())
        output = self.read_out_var.get().strip()
        if not addrs:
            messagebox.showerror("参数错误", "请至少勾选一个调用点。")
            return
        if new_len is None or new_len < 0:
            messagebox.showerror("参数错误", "无效的新长度。")
            return
        if not output:
            messagebox.showerror("参数错误", "请填写输出文件路径。")
            return
        orig = self.elf_path

        def make(elf: ELFBinary):
            patcher = Patcher(elf)
            plans = [fix_read_length(patcher, addr, new_len) for addr in addrs]
            return plans, lambda: patcher.save(output)

        self.log("info", f"[*] 批量 fix-read：{len(addrs)} 处调用点，新长度 {new_len:#x}")
        self._run_fix_task("fix-read", make, orig, output)

    # ---- 修复 free --------------------------------------------------------
    def _build_tab_fix_free(self) -> None:
        tab = ttk.Frame(self.nb, padding=10)
        self.nb.add(tab, text="  修复 free（UAF/Double-Free）  ")

        card = ttk.Frame(tab, style="Card.TFrame", padding=14)
        card.pack(fill="both", expand=True)
        ttk.Label(card, text="通过 trampoline 把 call free 改为 cave 内的真修复 stub："
                             "正常调用 free 后将指针置空，绝不 NOP。勾选多个调用点"
                             "（如 UAF free + double free）可一次批量修复。",
                  style="DimCard.TLabel").pack(anchor="w", pady=(0, 8))

        row = ttk.Frame(card)
        row.pack(fill="x", pady=3)
        ttk.Label(row, text="调用点", width=12, anchor="e").pack(side="left", padx=(0, 8))
        self.scan_free_btn = ttk.Button(row, text="扫描 call free@plt",
                                        command=lambda: self.scan_calls("free"))
        self.scan_free_btn.pack(side="left")
        self.scan_free_hint = ttk.Label(card, text="尚未扫描（也可在下方清单手动输入地址添加）",
                                        style="DimCard.TLabel")
        self.scan_free_hint.pack(anchor="w", padx=(96, 0), pady=(0, 2))

        self.free_sites = _SiteList(
            card, self._insn_at, on_select=self._preview_free_site,
            on_change=lambda: self._update_action_btn(self.free_run_btn, self.free_sites))

        self.free_ptr_var = tk.StringVar()
        self._form_row(card, "指针变量 vaddr",
                       lambda row: ttk.Entry(row, textvariable=self.free_ptr_var))
        ttk.Label(card, text="可选；对全部勾选点生效（置空该指针变量防 UAF，绝对寻址要求非 PIE）",
                  style="DimCard.TLabel").pack(fill="x", padx=(96, 0), pady=(0, 2))

        self.free_out_var = tk.StringVar()
        self._path_row(card, "输出文件", self.free_out_var, save=True)

        ttk.Label(card, text="指令预览（点击列表行查看）", style="DimCard.TLabel").pack(
            anchor="w", pady=(10, 2))
        self.free_preview = tk.Text(card, height=7, font=_MONO_FONT_SMALL, state="disabled",
                                    background="#f6f8fa", relief="solid", borderwidth=1,
                                    padx=8, pady=4)
        self.free_preview.pack(fill="x", pady=(0, 4))
        self.free_preview.tag_configure("target", background="#fff3c4")

        self.free_run_btn = ttk.Button(card, text="执行修复", style="Accent.TButton",
                                       state="disabled", command=self.run_fix_free)
        self.free_run_btn.pack(anchor="w", padx=(96, 0), pady=(6, 0))

    def _preview_free_site(self, vaddr: int) -> None:
        self._render_preview(self.free_preview, vaddr)

    def run_fix_free(self) -> None:
        if not self._require_elf() or self._require_idle():
            return
        addrs = self.free_sites.checked_addrs()
        ptr = parse_addr(self.free_ptr_var.get())
        if self.free_ptr_var.get().strip() and ptr is None:
            messagebox.showerror("参数错误", "无效的指针变量 vaddr。")
            return
        output = self.free_out_var.get().strip()
        if not addrs:
            messagebox.showerror("参数错误", "请至少勾选一个调用点。")
            return
        if not output:
            messagebox.showerror("参数错误", "请填写输出文件路径。")
            return
        orig = self.elf_path

        def make(elf: ELFBinary):
            patcher = Patcher(elf)
            plans = [true_fix_free(patcher, addr, ptr) for addr in addrs]
            return plans, lambda: patcher.save(output)

        self.log("info", f"[*] 批量 fix-free：{len(addrs)} 处调用点"
                         + (f"，置空指针 {_fmt_hex(ptr, 6)}" if ptr is not None else ""))
        self._run_fix_task("fix-free", make, orig, output)

    # ---- 符号改名 ----------------------------------------------------------
    def _build_tab_rename(self) -> None:
        tab = ttk.Frame(self.nb, padding=10)
        self.nb.add(tab, text="  符号改名  ")

        card = ttk.Frame(tab, style="Card.TFrame", padding=14)
        card.pack(fill="both", expand=True)
        ttk.Label(card, text="等长改写 .dynstr 符号名（如 free → atoi），改数据不改控制流，"
                             "不触碰 GOT。新名必须不长于旧名，不足补 NUL。",
                  style="DimCard.TLabel").pack(anchor="w", pady=(0, 10))

        self.rename_old_var = tk.StringVar(value="free")
        self.rename_new_var = tk.StringVar(value="atoi")
        self._form_row(card, "原符号名",
                       lambda row: ttk.Entry(row, textvariable=self.rename_old_var))
        self._form_row(card, "新符号名",
                       lambda row: ttk.Entry(row, textvariable=self.rename_new_var))

        self.rename_hint = ttk.Label(card, text="", style="DimCard.TLabel")
        self.rename_hint.pack(anchor="w", padx=(96, 0), pady=(2, 4))
        self.rename_old_var.trace_add("write", lambda *_: self._validate_rename())
        self.rename_new_var.trace_add("write", lambda *_: self._validate_rename())
        self._validate_rename()

        self.rename_out_var = tk.StringVar()
        self._path_row(card, "输出文件", self.rename_out_var, save=True)

        ttk.Button(card, text="执行改名", style="Accent.TButton",
                   command=self.run_rename).pack(anchor="w", padx=(96, 0), pady=(10, 0))

    def _validate_rename(self) -> None:
        old, new = self.rename_old_var.get(), self.rename_new_var.get()
        if not old or not new:
            self.rename_hint.config(text="请填写符号名", foreground=_WARN)
            return
        if len(new) > len(old):
            self.rename_hint.config(
                text=f"✗ 新名 {len(new)}B 长于旧名 {len(old)}B，无法等长替换", foreground=_FAIL)
        else:
            pad = len(old) - len(new)
            extra = f"，将补 {pad} 个 NUL" if pad else "（等长）"
            self.rename_hint.config(text=f"✓ 可以等长替换{extra}", foreground=_PASS)

    def run_rename(self) -> None:
        if not self._require_elf() or self._require_idle():
            return
        old, new = self.rename_old_var.get().strip(), self.rename_new_var.get().strip()
        output = self.rename_out_var.get().strip()
        if not old or not new:
            messagebox.showerror("参数错误", "原/新符号名不能为空。")
            return
        if not output:
            messagebox.showerror("参数错误", "请填写输出文件路径。")
            return
        orig = self.elf_path

        def make(elf: ELFBinary):
            plan = dynstr_rename(elf, old=old, new=new)
            return [plan], lambda: elf.save(output)

        self._run_fix_task("rename", make, orig, output)

    # ---- 整数比较 ----------------------------------------------------------
    def _build_tab_fix_cmp(self) -> None:
        tab = ttk.Frame(self.nb, padding=10)
        self.nb.add(tab, text="  整数比较  ")

        card = ttk.Frame(tab, style="Card.TFrame", padding=14)
        card.pack(fill="both", expand=True)
        ttk.Label(card, text="把 `cmp reg, imm` 的立即数等长替换（如把 choices 上限改小），"
                             "只改数据，不改条件跳转。", style="DimCard.TLabel").pack(
            anchor="w", pady=(0, 8))

        self.cmp_vaddr_var = tk.StringVar()
        self._form_row(card, "cmp 指令 vaddr",
                       lambda row: ttk.Entry(row, textvariable=self.cmp_vaddr_var))
        ttk.Label(card, text="支持 0x/十进制/纯十六进制", style="DimCard.TLabel").pack(
            fill="x", padx=(96, 0), pady=(0, 2))

        self.cmp_imm_var = tk.StringVar()
        self._form_row(card, "新立即数",
                       lambda row: ttk.Entry(row, textvariable=self.cmp_imm_var))

        ttk.Label(card, text="指令预览", style="DimCard.TLabel").pack(anchor="w", pady=(10, 2))
        self.cmp_preview = tk.Text(card, height=7, font=_MONO_FONT_SMALL, state="disabled",
                                   background="#f6f8fa", relief="solid", borderwidth=1,
                                   padx=8, pady=4)
        self.cmp_preview.pack(fill="x", pady=(0, 8))
        self.cmp_preview.tag_configure("target", background="#fff3c4")
        self.cmp_vaddr_var.trace_add(
            "write", lambda *_: self._render_preview(self.cmp_preview, self.cmp_vaddr_var.get()))

        self.cmp_out_var = tk.StringVar()
        self._path_row(card, "输出文件", self.cmp_out_var, save=True)

        ttk.Button(card, text="执行修复", style="Accent.TButton",
                   command=self.run_fix_cmp).pack(anchor="w", padx=(96, 0))

    def run_fix_cmp(self) -> None:
        if not self._require_elf() or self._require_idle():
            return
        addr = parse_addr(self.cmp_vaddr_var.get())
        imm = parse_addr(self.cmp_imm_var.get())
        output = self.cmp_out_var.get().strip()
        if addr is None:
            messagebox.showerror("参数错误", "无效的 cmp 指令 vaddr。")
            return
        if imm is None:
            messagebox.showerror("参数错误", "无效的新立即数。")
            return
        if not output:
            messagebox.showerror("参数错误", "请填写输出文件路径。")
            return
        orig = self.elf_path

        def make(elf: ELFBinary):
            patcher = Patcher(elf)
            plan = fix_int_compare(patcher, addr, imm)
            return [plan], lambda: patcher.save(output)

        self._run_fix_task("fix-cmp", make, orig, output)

    # ---- 合规检测 ----------------------------------------------------------
    def _build_tab_check(self) -> None:
        tab = ttk.Frame(self.nb, padding=10)
        self.nb.add(tab, text="  合规检测  ")

        card = ttk.Frame(tab, style="Card.TFrame", padding=14)
        card.pack(fill="both", expand=True)
        ttk.Label(card, text="模拟 AWDP 平台检测：文件大小 / 节表 / .got.plt / _start / "
                             "prctl 特征码 / NOP free 特征 / 修改字节数。",
                  style="DimCard.TLabel").pack(anchor="w", pady=(0, 8))

        self.check_orig_var = tk.StringVar()
        self._path_row(card, "原文件", self.check_orig_var)
        self.check_patched_var = tk.StringVar()
        self._path_row(card, "修复后文件", self.check_patched_var)

        row = ttk.Frame(card)
        row.pack(fill="x", pady=(8, 4))
        ttk.Button(row, text="运行合规检测", style="Accent.TButton",
                   command=self.run_check).pack(side="left")
        self.check_summary = tk.Label(card, text="", font=_UI_FONT_BOLD)
        self.check_summary.pack(anchor="w", pady=(4, 2))

        cols = [("name", "检测项", 190, "w"), ("result", "结果", 70, "center"),
                ("detail", "详情", 640, "w")]
        self.check_tree = self._make_tree(card, cols, height=8)
        self.check_tree.tag_configure("pass", foreground=_PASS)
        self.check_tree.tag_configure("fail", foreground=_FAIL, background=_FAIL_BG)
        self.check_tree.tag_configure("warn", foreground=_WARN)

    def run_check(self) -> None:
        if self._require_idle():
            return
        orig, patched = self.check_orig_var.get().strip(), self.check_patched_var.get().strip()
        for p, what in ((orig, "原文件"), (patched, "修复后文件")):
            if not p:
                messagebox.showerror("参数错误", f"请填写{what}路径。")
                return
            if not os.path.isfile(p):
                messagebox.showerror("参数错误", f"{what}不存在: {p}")
                return
        self.log("info", f"合规检测: {orig} vs {patched}")
        checker = ComplianceChecker(orig, patched)
        self._run_bg("合规检测", checker.run_all, self._show_check_results)

    def _show_check_results(self, results: list[CheckResult]) -> None:
        tree = self.check_tree
        tree.delete(*tree.get_children())
        n_pass = 0
        for i, r in enumerate(results):
            mark = "PASS" if r.passed else "FAIL"
            if r.passed:
                n_pass += 1
            is_warn = r.passed and "WARN" in r.detail
            tag = "warn" if is_warn else ("pass" if r.passed else "fail")
            tree.insert("", "end", iid=str(i), values=(r.name, mark, r.detail), tags=(tag,))
            self.log("ok" if r.passed else "err", f"  [{mark}] {r.name}: {r.detail}")
        all_pass = n_pass == len(results)
        self.check_summary.config(
            text=f"{n_pass}/{len(results)} 项通过" + ("（全部合规）" if all_pass else "（存在未通过项）"),
            foreground=_PASS if all_pass else _FAIL)
        self.log("ok" if all_pass else "err",
                 "[+] 合规检测全部通过" if all_pass else "[!] 存在未通过的合规检测项，请检查修复方式")

    # ---- 功能测试 ----------------------------------------------------------
    def _build_tab_test(self) -> None:
        tab = ttk.Frame(self.nb, padding=10)
        self.nb.add(tab, text="  功能测试  ")

        card = ttk.Frame(tab, style="Card.TFrame", padding=14)
        card.pack(fill="both", expand=True)
        ttk.Label(card, text="用交互脚本驱动被测程序，验证正常业务流程未被破坏"
                             "（功能 check）/ 官方 exp 已失效（exp 复验）。"
                             "仅 Linux 上实际运行，其他平台返回 skipped。",
                  style="DimCard.TLabel").pack(anchor="w", pady=(0, 8))

        self.test_bin_var = tk.StringVar()
        self._path_row(card, "被测程序", self.test_bin_var)

        row = ttk.Frame(card)
        row.pack(fill="x", pady=3)
        ttk.Label(row, text="超时(秒)", width=12, anchor="e").pack(side="left", padx=(0, 8))
        self.test_timeout_var = tk.IntVar(value=10)
        ttk.Spinbox(row, from_=3, to=120, textvariable=self.test_timeout_var,
                    width=6).pack(side="left")

        btns = ttk.Frame(card)
        btns.pack(fill="x", pady=(8, 4))
        ttk.Button(btns, text="▶ 运行功能测试", style="Accent.TButton",
                   command=lambda: self.run_test("functional")).pack(side="left")
        ttk.Button(btns, text="▶ 运行 EXP 复验", style="Danger.TButton",
                   command=lambda: self.run_test("exp")).pack(side="left", padx=8)
        ttk.Button(btns, text="从文件导入…", command=self._import_script).pack(side="left")
        ttk.Button(btns, text="保存脚本…", command=self._save_script).pack(side="left", padx=6)
        self.test_result = tk.Label(card, text="", font=_UI_FONT_BOLD, wraplength=760)
        self.test_result.pack(anchor="w", pady=(2, 6))

        from tkinter import scrolledtext
        self.script_box = scrolledtext.ScrolledText(
            card, height=9, font=_MONO_FONT_SMALL, background="#f6f8fa",
            relief="solid", borderwidth=1, padx=8, pady=6)
        self.script_box.pack(fill="both", expand=True)
        self.script_box.insert("1.0", _SCRIPT_TEMPLATE)

    def _import_script(self) -> None:
        path = filedialog.askopenfilename(
            title="导入交互脚本", filetypes=[("Python 脚本", "*.py"), ("所有文件", "*.*")])
        if not path:
            return
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("读取失败", str(exc))
            return
        self.script_box.delete("1.0", "end")
        self.script_box.insert("1.0", text)
        self.log("info", f"已导入交互脚本: {path}")

    def _save_script(self) -> None:
        path = filedialog.asksaveasfilename(
            title="保存交互脚本", defaultextension=".py",
            filetypes=[("Python 脚本", "*.py")])
        if not path:
            return
        Path(path).write_text(self.script_box.get("1.0", "end"), encoding="utf-8")
        self.log("ok", f"交互脚本已保存: {path}")

    def run_test(self, mode: str) -> None:
        if self._require_idle():
            return
        binary = self.test_bin_var.get().strip()
        if not binary:
            messagebox.showerror("参数错误", "请填写被测程序路径。")
            return
        if not os.path.isfile(binary):
            messagebox.showerror("参数错误", f"被测程序不存在: {binary}")
            return
        script = self.script_box.get("1.0", "end").strip()
        if not script:
            messagebox.showerror("参数错误", "交互脚本为空。")
            return
        timeout = self.test_timeout_var.get()
        label = "功能测试" if mode == "functional" else "EXP 复验"
        self.log("info", f"{label}: {binary}（超时 {timeout}s）")

        def task() -> CheckResult:
            if mode == "functional":
                return FunctionalTester(binary).run_script(script, timeout=timeout)
            return replay_exp(binary, script, timeout=timeout)

        def done(result: CheckResult) -> None:
            mark = "PASS" if result.passed else "FAIL"
            color = _PASS if result.passed else _FAIL
            if "skipped" in result.detail:
                mark, color = "SKIP", _WARN
            self.test_result.config(text=f"[{mark}] {result.name}: {result.detail}",
                                    foreground=color)
            self.log("ok" if result.passed else "err",
                     f"[{mark}] {result.name}: {result.detail}")

        self._run_bg(label, task, done)

    # ---- 通用补丁 ----------------------------------------------------------
    def _build_tab_patch(self) -> None:
        tab = ttk.Frame(self.nb, padding=10)
        self.nb.add(tab, text="  通用补丁  ")

        card = ttk.Frame(tab, style="Card.TFrame", padding=14)
        card.pack(fill="both", expand=True)
        ttk.Label(card, text="在任意地址插入任意机器码（trampoline，前身项目 elf-patcher 移植）："
                             "hook 点跳入 cave → 先执行插入代码 → 重放被覆盖的原指令 → 跳回。"
                             "被覆盖指令含 RIP 相对寻址时会被拒绝（照搬会错位）。",
                  style="DimCard.TLabel").pack(anchor="w", pady=(0, 8))

        row = ttk.Frame(card)
        row.pack(fill="x", pady=3)
        ttk.Label(row, text="补丁位置", width=12, anchor="e").pack(side="left", padx=(0, 8))
        self.patch_pos_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.patch_pos_var, width=20).pack(side="left")
        self.patch_offset_mode_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text="按文件偏移（默认 vaddr）",
                        variable=self.patch_offset_mode_var).pack(side="left", padx=10)
        ttk.Label(card, text="支持 0x / 十进制 / 纯十六进制", style="DimCard.TLabel").pack(
            fill="x", padx=(96, 0), pady=(0, 2))

        self.patch_code_var = tk.StringVar(value="90")
        self._form_row(card, "插入机器码",
                       lambda row: ttk.Entry(row, textvariable=self.patch_code_var))
        ttk.Label(card, text="十六进制字节：5058 / \\x50\\x58 / '50 58'", style="DimCard.TLabel"
                  ).pack(fill="x", padx=(96, 0), pady=(0, 2))

        ttk.Label(card, text="指令预览（输入地址后显示）", style="DimCard.TLabel").pack(
            anchor="w", pady=(10, 2))
        self.patch_preview = tk.Text(card, height=7, font=_MONO_FONT_SMALL, state="disabled",
                                     background="#f6f8fa", relief="solid", borderwidth=1,
                                     padx=8, pady=4)
        self.patch_preview.pack(fill="x", pady=(0, 4))
        self.patch_preview.tag_configure("target", background="#fff3c4")
        self.patch_pos_var.trace_add(
            "write", lambda *_: self._render_preview(self.patch_preview, self.patch_pos_var.get()))

        self.patch_out_var = tk.StringVar()
        self._path_row(card, "输出文件", self.patch_out_var, save=True)

        self.patch_run_btn = ttk.Button(card, text="执行补丁", style="Accent.TButton",
                                        command=self.run_patch)
        self.patch_run_btn.pack(anchor="w", padx=(96, 0), pady=(6, 0))

    @staticmethod
    def _parse_hex_code(raw: str) -> bytes | None:
        """解析插入机器码：'5058' / '\\x50\\x58' / '50 58' / '50,58'。"""
        text = raw.strip()
        if not text:
            return None
        normalized = (text.replace(" ", "").replace("\t", "").replace("\n", "")
                      .replace(",", "").replace("\\x", "").replace("\\X", "")
                      .replace("0x", "").replace("0X", ""))
        if not normalized or len(normalized) % 2 != 0:
            return None
        try:
            return bytes.fromhex(normalized)
        except ValueError:
            return None

    def run_patch(self) -> None:
        if not self._require_elf() or self._require_idle():
            return
        insert = self._parse_hex_code(self.patch_code_var.get())
        if not insert:
            messagebox.showerror("参数错误", "无效的插入机器码（需为偶数个十六进制字符）。")
            return
        pos = parse_addr(self.patch_pos_var.get())
        if pos is None:
            messagebox.showerror("参数错误", "无效的补丁位置。")
            return
        output = self.patch_out_var.get().strip()
        if not output:
            messagebox.showerror("参数错误", "请填写输出文件路径。")
            return
        offset_mode = self.patch_offset_mode_var.get()
        orig = self.elf_path

        def make(elf: ELFBinary):
            if offset_mode:
                vaddr = elf.offset_to_vaddr(pos)
            else:
                elf.vaddr_to_offset(pos)  # 校验可映射
                vaddr = pos
            patcher = Patcher(elf)
            cave_vaddr = patcher.build_trampoline(vaddr, insert, stolen=5, resteal=True)
            desc = (f"generic trampoline: hook 0x{vaddr:x} -> cave 0x{cave_vaddr:x}, "
                    f"insert {len(insert)} bytes then replay stolen instructions")
            plan = PatchPlan(description=desc, changes=patcher.log[:], applied=True)
            return [plan], lambda: patcher.save(output)

        self.log("info", f"[*] 通用补丁: {'文件偏移' if offset_mode else 'vaddr'} "
                         f"{_fmt_hex(pos, 6)}，插入 {insert.hex()}")
        self._run_fix_task("patch", make, orig, output)

    # ---- 沙箱（研究用途）----------------------------------------------------
    def _build_tab_sandbox(self) -> None:
        tab = ttk.Frame(self.nb, padding=10)
        self.nb.add(tab, text="  沙箱(研究)  ")

        card = ttk.Frame(tab, style="Card.TFrame", padding=14)
        card.pack(fill="both", expand=True)

        warn_box = tk.Text(card, height=6, font=_UI_FONT_SMALL, wrap="word",
                           background=_WARN_BG, foreground="#7a4a00",
                           relief="solid", borderwidth=1, padx=10, pady=6)
        warn_box.pack(fill="x", pady=(0, 8))
        warn_box.insert("1.0", rules_warning())
        warn_box.configure(state="disabled")

        row = ttk.Frame(card)
        row.pack(fill="x", pady=3)
        ttk.Label(row, text="模式", width=12, anchor="e").pack(side="left", padx=(0, 8))
        self.sb_mode_var = tk.StringVar(value="白名单（其余 EPERM）")
        ttk.Combobox(row, textvariable=self.sb_mode_var, width=24, state="readonly",
                     values=["白名单（其余 EPERM）", "黑名单（命中即杀）",
                             "strict（仅 read/write/exit）"]).pack(side="left")
        ttk.Label(card, text="安装方式自动选择：cave 优先 + .init_array[0]（非 PIE）/"
                             "e_entry（PIE）劫持；无 cave 时段尾注入并扩容段头",
                  style="DimCard.TLabel").pack(fill="x", padx=(96, 0), pady=(0, 4))

        self.sb_allow_var = tk.StringVar(value="read,write,exit,exit_group")
        self._form_row(card, "白名单 syscall",
                       lambda row: ttk.Entry(row, textvariable=self.sb_allow_var))
        self.sb_blacklist_var = tk.StringVar(value="execve,execveat,openat,openat2")
        self._form_row(card, "黑名单 syscall",
                       lambda row: ttk.Entry(row, textvariable=self.sb_blacklist_var))
        ttk.Label(card, text="名称或编号，逗号分隔；黑名单命中即 KILL_PROCESS，其余放行（破坏面最小）",
                  style="DimCard.TLabel").pack(fill="x", padx=(96, 0), pady=(0, 2))

        row2 = ttk.Frame(card)
        row2.pack(fill="x", pady=3)
        ttk.Label(row2, text="架构", width=12, anchor="e").pack(side="left", padx=(0, 8))
        self.sb_arch_var = tk.StringVar(value="自动(跟随二进制)")
        ttk.Combobox(row2, textvariable=self.sb_arch_var, width=22, state="readonly",
                     values=["自动(跟随二进制)", "amd64"]).pack(side="left")

        self.sb_out_var = tk.StringVar()
        self._path_row(card, "输出文件", self.sb_out_var, save=True)

        self.sb_risk_var = tk.BooleanVar(value=False)
        risk_row = ttk.Frame(card)
        risk_row.pack(fill="x", pady=(10, 4))
        ttk.Checkbutton(
            risk_row, text="我已阅读并了解上述规则风险，仅用于研究/出题自测",
            variable=self.sb_risk_var).pack(side="left")
        btns = ttk.Frame(card)
        btns.pack(fill="x", pady=6)
        self.sb_run_btn = ttk.Button(card, text="安装 seccomp stub", style="Danger.TButton",
                                     command=self.run_sandbox, state="disabled")
        self.sb_run_btn.pack(side="left", padx=(96, 0))
        self.sb_dry_btn = ttk.Button(card, text="仅看安装计划 (dry-run)",
                                     command=lambda: self.run_sandbox(dry_run=True))
        self.sb_dry_btn.pack(side="left", padx=8)
        self.sb_risk_var.trace_add(
            "write", lambda *_: self.sb_run_btn.configure(
                state="normal" if self.sb_risk_var.get() else "disabled"))

    def run_sandbox(self, dry_run: bool = False) -> None:
        if not self._require_elf() or self._require_idle():
            return
        output = self.sb_out_var.get().strip()
        if not dry_run and not output:
            messagebox.showerror("参数错误", "请填写输出文件路径。")
            return
        mode = {"白名单（其余 EPERM）": "whitelist",
                "黑名单（命中即杀）": "blacklist",
                "strict（仅 read/write/exit）": "strict"}[self.sb_mode_var.get()]
        allow = tuple(s.strip() for s in self.sb_allow_var.get().split(",") if s.strip())
        blacklist: tuple[int, ...] = ()
        if mode == "blacklist":
            try:
                blacklist = tuple(parse_syscall_list(self.sb_blacklist_var.get()))
            except ValueError as exc:
                messagebox.showerror("参数错误", str(exc))
                return
        arch = None if self.sb_arch_var.get().startswith("自动") else "amd64"
        orig = self.elf_path

        def task() -> str:
            elf = ELFBinary(orig)  # 在副本上操作，不污染已加载对象
            use_arch = arch or elf.arch
            probe = build_seccomp_stub(use_arch, allow=allow, blacklist=blacklist,
                                       mode=mode, obfuscate=False, vaddr=0,
                                       entry_jmp_to=0)
            plan = plan_install(elf, len(probe))

            def make_stub(vaddr: int, hook_orig: int) -> bytes:
                return build_seccomp_stub(use_arch, allow=allow, blacklist=blacklist,
                                          mode=mode, vaddr=vaddr, entry_jmp_to=hook_orig)

            if dry_run:
                return f"dry-run\n{plan.describe()}"
            patcher = Patcher(elf)
            stub_vaddr = apply_install(patcher, plan, make_stub)
            patcher.save(output)
            return f"installed @ 0x{stub_vaddr:x}\n{plan.describe()}"

        def done(desc: str) -> None:
            for line in desc.splitlines():
                self._log_write("info", f"    {line}")
            if dry_run:
                self._log_write("dim", "[*] dry-run：仅打印安装计划，未写出文件")
                return
            self._log_write("ok", f"[+] 已保存: {output}")
            self.check_patched_var.set(output)
            checker = ComplianceChecker(orig, output)
            self._run_bg("合规检测", checker.run_all, self._show_check_results)

        if not dry_run:
            self.log("warn", "sandbox 为研究用途功能；正式比赛中使用通防属于违规行为")
        self._run_bg("sandbox", task, done)

    # ------------------------------------------------------------------ 日志
    def _build_log_panel(self) -> None:
        container = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        container.pack(fill="both", pady=(0, 8))

        header = ttk.Frame(container)
        header.pack(fill="x")
        ttk.Label(header, text="日志", font=_UI_FONT_BOLD).pack(side="left", pady=(0, 4))
        ttk.Button(header, text="清空", width=6,
                   command=lambda: self.log_text.delete("1.0", "end")).pack(side="right")
        ttk.Button(header, text="导出…", width=7,
                   command=self._export_log).pack(side="right", padx=6)

        from tkinter import scrolledtext
        self.log_text = scrolledtext.ScrolledText(
            container, height=10, font=_MONO_FONT_SMALL, state="disabled",
            background=_LOG_BG, foreground=_LOG_FG, relief="flat",
            insertbackground=_LOG_FG, padx=10, pady=6)
        self.log_text.pack(fill="both", expand=False)
        for tag, color in _LOG_TAGS.items():
            self.log_text.tag_configure(tag, foreground=color)

    def log(self, kind: str, message: str) -> None:
        self._post(lambda: self._log_write(kind, message))

    def _log_write(self, kind: str, message: str) -> None:
        text = self.log_text
        text.configure(state="normal")
        text.insert("end", message + "\n", kind)
        text.configure(state="disabled")
        text.see("end")

    def _export_log(self) -> None:
        path = filedialog.asksaveasfilename(title="导出日志", defaultextension=".log",
                                            filetypes=[("日志文件", "*.log"), ("文本", "*.txt")])
        if not path:
            return
        Path(path).write_text(self.log_text.get("1.0", "end"), encoding="utf-8")
        self._log_write("ok", f"[+] 日志已导出: {path}")

    # ------------------------------------------------------------------ 线程
    def _post(self, fn: Callable[[], None]) -> None:
        """把 callable 调度回 UI 线程执行（线程安全）。"""
        self._queue.put(fn)

    def _poll_queue(self) -> None:
        try:
            while True:
                self._queue.get_nowait()()
        except queue.Empty:
            pass
        self.root.after(60, self._poll_queue)

    def _require_idle(self) -> bool:
        """有任务在跑时返回 True（调用方应直接返回）。"""
        if self._busy_count > 0:
            messagebox.showinfo("请稍候", "有任务正在执行，请等待完成。")
            return True
        return False

    def _run_bg(self, label: str, task: Callable[[], Any],
                on_done: Callable[[Any], None] | None = None) -> None:
        """后台线程执行 task，完成后在 UI 线程调用 on_done(结果)。

        task 内如需打日志，可通过 self.log（线程安全）。
        """

        def set_busy(delta: int) -> None:
            self._busy_count += delta
            busy = self._busy_count > 0
            self.info_vars["status"].set("状态: " + ("执行中…" if busy else "就绪"))
            self.status_label.config(foreground=_WARN if busy else _PASS)
            self.root.config(cursor="watch" if busy else "")

        def worker() -> None:
            self._post(lambda: set_busy(1))
            try:
                result = task()
            except Exception as exc:  # noqa: BLE001 - GUI 兜底，完整记录
                detail = f"{type(exc).__name__}: {exc}"
                self.log("err", f"[!] {label} 执行失败: {detail}")
                tb = traceback.format_exc(limit=3)
                for line in tb.strip().splitlines():
                    self.log("dim", "    " + line)
                self._post(lambda: set_busy(-1))
                return
            if on_done is not None:
                self._post(lambda: on_done(result))
            self._post(lambda: set_busy(-1))

        threading.Thread(target=worker, daemon=True, name=f"bg-{label}").start()

    # ------------------------------------------------------------------ 加载
    def _set_binary_path(self, path: str) -> None:
        self.path_var.set(path)

    def browse_binary(self) -> None:
        path = filedialog.askopenfilename(
            title="选择目标 ELF 文件",
            filetypes=[("所有文件", "*.*"), ("ELF 相关", "*.elf;*.bin;*.so;*.so.*")])
        if path:
            self._set_binary_path(path)
            self.load_binary()

    def load_binary(self) -> None:
        path = self.path_var.get().strip()
        if not path:
            messagebox.showwarning("提示", "请先填写目标文件路径。")
            return
        if not os.path.isfile(path):
            messagebox.showerror("错误", f"文件不存在: {path}")
            return
        self._run_bg(f"加载 {os.path.basename(path)}", lambda: ELFBinary(path),
                     lambda elf: self._populate(elf, path))

    def _populate(self, elf: ELFBinary, path: str) -> None:
        self.elf = elf
        self.elf_path = path
        sections = elf.sections()
        caves = elf.caves()

        # 信息条
        self.info_vars["arch"].set(f"架构: {elf.arch}")
        self.info_vars["pie"].set(f"PIE: {'是' if elf.is_pie else '否'}")
        self.info_vars["entry"].set(f"入口: {_fmt_hex(elf.entry_vaddr(), 6)}")
        self.info_vars["size"].set(f"大小: {len(elf.data):,} 字节")
        self.info_vars["secs"].set(f"节: {len(sections)}")
        self.info_vars["caves"].set(f"cave(≥32B): {len(caves)}")

        # 概览表
        self.sections_tree.delete(*self.sections_tree.get_children())
        for i, s in enumerate(sections):
            self.sections_tree.insert("", "end", iid=str(i), values=(
                s.name or "<null>", _fmt_hex(s.vaddr), hex(s.size), hex(s.offset)))
        self._fill_caves(caves)

        # 各标签页默认值
        stem = str(Path(path).with_suffix(""))
        self.read_out_var.set(stem + ".fixread")
        self.free_out_var.set(stem + ".fixfree")
        self.rename_out_var.set(stem + ".rename")
        self.cmp_out_var.set(stem + ".fixcmp")
        self.patch_out_var.set(stem + ".patched")
        self.sb_out_var.set(stem + ".sandbox")
        self.check_orig_var.set(path)
        self.test_bin_var.set(path)

        # 重置扫描状态
        self.read_sites.clear()
        self.free_sites.clear()
        self.scan_read_hint.config(text="尚未扫描（也可在下方清单手动输入地址添加）")
        self.scan_free_hint.config(text="尚未扫描（也可在下方清单手动输入地址添加）")
        self._update_action_btn(self.read_run_btn, self.read_sites)
        self._update_action_btn(self.free_run_btn, self.free_sites)
        for pane in (self.read_preview, self.free_preview):
            self._render_preview(pane, None)

        self.log("ok", f"[+] 已加载 {path}（{elf.arch}，入口 {_fmt_hex(elf.entry_vaddr(), 6)}，"
                       f"{len(elf.data):,} 字节，{len(sections)} 节，{len(caves)} 个 cave）")
        self.log("info", "提示: 各修复标签页点「扫描调用点」可自动定位 call 指令地址")

    # ------------------------------------------------------------------ 修复公共流程
    def _run_fix_task(self, label: str, make: Callable, orig: str, output: str) -> None:
        """后台：从原文件重建 ELFBinary → 逐项执行策略 → 全部失败不保存 → 自动合规检测。

        make(elf) 返回 (plans: list[PatchPlan], save: Callable)；只要有一项应用
        成功就保存（同一内存副本上叠加全部补丁，单次写出）。
        """

        def task() -> dict:
            elf = ELFBinary(orig)
            plans, save = make(elf)
            if any(p.applied for p in plans):
                save()
            return {"plans": plans}

        def done(result: dict) -> None:
            plans: list = result["plans"]
            n_ok = 0
            for i, plan in enumerate(plans, 1):
                prefix = f"{label} #{i}/{len(plans)}" if len(plans) > 1 else label
                kind = "info" if plan.applied else "err"
                self._log_write(kind, f"[*] {prefix}: {plan.description}")
                for change in plan.changes:
                    self._log_write("dim", f"    - {change}")
                n_ok += plan.applied
            self.last_fix_stats = {"applied": n_ok, "total": len(plans), "label": label}

            if n_ok == 0:
                self._log_write("err", f"[!] {label} 全部未应用，未写出文件")
                messagebox.showwarning(
                    "修复未应用",
                    f"{len(plans)} 处均未应用，原因见日志。\n首个失败: {plans[0].description}")
                return
            if n_ok < len(plans):
                self._log_write("warn", f"[!] {label}: {n_ok}/{len(plans)} 处已应用，"
                                        f"其余失败（详见日志），失败项未写入产物")
            else:
                self._log_write("ok", f"[+] {label}: {n_ok}/{len(plans)} 处全部应用")
            self._log_write("ok", f"[+] 已保存: {output}")
            self.check_patched_var.set(output)
            checker = ComplianceChecker(orig, output)
            self._log_write("info", "[*] 自动合规检测（原文件 vs 修复后文件）:")

            def after_check(results: list) -> None:
                self._show_check_results(results)
                # 修复产物自动设为目标文件，便于在其它标签页叠加修复
                if self.autochain_var.get() and os.path.isfile(output):
                    self.log("dim", f"提示: 已自动加载产物 {output}，可继续叠加其他修复")
                    self._set_binary_path(output)
                    self.load_binary()

            self._run_bg("合规检测", checker.run_all, after_check)

        self.log("info", f"[*] 执行 {label} …")
        self._run_bg(label, task, done)

    # ------------------------------------------------------------------ 帮助
    def _run_doctor(self) -> None:
        """环境检查（与 CLI doctor 同一逻辑），结果写日志。"""
        try:
            from .cli import collect_doctor_rows
        except ImportError:
            from mistyfix.cli import collect_doctor_rows

        self._log_write("info", "[*] 环境检查 (doctor):")
        n_miss = 0
        for name, ok, hint in collect_doctor_rows():
            mark = "OK " if ok else "MISS"
            self._log_write("ok" if ok else "warn",
                            f"    [{mark}] {name}" + (f" -> {hint}" if hint and not ok else ""))
            if not ok and hint and "可选" not in hint and "非 Linux" not in hint:
                n_miss += 1
        self._log_write("ok" if n_miss == 0 else "err",
                        "[+] 环境检查通过" if n_miss == 0
                        else f"[!] {n_miss} 项必需依赖缺失（详见上方）")

    def _show_help(self) -> None:
        win = tk.Toplevel(self.root)
        win.title("使用说明")
        win.geometry("720x520")
        from tkinter import scrolledtext
        text = scrolledtext.ScrolledText(win, font=_UI_FONT, wrap="word", padx=12, pady=10)
        text.pack(fill="both", expand=True)
        text.insert("1.0", """\
MistyFix 快速上手
==================

1. 顶部选择目标 ELF 文件并点「加载」，概览页会显示节表与 code cave。

2. 按漏洞类型选择修复标签页：
   • 栈溢出（read/recv 长度过大）→ 「修复 read」：扫描调用点后默认全选，
     可勾选/手动添加，填新长度后一次批量修复；
   • UAF / Double-Free → 「修复 free」：真修复（free 后置空指针），
     多个 free 调用点（如 UAF free + double free）可一次批量修复；
   • 想替换危险动态符号 → 「符号改名」：.dynstr 等长改写，如 free → atoi；
   • 越界索引/选项过多 → 「整数比较」：等长替换 cmp 立即数。

3. 每次修复保存后自动运行合规检测（模拟 AWDP 平台的 7 项静态检测），
   结果同时显示在日志与「合规检测」页；全部 PASS 才可放心提交。
   默认开启「修复后自动加载产物」：产物自动成为目标文件，
   可直接切换到其他标签页叠加修复（如先修 read 再修 free）。

4. 「功能测试」页可用内置编辑器编写交互脚本（recvuntil/sendline …），
   在 Linux 上验证正常业务不变、官方 exp 失效。

修复原则：等长替换 · code cave 注入 · 真修复拒绝 NOP · 不碰 GOT/_start。
""")
        text.configure(state="disabled")

    def _show_about(self) -> None:
        messagebox.showinfo(
            "关于 MistyFix",
            f"MistyFix v{__version__}\n\nAWDP（CTF 攻防赛）PWN 方向合规漏洞修复工具。\n\n"
            "等长替换 · code cave 注入 · 真修复替代 NOP · 改数据不改控制流 · 不碰 GOT/_start\n\n"
            "GUI: tkinter（Python 自带，零额外依赖）",
        )


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------
def run_gui(initial_binary: str | None = None) -> int:
    """创建并运行主窗口，返回退出码。"""
    root = tk.Tk()
    MistyFixGUI(root, initial_binary)
    root.mainloop()
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    binary = argv[0] if argv else None
    try:
        return run_gui(binary)
    except tk.TclError as exc:
        print(f"[!] 无法启动图形界面: {exc}", file=sys.stderr)
        print("    tkinter 随官方 Python 自带；若缺失请安装 python.org 版本或 "
              "系统 tkinter 包。", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
