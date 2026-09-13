"""GUI 自动化冒烟测试：不依赖人工点击，直接驱动 MistyFixGUI 各流程。

运行: python tests/gui_smoke.py
原理: 实例化 MistyFixGUI 后用 root.update() 泵事件，
     _run_bg 的后台线程经队列回到 UI 线程，等待 _busy_count 归零即任务完成。
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import time
from pathlib import Path

import tkinter as tk

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mistyfix.gui import MistyFixGUI, parse_addr  # noqa: E402

SAMPLE = ROOT / "tmp" / "vuln"
SAMPLE_PIE = ROOT / "tmp" / "vuln_pie"

# 打掉模态对话框：自动测试中弹窗会永久阻塞
import mistyfix.gui as gui_mod  # noqa: E402
POPUPS: list[tuple[str, tuple]] = []
for _name in ("showinfo", "showwarning", "showerror"):
    setattr(gui_mod.messagebox, _name,
            staticmethod(lambda *a, _n=_name, **k: POPUPS.append((_n, a))))

PASS = 0
FAIL = 0


def check(name: str, cond: bool, extra: str = "") -> None:
    global PASS, FAIL
    mark = "PASS" if cond else "FAIL"
    print(f"  [{mark}] {name}" + (f"  ({extra})" if extra else ""))
    PASS += cond
    FAIL += not cond


def wait_idle(app: MistyFixGUI, timeout: float = 20.0) -> None:
    """泵事件直到后台任务全部完成。"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.root.update()
        if app._busy_count == 0 and app._queue.empty():
            app.root.update()
            return
        time.sleep(0.02)
    raise TimeoutError("等待后台任务超时")


def _read_qword(path: Path, off: int) -> int:
    import struct
    with open(path, "rb") as f:
        f.seek(off)
        return struct.unpack("<Q", f.read(8))[0]


def main() -> int:
    if not SAMPLE.is_file():
        print(f"样例不存在: {SAMPLE}")
        return 1

    tmpdir = Path(tempfile.mkdtemp(prefix="mistyfix_gui_"))
    work = tmpdir / "vuln"
    shutil.copy(SAMPLE, work)
    pie = tmpdir / "vuln_pie"
    if SAMPLE_PIE.is_file():
        shutil.copy(SAMPLE_PIE, pie)

    root = tk.Tk()
    root.withdraw()  # 冒烟测试不显示窗口
    app = MistyFixGUI(root, initial_binary=str(work))
    wait_idle(app)

    print("== 加载 ==")
    check("elf 已加载", app.elf is not None)
    check("架构 amd64", app.elf.arch == "amd64")
    check("路径一致", app.elf_path == str(work))
    check("节表已填充", len(app.sections_tree.get_children()) > 0)
    check("cave 已填充", len(app.caves_tree.get_children()) > 0)
    check("入口地址条", app.info_vars["entry"].get().startswith("入口: 0x"))
    check("输出路径默认值", app.read_out_var.get().endswith(".fixread"))
    check("清单初始为空且按钮禁用",
          len(app.read_sites.checked_addrs()) == 0
          and app.read_run_btn.instate(["disabled"]))

    print("== 地址解析 ==")
    check("0x 前缀", parse_addr("0x4011a3") == 0x4011A3)
    check("纯十六进制", parse_addr("4011a3") == 0x4011A3)
    check("十进制", parse_addr("4198819") == 4198819)
    check("非法输入", parse_addr("xyz") is None)

    print("== 扫描 + 调用点清单 ==")
    app.scan_calls("read")
    wait_idle(app)
    read_addrs = app.read_sites.checked_addrs()
    check("扫描到 call read@plt 且默认全选", len(read_addrs) == 1,
          ", ".join(hex(a) for a in read_addrs))
    check("按钮显示数量并启用",
          "1 处" in app.read_run_btn.cget("text") and not app.read_run_btn.instate(["disabled"]))
    app._preview_read_site(read_addrs[0])
    preview = app.read_preview.get("1.0", "end")
    check("指令预览含 call", "call" in preview)
    tree_rows = app.read_sites.tree.get_children()
    check("清单行含指令文本", any("call" in (app.read_sites.tree.set(i, "insn") or "")
                                for i in tree_rows))

    app.scan_calls("free")
    wait_idle(app)
    free_addrs = app.free_sites.checked_addrs()
    check("扫描到 call free@plt 默认全选", len(free_addrs) == 2,
          ", ".join(hex(a) for a in free_addrs))
    app.free_sites.set_all(False)
    root.update()
    check("全不选后按钮禁用", app.free_run_btn.instate(["disabled"]))
    app.free_sites.set_all(True)
    root.update()
    check("全选后恢复 2 处", len(app.free_sites.checked_addrs()) == 2)

    print("== 手动添加（内联地址输入框）==")
    app.free_sites.addr_var.set("0x401090")  # _start，非 call
    app.free_sites.add_from_entry()
    check("手动地址入列", 0x401090 in app.free_sites.checked_addrs())
    check("输入框已清空", app.free_sites.addr_var.get() == "")
    check("按钮更新为 3 处", "3 处" in app.free_run_btn.cget("text"))

    print("== fix-read 批量（1 处，含自动加载产物）==")
    out_read = tmpdir / "vuln.fixread"
    app.read_len_var.set("0x20")
    app.read_out_var.set(str(out_read))
    app.run_fix_read()
    wait_idle(app)
    check("统计 1/1", app.last_fix_stats["applied"] == 1
          and app.last_fix_stats["total"] == 1)
    check("产物已写出", out_read.is_file())
    check("文件等长", out_read.stat().st_size == work.stat().st_size)
    check("合规树已填充", len(app.check_tree.get_children()) == 7)
    check("check 页已回填", app.check_patched_var.get() == str(out_read))
    check("自动加载产物为目标", app.elf_path == str(out_read),
          app.elf_path)
    check("重载后清单已重置", len(app.free_sites.checked_addrs()) == 0)

    print("== fix-free 批量（2 处真修复 + 1 处无效地址，叠加在产物上）==")
    out_free = tmpdir / "vuln.fixfree"
    app.scan_calls("free")
    wait_idle(app)
    app.free_sites.addr_var.set("0x401090")
    app.free_sites.add_from_entry()  # 3 处勾选：2 真 call + 1 无效
    app.free_out_var.set(str(out_free))
    app.run_fix_free()
    wait_idle(app)
    check("统计 2/3（部分失败）", app.last_fix_stats["applied"] == 2
          and app.last_fix_stats["total"] == 3)
    check("产物已写出", out_free.is_file())
    check("文件等长", out_free.stat().st_size == out_read.stat().st_size)
    check("双 trampoline 写入互不覆盖",
          out_free.read_bytes().count(b"\xe9") >= 3)

    print("== rename ==")
    app.rename_old_var.set("free")
    app.rename_new_var.set("atoi")
    wait_idle(app)  # trace 回调即时，等一拍
    hint = app.rename_hint.cget("text")
    check("等长校验通过", hint.startswith("✓"), hint)
    out_ren = tmpdir / "vuln.rename"
    app.rename_out_var.set(str(out_ren))
    app.run_rename()
    wait_idle(app)
    check("产物已写出", out_ren.is_file())
    check("统计 1/1", app.last_fix_stats["applied"] == 1)

    app.rename_new_var.set("system")
    root.update()
    check("超长校验拦截", app.rename_hint.cget("text").startswith("✗"))

    print("== fix-cmp（样例仅有 3D 短格式 cmp，验证拒绝路径）==")
    # 样例中 `cmp rax, 0x404040` 为 0x3D 短格式，核心策略仅支持 0x80/81/83，
    # 应走「修复未应用」路径：弹窗警告（已被拦截）且不写出文件
    out_cmp = tmpdir / "vuln.fixcmp"
    app.cmp_vaddr_var.set("0x4010d5")
    app.cmp_imm_var.set("0x10")
    app.cmp_out_var.set(str(out_cmp))
    root.update()
    n_popups = len(POPUPS)
    app.run_fix_cmp()
    wait_idle(app)
    check("弹窗提示未应用", len(POPUPS) > n_popups and POPUPS[n_popups][1][0] == "修复未应用")
    check("未写出产物", not out_cmp.is_file())
    check("统计 0/1", app.last_fix_stats["applied"] == 0)

    print("== 合规检测独立运行 ==")
    app.check_orig_var.set(str(work))
    app.run_check()
    wait_idle(app)
    check("结果树 7 项", len(app.check_tree.get_children()) == 7)
    check("汇总文本", "/7 项通过" in app.check_summary.cget("text"))

    print("== 功能测试(skipped on Windows) ==")
    app.test_bin_var.set(str(work))
    app.script_box.delete("1.0", "end")
    app.script_box.insert("1.0", "recvline(timeout=1)\n")
    app.run_test("functional")
    wait_idle(app)
    check("结果标签已更新", "[" in app.test_result.cget("text"))

    print("== doctor（环境检查）==")
    app._run_doctor()
    check("doctor 输出到日志", "环境检查" in app.log_text.get("1.0", "end"))

    print("== 通用补丁（trampoline）==")
    out_patch = tmpdir / "vuln.patched"
    app.patch_pos_var.set("0x40120c")
    app.patch_code_var.set("90")
    app.patch_out_var.set(str(out_patch))
    root.update()
    app.run_patch()
    wait_idle(app)
    check("通用补丁产物已写出", out_patch.is_file())
    check("统计 1/1", app.last_fix_stats["applied"] == 1)
    check("产物等长", out_patch.is_file()
          and out_patch.stat().st_size == Path(app.elf_path).stat().st_size)

    print("== 沙箱（新安装机制）==")
    check("未确认时按钮禁用", app.sb_run_btn.instate(["disabled"]))
    POPUPS.clear()
    app.run_sandbox(dry_run=True)
    wait_idle(app)
    check("dry-run 打印安装计划", "安装方式" in app.log_text.get("1.0", "end"))
    check("dry-run 未写产物", not (tmpdir / "vuln.sandbox").exists()
          or app.sb_out_var.get() == "")
    app.sb_risk_var.set(True)
    root.update()
    check("确认后按钮可用", not app.sb_run_btn.instate(["disabled"]))
    out_sb = tmpdir / "vuln.sb"
    app.sb_out_var.set(str(out_sb))
    app.sb_mode_var.set("黑名单（命中即杀）")
    app.run_sandbox()
    wait_idle(app)
    check("sandbox 产物已写出", out_sb.is_file())
    if out_sb.is_file():
        ia = _read_qword(out_sb, 0x2df8)  # .init_array[0]（固定布局样例）
        check("init_array 已劫持指向 stub", ia != 0x401170 and 0x401000 <= ia < 0x401500,
              f"-> {ia:#x}")

    print("== PIE 支持 ==")
    if pie.is_file():
        app._set_binary_path(str(pie))
        app.load_binary()
        wait_idle(app)
        check("PIE 标记为是", app.info_vars["pie"].get() == "PIE: 是")
        app.scan_calls("free")
        wait_idle(app)
        n_free_pie = len(app.free_sites.checked_addrs())
        check("PIE 扫描到 call free@plt", n_free_pie == 2)
        out_pie = tmpdir / "vuln_pie.fixfree"
        app.autochain_var.set(False)  # 保持原样例为目标，便于继续测拒绝路径
        app.free_ptr_var.set("")  # 无 ptr：应成功
        app.free_out_var.set(str(out_pie))
        app.run_fix_free()
        wait_idle(app)
        check("PIE fix-free 批量成功", app.last_fix_stats["applied"] == 2)
        check("PIE 产物等长", out_pie.stat().st_size == pie.stat().st_size)

        POPUPS.clear()
        app.free_ptr_var.set("0x404050")  # PIE + ptr：应拒绝
        app.free_out_var.set(str(tmpdir / "vuln_pie2"))
        app.run_fix_free()
        wait_idle(app)
        check("PIE+ptr 被拒绝", app.last_fix_stats["applied"] == 0)
        check("拒绝弹窗提示", POPUPS and POPUPS[0][1][0] == "修复未应用")
        app.autochain_var.set(True)
    else:
        print("  [SKIP] 无 PIE 样例（tmp/vuln_pie），跳过 PIE 用例")

    print(f"\n结果: {PASS} passed, {FAIL} failed")
    if POPUPS:
        print("弹窗记录（已拦截，未阻塞）:")
        for name, args in POPUPS:
            print(f"    {name}: {args[0]} - {args[1] if len(args) > 1 else ''}")
    app.elf = None
    root.destroy()
    shutil.rmtree(tmpdir, ignore_errors=True)
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
