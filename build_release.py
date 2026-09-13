#!/usr/bin/env python3
"""MistyFix 便携版一键构建脚本。

用法（在仓库根目录）::

    python build_release.py

产出 ``dist/MistyFix-v<version>-win64-portable.zip``，解压即用，无需安装
Python 与任何依赖。包含：

- ``mistyfix.exe``      控制台版（完整 CLI，含 ``mistyfix gui`` 子命令）
- ``mistyfix-gui.exe``  窗口版（单文件，双击即开 GUI，无黑框）
- ``README.md`` / ``使用说明.txt``
- ``demo/``             样例二进制（vuln / vuln_pie）与源码

构建细节：
- CLI 用 onedir（启动快）；GUI 用 onefile（双击友好、与 CLI 的 _internal 无冲突）
- keystone.dll 需随包放入 ``keystone/`` 目录（其加载器按 ``__file__`` 同目录查找）
- pwntools 为可选依赖，便携版不带（功能测试优雅降级，doctor 会如实提示）
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
NAME_DIR = "MistyFix"  # 便携目录名（zip 内的顶层目录）

sys.path.insert(0, str(ROOT))
from mistyfix import __version__  # noqa: E402


def keystone_dll_args() -> list[str]:
    """返回 --add-binary 参数，把 keystone.dll 放到冻结包的 keystone/ 目录。"""
    import keystone as _ks
    pkg_dir = Path(_ks.__file__).resolve().parent
    dll = pkg_dir / "keystone.dll"
    if not dll.is_file():
        raise SystemExit(f"[!] 未找到 {dll}（Windows 轮子应内置该 DLL）")
    return ["--add-binary", f"{dll};keystone"]


COMMON_ARGS = [
    "--noconfirm",
    "--clean",
    *keystone_dll_args(),
    "--exclude-module", "pwn",
    "--exclude-module", "pwnlib",
    "--exclude-module", "pytest",
    "--exclude-module", "_pytest",
    "--exclude-module", "setuptools",
    "--exclude-module", "pip",
]


def run(cmd: list[str]) -> None:
    print("[*]", " ".join(str(c) for c in cmd))
    subprocess.run([sys.executable, "-m", "PyInstaller", *cmd], check=True,
                   cwd=ROOT)


def main() -> int:
    print(f"[*] 构建 MistyFix v{__version__} 便携版")

    # 干净起步：清掉历史构建产物，避免旧文件锁/半成品干扰
    if DIST.exists():
        shutil.rmtree(DIST, ignore_errors=True)

    # 1) CLI（onedir，控制台）
    run(["release_entry_cli.py", "--name", "mistyfix", "--paths", ".", *COMMON_ARGS])

    # 2) GUI（onefile，无控制台）
    run(["release_entry_gui.py", "--name", "mistyfix-gui", "--onefile",
         "--noconsole", "--paths", ".", *COMMON_ARGS])

    if not (DIST / "mistyfix" / "mistyfix.exe").is_file():
        raise SystemExit("[!] CLI 构建产物缺失: dist/mistyfix/mistyfix.exe")
    if not (DIST / "mistyfix-gui.exe").is_file():
        raise SystemExit("[!] GUI 构建产物缺失: dist/mistyfix-gui.exe")

    # 3) 装配便携目录（注意：Windows 文件系统不区分大小写，staging 目录
    #    不能与源 dist/mistyfix 同名，否则 rmtree(portable) 会把源删掉）
    stage_parent = DIST / "_stage"
    stage = stage_parent / NAME_DIR
    if stage_parent.exists():
        shutil.rmtree(stage_parent, ignore_errors=True)
    shutil.copytree(DIST / "mistyfix", stage)  # mistyfix.exe + _internal/
    shutil.copy2(DIST / "mistyfix-gui.exe", stage / "mistyfix-gui.exe")
    shutil.copy2(ROOT / "README.md", stage / "README.md")
    (stage / "使用说明.txt").write_text(USAGE_TXT, encoding="utf-8")
    demo = stage / "demo"
    demo.mkdir()
    for f in ("vuln", "vuln_pie", "vuln.c"):
        src = ROOT / "tmp" / f
        if src.is_file():
            shutil.copy2(src, demo / f)

    # 4) 打 zip（顶层目录为 MistyFix/）
    zip_path = DIST / f"MistyFix-v{__version__}-win64-portable.zip"
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for p in sorted(stage.rglob("*")):
            zf.write(p, Path(NAME_DIR) / p.relative_to(stage))
    shutil.rmtree(stage_parent, ignore_errors=True)
    size_mb = zip_path.stat().st_size / 1024 / 1024
    print(f"[+] 便携包: {zip_path} ({size_mb:.1f} MB)")
    return 0


USAGE_TXT = f"""\
MistyFix v{__version__} 便携版 — AWDP PWN 合规修复工具
======================================================

【快速开始】
  1. 双击 mistyfix-gui.exe 打开图形界面（推荐）；
     或在终端运行 mistyfix.exe 使用完整命令行（mistyfix.exe --help）。
  2. GUI: 顶部选择目标 ELF → 各标签页修复 → 自动合规检测。
  3. demo/ 内附样例二进制（vuln 含栈溢出 + UAF/double-free，vuln_pie 为
     PIE 样例），可直接用来试用。

【说明】
  - 本包自带全部依赖（lief/capstone/keystone/tkinter），无需安装 Python。
  - pwntools 未打包（可选依赖）：功能测试/exp 复验仍可用内置交互原语，
    doctor 会如实显示该项缺失。
  - 功能测试/exp 复验仅在 Linux 上实际运行 ELF，Windows 下返回 skipped。
  - seccomp 沙箱为研究用途，赛事规则风险详见 README「合规警告」。
"""


if __name__ == "__main__":
    raise SystemExit(main())
