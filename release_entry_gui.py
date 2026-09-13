#!/usr/bin/env python3
"""mistyfix-gui.exe 的打包入口：直接进 GUI，不带控制台。

PyInstaller 以本文件作为窗口版入口（console=False），
内部调用 mistyfix.gui.main 保持与 CLI `mistyfix gui` 一致的行为。
"""

from mistyfix.gui import main

if __name__ == "__main__":
    raise SystemExit(main())
