#!/usr/bin/env python3
"""mistyfix.exe 的打包入口。

mistyfix/cli.py 使用相对导入（`from . import __version__`），不能直接作为
PyInstaller 入口脚本（无包上下文）。本包装器以绝对导入方式调用
mistyfix.cli.main，行为与安装后的 `mistyfix` 命令完全一致。
"""

from mistyfix.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
