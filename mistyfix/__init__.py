"""MistyFix —— AWDP（CTF 攻防赛）PWN 方向合规漏洞修复工具。

修复原则：等长替换、code cave 注入（不改节表/文件大小）、真修复替代 NOP、
改数据不改控制流、不碰 GOT/_start。
"""

__version__ = "0.2.0"

from .elf_utils import Cave, ELFBinary, SectionInfo, diff_files
from .patcher import PatchError, Patcher
from .strategies import (
    PatchPlan,
    dynstr_rename,
    fix_int_compare,
    fix_read_length,
    true_fix_free,
)
from .checker import CheckResult, ComplianceChecker, FunctionalTester, replay_exp
from .injector import InstallPlan, apply_install, plan_install
from .sandbox import build_seccomp_stub, parse_syscall_list

__all__ = [
    "__version__",
    "Cave",
    "ELFBinary",
    "SectionInfo",
    "diff_files",
    "PatchError",
    "Patcher",
    "PatchPlan",
    "fix_read_length",
    "true_fix_free",
    "dynstr_rename",
    "fix_int_compare",
    "CheckResult",
    "ComplianceChecker",
    "FunctionalTester",
    "replay_exp",
    "InstallPlan",
    "plan_install",
    "apply_install",
    "build_seccomp_stub",
    "parse_syscall_list",
]
