"""MistyFix 命令行接口。

子命令：info / caves / fix-read / fix-free / rename / check / test / sandbox /
patch / doctor / exp / batch / traffic / gui
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

from . import __version__
from .checker import CheckResult, ComplianceChecker, FunctionalTester
from .elf_utils import ELFBinary
from .injector import apply_install, plan_install
from .patcher import Patcher
from .sandbox import build_seccomp_stub, parse_syscall_list, rules_warning
from .strategies import (
    PatchPlan,
    RENAME_PRESETS,
    dynstr_rename,
    fix_read_length,
    true_fix_free,
)


def _parse_int(text: str) -> int:
    """解析地址/数值参数，支持十进制与 0x 十六进制。"""
    try:
        return int(text, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(f"无效的数值: {text!r}（支持十进制或 0x 前缀十六进制）")


def _print_plan(plan: PatchPlan) -> None:
    print(f"[*] 修复方案: {plan.description}")
    for change in plan.changes:
        print(f"    - {change}")
    print(f"[*] 状态: {'已应用' if plan.applied else '未应用'}")


def _print_check_results(results: list[CheckResult]) -> bool:
    """逐条打印检测结果，返回是否全部通过。"""
    all_passed = True
    for r in results:
        mark = "PASS" if r.passed else "FAIL"
        print(f"  [{mark}] {r.name}: {r.detail}")
        if not r.passed:
            all_passed = False
    return all_passed


def _run_compliance_check(orig_path: str, patched_path: str) -> bool:
    """对修复产物跑一次合规检测并打印结果。"""
    print("[*] 自动合规检测（原文件 vs 修复后文件）:")
    checker = ComplianceChecker(orig_path, patched_path)
    results = checker.run_all()
    all_passed = _print_check_results(results)
    if all_passed:
        print("[+] 合规检测全部通过")
    else:
        print("[!] 存在未通过的合规检测项，请检查修复方式")
    return all_passed


def cmd_info(args: argparse.Namespace) -> int:
    elf = ELFBinary(args.binary)
    print(f"文件:      {elf.path}")
    print(f"架构:      {elf.arch}")
    print(f"入口地址:  0x{elf.entry_vaddr():x}")
    print(f"文件大小:  {len(elf.data)} 字节")
    print("节列表:")
    for s in elf.sections():
        print(f"  {s.name:<16} vaddr=0x{s.vaddr:012x} size=0x{s.size:<8x} offset=0x{s.offset:x}")
    caves = elf.caves()
    print(f"可用 cave（>= 32 字节，共 {len(caves)} 个）:")
    for c in caves:
        print(f"  {c.section:<16} vaddr=0x{c.vaddr:012x} offset=0x{c.file_offset:<8x} size={c.size}")
    return 0


def cmd_caves(args: argparse.Namespace) -> int:
    elf = ELFBinary(args.binary)
    caves = elf.caves(min_size=args.min_size)
    print(f"可用 cave（>= {args.min_size} 字节，共 {len(caves)} 个）:")
    for c in caves:
        print(f"  {c.section:<16} vaddr=0x{c.vaddr:012x} offset=0x{c.file_offset:<8x} size={c.size}")
    if not caves:
        print("  （无满足条件的 cave）")
    return 0


def cmd_fix_read(args: argparse.Namespace) -> int:
    elf = ELFBinary(args.binary)
    patcher = Patcher(elf)
    plan = fix_read_length(patcher, args.call_vaddr, args.new_len)
    _print_plan(plan)
    if not plan.applied:
        print("[!] 修复未应用，未写出文件")
        return 1
    patcher.save(args.output)
    print(f"[+] 已保存: {args.output}")
    _run_compliance_check(args.binary, args.output)
    return 0


def cmd_fix_free(args: argparse.Namespace) -> int:
    elf = ELFBinary(args.binary)
    patcher = Patcher(elf)
    plan = true_fix_free(patcher, args.call_vaddr, args.ptr)
    _print_plan(plan)
    if not plan.applied:
        print("[!] 修复未应用，未写出文件")
        return 1
    patcher.save(args.output)
    print(f"[+] 已保存: {args.output}")
    _run_compliance_check(args.binary, args.output)
    return 0


def cmd_rename(args: argparse.Namespace) -> int:
    old, new = args.old, args.new
    if args.preset:
        try:
            old, new, _desc = RENAME_PRESETS[args.preset]
        except KeyError:
            print(f"[!] 未知预设: {args.preset}", file=sys.stderr)
            print("    可用预设:", ", ".join(sorted(RENAME_PRESETS)), file=sys.stderr)
            return 2
        print(f"[*] 使用预设 {args.preset}: {old} -> {new}")
    elf = ELFBinary(args.binary)
    plan = dynstr_rename(elf, old=old, new=new)
    _print_plan(plan)
    if not plan.applied:
        print("[!] 重命名未应用，未写出文件")
        return 1
    elf.save(args.output)
    print(f"[+] 已保存: {args.output}")
    _run_compliance_check(args.binary, args.output)
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    checker = ComplianceChecker(args.orig, args.patched)
    results = checker.run_all()
    print(f"合规检测: {args.orig} vs {args.patched}")
    all_passed = _print_check_results(results)
    if all_passed:
        print("[+] 全部通过")
        return 0
    print("[!] 存在未通过项")
    return 1


def cmd_test(args: argparse.Namespace) -> int:
    script = Path(args.script).read_text(encoding="utf-8")
    tester = FunctionalTester(args.binary)
    result = tester.run_script(script)
    mark = "PASS" if result.passed else "FAIL"
    print(f"[{mark}] {result.name}: {result.detail}")
    return 0 if result.passed else 1


def cmd_traffic(args: argparse.Namespace) -> int:
    from . import traffic  # 延迟导入：receiver 模式常驻运行

    return traffic.main(args.rest)


def cmd_gui(args: argparse.Namespace) -> int:
    from .gui import run_gui  # 延迟导入：无显示环境时不受影响

    return run_gui(args.binary)


def cmd_sandbox(args: argparse.Namespace) -> int:
    print(rules_warning())
    if not args.dry_run and not args.i_know_the_risk:
        print("[!] sandbox 会安装 seccomp 规则，属于 AWDP 规则敏感操作。")
        print("    如确认了解风险并仍需执行，请显式添加 --i-know-the-risk")
        print("    （--dry-run 仅打印安装计划，无需确认）")
        return 2

    elf = ELFBinary(args.binary)
    arch = args.arch if args.arch else elf.arch
    allow = tuple(s.strip() for s in args.allow.split(",") if s.strip())
    blacklist: tuple[int, ...] = ()
    if args.mode == "blacklist":
        try:
            blacklist = tuple(parse_syscall_list(args.blacklist))
        except ValueError as e:
            print(f"[!] {e}", file=sys.stderr)
            return 1
    mode_desc = {
        "whitelist": f"白名单（允许: {', '.join(allow)}，其余 EPERM）",
        "blacklist": f"黑名单（命中即杀: {', '.join(map(str, blacklist))}，其余放行）",
        "strict": "strict（内核仅放行 read/write/exit/sigreturn，大概率破坏功能）",
    }[args.mode]

    # 探针用 obfuscate=False（mov-eax 最长变体）做长度上界；实际混淆产物只会更短
    probe = build_seccomp_stub(arch, allow=allow, blacklist=blacklist,
                               mode=args.mode, obfuscate=False, vaddr=0, entry_jmp_to=0)
    plan = plan_install(elf, len(probe))
    print(f"[*] seccomp stub（arch={arch}，模式: {mode_desc}，≤{len(probe)} 字节）")
    print("[*] 安装计划:")
    for line in plan.describe().splitlines():
        print(f"    {line}")
    if plan.hook_label == "e_entry":
        print("[!] 注意: 改写 e_entry 属于高可见度改动（入口跳转），运行时检测极易暴露")
    if plan.need_phdr_grow:
        print("[!] 注意: 无足够 cave，使用段尾注入 + 段头扩容（修改 16 字节段头）")

    if args.dry_run:
        print("[+] dry-run 模式，不写出文件")
        return 0

    def make_stub(vaddr: int, hook_orig: int) -> bytes:
        return build_seccomp_stub(arch, allow=allow, blacklist=blacklist,
                                  mode=args.mode, vaddr=vaddr, entry_jmp_to=hook_orig)

    patcher = Patcher(elf)
    stub_vaddr = apply_install(patcher, plan, make_stub)
    print(f"[*] 已安装 stub @ 0x{stub_vaddr:x}（{plan.method}）")
    patcher.save(args.output)
    print(f"[+] 已保存: {args.output}")
    _run_compliance_check(args.binary, args.output)
    return 0


# ---------------------------------------------------------------------------
# 通用 trampoline patch（前身项目 4.elf-patcher.py 的等长移植）
# ---------------------------------------------------------------------------
def _parse_hex_code(raw: str) -> bytes:
    """解析插入机器码：'5058' / '\\x50\\x58' / '50 58' / '50,58'。"""
    text = raw.strip()
    if not text:
        raise argparse.ArgumentTypeError("insert_code 不能为空")
    normalized = (text.replace(" ", "").replace("\t", "").replace("\n", "")
                  .replace(",", "").replace("\\x", "").replace("\\X", "")
                  .replace("0x", "").replace("0X", ""))
    if not normalized or len(normalized) % 2 != 0:
        raise argparse.ArgumentTypeError("insert_code 必须是偶数个十六进制字符")
    try:
        return bytes.fromhex(normalized)
    except ValueError:
        raise argparse.ArgumentTypeError("insert_code 不是有效十六进制字节串") from None


def cmd_patch(args: argparse.Namespace) -> int:
    elf = ELFBinary(args.binary)
    if args.offset_mode:
        try:
            vaddr = elf.offset_to_vaddr(args.pos)
        except Exception as e:
            print(f"[!] 文件偏移不可映射: {e}", file=sys.stderr)
            return 1
    else:
        try:
            elf.vaddr_to_offset(args.pos)  # 校验可映射
        except Exception as e:
            print(f"[!] 地址不可映射: {e}", file=sys.stderr)
            return 1
        vaddr = args.pos

    patcher = Patcher(elf)
    try:
        cave_vaddr = patcher.build_trampoline(vaddr, args.insert_code, stolen=5, resteal=True)
    except Exception as e:
        print(f"[!] trampoline 失败: {type(e).__name__}: {e}", file=sys.stderr)
        return 1

    print(f"[*] hook 0x{vaddr:x} -> cave 0x{cave_vaddr:x}：先执行插入代码，"
          f"再重放被覆盖的原指令并跳回（RIP 相对指令会被拒绝搬运）")
    for entry in patcher.log:
        print(f"    - {entry}")
    if args.dry_run:
        print("[+] dry-run 模式，不写出文件")
        return 0
    patcher.save(args.output)
    print(f"[+] 已保存: {args.output}")
    _run_compliance_check(args.binary, args.output)
    return 0


# ---------------------------------------------------------------------------
# 环境检查（前身项目 1.Check_Environment.sh 的 Python 升级版）
# ---------------------------------------------------------------------------
def collect_doctor_rows() -> list[tuple[str, bool, str]]:
    """返回环境检查结果 [(名称, 是否就绪, 缺失提示)]，GUI/CLI 共用。"""
    import platform

    py = sys.version_info
    rows: list[tuple[str, bool, str]] = []
    rows.append((f"Python {py.major}.{py.minor}.{py.micro} ({platform.system()} "
                 f"{platform.machine()})", py >= (3, 10), "需要 >= 3.10"))
    for mod, required, purpose in (
        ("lief", True, "ELF 解析"),
        ("capstone", True, "反汇编"),
        ("keystone", True, "汇编/stub 生成"),
        ("pwn", False, "可选：交互测试可用 pwntools 特性"),
        ("tkinter", False, "可选：GUI"),
    ):
        try:
            __import__(mod)
            ok = True
        except ImportError:
            ok = False
        hint = "" if ok else f"pip install {mod}" + ("" if required else "（可选）")
        rows.append((f"模块 {mod}（{purpose}）", ok or not required, hint))
    is_linux = sys.platform.startswith("linux")
    rows.append(("Linux 运行环境（功能测试/exp 复验实际运行 ELF）", is_linux,
                 "非 Linux 平台 test/replay 返回 skipped"))
    return rows


def cmd_doctor(args: argparse.Namespace) -> int:
    missing_required = False
    for name, ok, hint in collect_doctor_rows():
        mark = "OK " if ok else "MISS"
        print(f"  [{mark}] {name}" + (f"  -> {hint}" if hint and not ok else ""))
        if not ok and hint and "可选" not in hint and "非 Linux" not in hint:
            missing_required = True
    if missing_required:
        print("[!] 存在缺失的必需依赖")
        return 1
    print("[+] 环境检查通过")
    return 0


# ---------------------------------------------------------------------------
# AWD 攻击侧工具（前身项目 0/8 号脚本，与 AWDP 合规修复共存、互不混用）
# ---------------------------------------------------------------------------
_EXP_TEMPLATE = '''#!/usr/bin/env python3
"""pwntools EXP 模板（mistyfix exp 生成；前身 AWD-Tools-For-PWN 模板升级版）。

用法: python {exp_name} [host port]   # 无参数走本地 process
"""
from pwn import *

context(arch="amd64", os="linux", log_level="info")
context.binary = "{binary}"

if len(args) >= 2:
    p = remote(args[1], int(args[2]))
else:
    p = process(context.binary.path)
    context.log_level = "debug"

elf = context.binary
# libc = ELF("./libc.so.6", checksec=False)

# ---- 利用逻辑（按题目补充） ----
p.interactive()

# 自动尝试读 flag（mistyfix batch 依赖 "FOUND FLAG: " 关键字）
print("Trying to get flag...")
p.sendline(b"cat /flag")
flag = p.recvline(timeout=3)
if flag:
    print("FOUND FLAG: ", flag.decode(errors="replace"))
'''


def cmd_exp(args: argparse.Namespace) -> int:
    exp_name = Path(args.output).name
    text = _EXP_TEMPLATE.format(exp_name=exp_name, binary=args.binary)
    Path(args.output).write_text(text, encoding="utf-8")
    print(f"[+] EXP 模板已生成: {args.output}（记得补充利用逻辑、核对 binary 路径）")
    return 0


def cmd_batch(args: argparse.Namespace) -> int:
    hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
    try:
        ports = [int(p) for p in args.ports.split(",") if p.strip()]
    except ValueError:
        print("[!] --ports 需为逗号分隔的数字", file=sys.stderr)
        return 1
    if not hosts or not ports:
        print("[!] --hosts/--ports 不能为空", file=sys.stderr)
        return 1
    if not Path(args.exp).is_file():
        print(f"[!] exp 脚本不存在: {args.exp}", file=sys.stderr)
        return 1

    print(f"[*] 批量攻击 {len(hosts)}x{len(ports)} 个目标（exp={args.exp}, 关键字={args.keyword!r}）")
    hits = 0
    for host in hosts:
        for port in ports:
            print(f"[*] attacking {host}:{port} ...")
            time.sleep(args.delay)
            try:
                result = subprocess.run(
                    [sys.executable, args.exp, host, str(port)],
                    capture_output=True, text=True, timeout=args.timeout)
                output = result.stdout
            except subprocess.TimeoutExpired as e:
                output = (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
                print(f"    [!] 超时（>{args.timeout}s），跳过")
            for line in output.splitlines():
                if args.keyword in line:
                    entry = f"Host: {host}, Port: {port}, Output: {line}"
                    print(f"    [+] {entry}")
                    with open(args.out, "a", encoding="utf-8") as f:
                        f.write(entry + "\n")
                    hits += 1
    print(f"[*] 完成：命中 {hits} 条，结果追加写入 {args.out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mistyfix",
        description="MistyFix —— AWDP PWN 方向合规漏洞修复工具",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_info = sub.add_parser("info", help="打印二进制基本信息（架构、入口、节、cave）")
    p_info.add_argument("binary", help="目标 ELF 文件")
    p_info.set_defaults(func=cmd_info)

    p_caves = sub.add_parser("caves", help="列出可用 code cave")
    p_caves.add_argument("binary", help="目标 ELF 文件")
    p_caves.add_argument("--min-size", type=int, default=32, help="cave 最小字节数（默认 32）")
    p_caves.set_defaults(func=cmd_caves)

    p_fix_read = sub.add_parser("fix-read", help="修复 read 长度参数（等长替换立即数）")
    p_fix_read.add_argument("binary", help="目标 ELF 文件")
    p_fix_read.add_argument("call_vaddr", type=_parse_int, help="call read@plt 指令的 vaddr（支持 0x）")
    p_fix_read.add_argument("new_len", type=_parse_int, help="新的长度值（支持 0x）")
    p_fix_read.add_argument("-o", "--output", required=True, help="输出文件路径")
    p_fix_read.set_defaults(func=cmd_fix_read)

    p_fix_free = sub.add_parser("fix-free", help="真修复 UAF/Double-Free（置空指针，非 NOP）")
    p_fix_free.add_argument("binary", help="目标 ELF 文件")
    p_fix_free.add_argument("call_vaddr", type=_parse_int, help="call free@plt 指令的 vaddr（支持 0x）")
    p_fix_free.add_argument("--ptr", type=_parse_int, default=None, help="指针变量的 vaddr（可选）")
    p_fix_free.add_argument("-o", "--output", required=True, help="输出文件路径")
    p_fix_free.set_defaults(func=cmd_fix_free)

    p_rename = sub.add_parser(
        "rename", help=".dynstr 符号改名（如 free -> atoi，需等长）",
        epilog="常用预设: " + ", ".join(f"{k} ({o}->{n})" for k, (o, n, _d)
                                        in RENAME_PRESETS.items()),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p_rename.add_argument("binary", help="目标 ELF 文件")
    p_rename.add_argument("--old", default="free", help="原符号名（默认 free）")
    p_rename.add_argument("--new", default="atoi", help="新符号名（默认 atoi）")
    p_rename.add_argument("--preset", default=None, metavar="KEY",
                          help="使用内置预设（覆盖 --old/--new），见上方预设列表")
    p_rename.add_argument("-o", "--output", required=True, help="输出文件路径")
    p_rename.set_defaults(func=cmd_rename)

    p_check = sub.add_parser("check", help="对比原文件与修复文件的合规性")
    p_check.add_argument("orig", help="原始 ELF 文件")
    p_check.add_argument("patched", help="修复后的 ELF 文件")
    p_check.set_defaults(func=cmd_check)

    p_test = sub.add_parser("test", help="用 python 交互脚本做功能测试")
    p_test.add_argument("binary", help="目标 ELF 文件")
    p_test.add_argument("--script", required=True, help="交互脚本文件路径（python 代码片段）")
    p_test.set_defaults(func=cmd_test)

    p_traffic = sub.add_parser(
        "traffic",
        help="流量镜像（前身项目移植）：patch 注入 / receiver 接收，详见 python -m mistyfix.traffic -h")
    p_traffic.add_argument("rest", nargs=argparse.REMAINDER,
                           help="传递给 traffic 的子命令与参数（patch / receiver ...）")
    p_traffic.set_defaults(func=cmd_traffic)

    p_gui = sub.add_parser("gui", help="启动图形界面（可选传入初始目标文件）")
    p_gui.add_argument("binary", nargs="?", default=None, help="启动时加载的 ELF 文件（可选）")
    p_gui.set_defaults(func=cmd_gui)

    p_sandbox = sub.add_parser(
        "sandbox", help="安装 seccomp 沙箱 stub（规则敏感，需 --i-know-the-risk）")
    p_sandbox.add_argument("binary", help="目标 ELF 文件")
    p_sandbox.add_argument("--arch", choices=["amd64", "i386"], default=None,
                           help="目标架构（默认取二进制自身架构）")
    p_sandbox.add_argument("--mode", choices=["whitelist", "blacklist", "strict"],
                           default="whitelist",
                           help="seccomp 模式：whitelist 白名单（默认）/ blacklist 黑名单"
                                "（命中即杀，破坏面最小）/ strict 内核严格模式")
    p_sandbox.add_argument("--allow", default="read,write,exit,exit_group",
                           help="白名单模式允许的 syscall（逗号分隔，名或编号）")
    p_sandbox.add_argument("--blacklist", default="execve,execveat,openat,openat2",
                           help="黑名单模式封禁的 syscall（逗号分隔，名或编号）")
    p_sandbox.add_argument("-o", "--output", required=True, help="输出文件路径")
    p_sandbox.add_argument("--dry-run", action="store_true",
                           help="只打印安装计划，不写出文件（无需风险确认）")
    p_sandbox.add_argument("--i-know-the-risk", action="store_true",
                           help="确认了解 AWDP 规则风险后才执行注入")
    p_sandbox.set_defaults(func=cmd_sandbox)

    p_patch = sub.add_parser(
        "patch", help="通用 trampoline：在任意地址插入任意机器码（等长，前身项目移植）")
    p_patch.add_argument("binary", help="目标 ELF 文件")
    p_patch.add_argument("pos", type=_parse_int,
                         help="补丁位置 vaddr（--offset-mode 时为文件偏移，支持 0x）")
    p_patch.add_argument("insert_code", type=_parse_hex_code,
                         help="插入机器码（5058 / \\x50\\x58 / '50 58'）")
    p_patch.add_argument("-o", "--output", required=True, help="输出文件路径")
    p_patch.add_argument("--offset-mode", action="store_true",
                         help="将 pos 解释为文件偏移（默认 VA）")
    p_patch.add_argument("--dry-run", action="store_true", help="只打印计划，不写出文件")
    p_patch.set_defaults(func=cmd_patch)

    p_doctor = sub.add_parser("doctor", help="检查运行环境与依赖（前身项目移植升级）")
    p_doctor.set_defaults(func=cmd_doctor)

    p_exp = sub.add_parser("exp", help="生成 pwntools EXP 模板（AWD 攻击侧，前身项目移植）")
    p_exp.add_argument("binary", help="目标 ELF 路径（写入模板 context.binary）")
    p_exp.add_argument("-o", "--output", default="exp.py", help="输出文件（默认 exp.py）")
    p_exp.set_defaults(func=cmd_exp)

    p_batch = sub.add_parser(
        "batch", help="批量调用 EXP 攻击 hosts x ports 并收集 flag（前身项目参数化）")
    p_batch.add_argument("--hosts", required=True, help="逗号分隔的目标主机")
    p_batch.add_argument("--ports", required=True, help="逗号分隔的目标端口")
    p_batch.add_argument("--exp", default="exp.py", help="EXP 脚本（默认 exp.py）")
    p_batch.add_argument("--keyword", default="FOUND FLAG: ",
                         help="命中关键字（默认 'FOUND FLAG: '）")
    p_batch.add_argument("--out", default="flags.txt", help="结果输出文件（默认 flags.txt）")
    p_batch.add_argument("--delay", type=float, default=1.0, help="每轮间隔秒数（默认 1）")
    p_batch.add_argument("--timeout", type=int, default=120, help="单个 exp 超时秒数")
    p_batch.set_defaults(func=cmd_batch)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as e:
        print(f"[!] 文件不存在: {e.filename}", file=sys.stderr)
        return 1
    except Exception as e:  # PatchError、lief 解析错误等统一兜底
        print(f"[!] 执行失败: {type(e).__name__}: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
