"""MistyFix 自检模块：模拟 AWDP 平台的 fix 合规检测与功能/EXP 复验。

ComplianceChecker 对比原始二进制与修复后二进制，逐项检查：
文件大小、节表、.got.plt、_start 机器码、.eh_frame prctl 特征码、
call free 被 NOP 的特征、修改字节总量。

FunctionalTester / replay_exp 通过 subprocess 与程序交互，
验证正常业务流程不变、官方 exp 失效。仅在 Linux 上实际运行，
其他平台返回 skipped 的 CheckResult。
"""

from __future__ import annotations

import os
import re
import select
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any, Optional

try:
    from .elf_utils import ELFBinary, ELFError, diff_files
except ImportError:  # 允许在包外直接调试本模块
    from elf_utils import ELFBinary, ELFError, diff_files  # type: ignore[no-redef]

try:
    import capstone  # type: ignore[import-not-found]
except ImportError:  # capstone 缺失时退化为纯字节特征判断
    capstone = None  # type: ignore[assignment]

_IS_LINUX: bool = sys.platform.startswith("linux")

_SKIP_DETAIL = "skipped: 非 Linux 平台无法运行 ELF"

# AWDP 平台在 .eh_frame 中扫描的 prctl 特征码
_PRCTL_SIGNATURES: dict[str, bytes] = {
    "amd64": bytes.fromhex("B0 9D 0F 05"),
    "i386": bytes.fromhex("B0 AC CD 80"),
}

# 修改字节数的告警阈值
_MODIFIED_BYTES_WARN = 128

# exp 输出中的 flag 特征
_FLAG_RE = re.compile(rb"[A-Za-z0-9_]*(?:flag|ctf)[A-Za-z0-9_]*\{[^\}\r\n]{1,128}\}", re.IGNORECASE)


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str = ""


class ComplianceChecker:
    """对比原始与修复后二进制，模拟 AWDP 平台的各项静态检测。"""

    def __init__(self, orig_path: str, patched_path: str) -> None:
        self.orig_path = orig_path
        self.patched_path = patched_path
        self._orig: Optional[ELFBinary] = None
        self._patched: Optional[ELFBinary] = None

    @property
    def orig(self) -> ELFBinary:
        if self._orig is None:
            self._orig = ELFBinary(self.orig_path)
        return self._orig

    @property
    def patched(self) -> ELFBinary:
        if self._patched is None:
            self._patched = ELFBinary(self.patched_path)
        return self._patched

    def run_all(self) -> list[CheckResult]:
        """依次执行全部合规检查，单项异常不会中断其余检查。"""
        checks = (
            self.check_size,
            self.check_sections,
            self.check_got_plt,
            self.check_start,
            self.check_eh_frame_signatures,
            self.check_nopped_call_free,
            self.check_modified_bytes,
        )
        results: list[CheckResult] = []
        for fn in checks:
            try:
                results.append(fn())
            except Exception as exc:
                results.append(CheckResult(fn.__name__, False, f"检查执行异常: {exc!r}"))
        return results

    def check_size(self) -> CheckResult:
        """文件大小必须一致（AWDP 检测手段 1）。"""
        name = "check_size"
        a = os.path.getsize(self.orig_path)
        b = os.path.getsize(self.patched_path)
        if a == b:
            return CheckResult(name, True, f"文件大小一致: {a} 字节")
        return CheckResult(name, False, f"文件大小改变: {a} -> {b}（相差 {b - a:+d} 字节）")

    def check_sections(self) -> CheckResult:
        """节表 name/vaddr/size 必须逐项一致（AWDP 检测手段 2，对应 LIEF 解析比对）。"""
        name = "check_sections"
        orig_secs = {s.name: (s.vaddr, s.size) for s in self.orig.sections()}
        patched_secs = {s.name: (s.vaddr, s.size) for s in self.patched.sections()}
        diffs: list[str] = []
        for sec_name in sorted(set(orig_secs) | set(patched_secs)):
            if sec_name not in orig_secs:
                diffs.append(f"新增节 {sec_name!r}")
            elif sec_name not in patched_secs:
                diffs.append(f"缺失节 {sec_name!r}")
            else:
                (ov, osz), (pv, psz) = orig_secs[sec_name], patched_secs[sec_name]
                if ov != pv or osz != psz:
                    diffs.append(
                        f"节 {sec_name!r} 变化: vaddr {ov:#x}->{pv:#x}, size {osz:#x}->{psz:#x}"
                    )
        if diffs:
            return CheckResult(name, False, "; ".join(diffs))
        return CheckResult(name, True, f"{len(orig_secs)} 个节的 name/vaddr/size 全部一致")

    def check_got_plt(self) -> CheckResult:
        """.got.plt 内容必须逐字节一致（AWDP 检测手段 3）。

        全 RELRO（-z now）二进制没有 .got.plt，退回比对 .got；
        两者皆无（如静态二进制）则视为无需比对。
        """
        name = "check_got_plt"
        try:
            a = self.orig.got_plt_bytes()
            b = self.patched.got_plt_bytes()
            label = ".got.plt"
        except ELFError:
            try:
                a = self.orig.section_data(".got")
                b = self.patched.section_data(".got")
                label = ".got（无 .got.plt，full RELRO）"
            except ELFError:
                return CheckResult(name, True, "无 .got.plt/.got（无需比对）")
        if a == b:
            return CheckResult(name, True, f"{label} 一致（{len(a)} 字节）")
        diffs = [i for i in range(min(len(a), len(b))) if a[i] != b[i]]
        if len(a) != len(b):
            return CheckResult(name, False, f"{label} 长度改变: {len(a)} -> {len(b)}")
        return CheckResult(name, False,
                           f"{label} 有 {len(diffs)} 字节不同，首个偏移 {diffs[0]:#x}")

    def check_start(self) -> CheckResult:
        """_start 入口机器码必须一致（AWDP 检测手段 4）。"""
        name = "check_start"
        a = self.orig.start_bytes()
        b = self.patched.start_bytes()
        if a == b:
            return CheckResult(name, True, f"_start 机器码一致（{len(a)} 字节）")
        diffs = sum(1 for x, y in zip(a, b) if x != y) + abs(len(a) - len(b))
        return CheckResult(name, False, f"_start 机器码有 {diffs} 字节不同")

    def check_eh_frame_signatures(self) -> CheckResult:
        """patched 的 .eh_frame 不得含 prctl 特征码（AWDP 检测手段 5）。"""
        name = "check_eh_frame_signatures"
        arch = self.patched.arch
        sig = _PRCTL_SIGNATURES.get(arch)
        if sig is None:
            return CheckResult(name, False, f"未知架构 {arch!r}，无对应特征码")
        data = self.patched.section_data(".eh_frame")
        hits: list[int] = []
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx < 0:
                break
            hits.append(idx)
            start = idx + 1
        if hits:
            offs = ", ".join(f"+{h:#x}" for h in hits[:8])
            extra = f" 等 {len(hits)} 处" if len(hits) > 8 else ""
            return CheckResult(
                name, False,
                f".eh_frame 中命中 prctl 特征码 {sig.hex(' ')}（{arch}）: 节内偏移 {offs}{extra}",
            )
        return CheckResult(name, True, f".eh_frame（{len(data)} 字节）未命中 {arch} prctl 特征码")

    def check_nopped_call_free(self) -> CheckResult:
        """call free@plt 不得被 NOP 掉（AWDP 检测手段 6）。

        - 保持原样或等长改写为其他指令：通过
        - 被改写为 jmp（trampoline 跳转）：WARN 级别通过并注明
        - 被改写为 NOP 序列：失败
        """
        name = "check_nopped_call_free"
        calls = self.orig.find_calls_to("free")
        if not calls:
            return CheckResult(name, True, "原文件中未发现 call free@plt，无需检查")

        md = None
        if capstone is not None:
            mode = capstone.CS_MODE_64 if self.patched.arch == "amd64" else capstone.CS_MODE_32
            md = capstone.Cs(capstone.CS_ARCH_X86, mode)

        nopped: list[str] = []
        jmped: list[str] = []
        rewritten: list[str] = []
        for vaddr in calls:
            orig_raw = bytes(self.orig.data[self.orig.vaddr_to_offset(vaddr):][:5])
            new_raw = bytes(self.patched.data[self.patched.vaddr_to_offset(vaddr):][:5])
            site = f"{vaddr:#x}"
            if new_raw == orig_raw:
                continue  # 未改动
            if all(b == 0x90 for b in new_raw):
                nopped.append(site)
                continue
            if self._is_jmp(md, new_raw, vaddr):
                jmped.append(site)
            else:
                rewritten.append(site)

        if nopped:
            return CheckResult(
                name, False,
                f"call free@plt 被 NOP（AWDP 特征检测会命中）: {', '.join(nopped)}",
            )
        parts: list[str] = []
        if jmped:
            parts.append(f"WARN: {', '.join(jmped)} 处被改写为 jmp（trampoline），非 NOP 特征但改动明显")
        if rewritten:
            parts.append(f"{', '.join(rewritten)} 处被等长改写（非 NOP 非 jmp）")
        if not parts:
            return CheckResult(name, True, f"{len(calls)} 处 call free@plt 均未改动")
        return CheckResult(name, True, "; ".join(parts))

    @staticmethod
    def _is_jmp(md: Any, raw: bytes, vaddr: int) -> bool:
        if md is not None:
            for insn in md.disasm(raw, vaddr):
                return insn.mnemonic.startswith("jmp")
            return False
        return raw[:1] in (b"\xe9", b"\xeb", b"\xff")

    def check_modified_bytes(self) -> CheckResult:
        """统计相对原文件的修改量；超过阈值给 WARN 级别通过。"""
        name = "check_modified_bytes"
        diff = diff_files(self.orig_path, self.patched_path)
        if not diff["size_equal"]:
            return CheckResult(name, False, "文件大小不一致（详见 check_size）")
        changed: int = diff["changed_bytes"]
        ranges = diff["changed_ranges"]
        range_desc = ", ".join(f"+{off:#x}({ln}B)" for off, ln in ranges[:6])
        if len(ranges) > 6:
            range_desc += f" 等 {len(ranges)} 段"
        if changed > _MODIFIED_BYTES_WARN:
            return CheckResult(
                name, True,
                f"WARN: 共修改 {changed} 字节（>{_MODIFIED_BYTES_WARN}），修改面较大，"
                f"存在被字节比对重点复查的风险: {range_desc}",
            )
        return CheckResult(name, True, f"共修改 {changed} 字节: {range_desc or '无改动'}")


class _Tube:
    """纯 subprocess 实现的交互辅助，封装 Popen 的 stdin/stdout 读写。

    所有读操作带超时（select），收到的数据会累计到 captured 供 flag 扫描。
    """

    def __init__(self, proc: subprocess.Popen[bytes], captured: bytearray) -> None:
        self.proc = proc
        self.captured = captured

    def send(self, data: bytes | str) -> None:
        if isinstance(data, str):
            data = data.encode()
        assert self.proc.stdin is not None
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def sendline(self, data: bytes | str = b"") -> None:
        if isinstance(data, str):
            data = data.encode()
        self.send(data + b"\n")

    def _wait_readable(self, timeout: float) -> None:
        assert self.proc.stdout is not None
        r, _, _ = select.select([self.proc.stdout], [], [], timeout)
        if not r:
            raise TimeoutError("读取进程输出超时")

    def recv(self, n: int = 4096, timeout: float = 2.0) -> bytes:
        self._wait_readable(timeout)
        assert self.proc.stdout is not None
        chunk = os.read(self.proc.stdout.fileno(), n)
        if not chunk:
            raise EOFError("进程已关闭输出")
        self.captured += chunk
        return chunk

    def recvuntil(self, delim: bytes | str, timeout: float = 5.0) -> bytes:
        if isinstance(delim, str):
            delim = delim.encode()
        buf = bytearray()
        deadline = time.monotonic() + timeout
        while delim not in buf:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"recvuntil({delim!r}) 超时")
            buf += self.recv(1, remaining)
        return bytes(buf)

    def recvline(self, timeout: float = 5.0) -> bytes:
        return self.recvuntil(b"\n", timeout)


def _exec_interaction(binary_path: str, script: str, timeout: int) -> dict[str, Any]:
    """启动二进制并 exec 用户交互片段，在独立线程中运行以便整体限时。

    片段可用变量：p（subprocess.Popen）、tube、send、sendline、recv、
    recvline、recvuntil、time、os；pwntools 可用时另有 pwn。
    返回 {'error', 'timeout', 'returncode', 'captured', 'ns'}。
    """
    result: dict[str, Any] = {
        "error": None,
        "timeout": False,
        "returncode": None,
        "captured": bytearray(),
        "ns": {},
    }
    proc: subprocess.Popen[bytes] = subprocess.Popen(
        [binary_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    tube = _Tube(proc, result["captured"])
    ns: dict[str, Any] = {
        "p": proc,
        "tube": tube,
        "send": tube.send,
        "sendline": tube.sendline,
        "recv": tube.recv,
        "recvline": tube.recvline,
        "recvuntil": tube.recvuntil,
        "time": time,
        "os": os,
    }
    try:  # pwntools 存在时可选使用
        import pwn  # type: ignore[import-not-found]

        pwn.context.log_level = "error"
        ns["pwn"] = pwn
    except ImportError:
        pass
    result["ns"] = ns

    def target() -> None:
        try:
            exec(compile(script, "<interaction>", "exec"), ns)
        except BaseException as exc:  # noqa: BLE001 - 需完整回传用户脚本异常
            result["error"] = exc

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        result["timeout"] = True
        proc.kill()
        proc.wait()
        return result

    # 片段正常结束：关闭 stdin 让程序自然退出，据退出码判断
    try:
        if proc.stdin is not None:
            proc.stdin.close()
    except OSError:
        pass
    try:
        result["returncode"] = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        result["returncode"] = None  # 程序仍在运行，按挂起处理，不算崩溃
    return result


class FunctionalTester:
    """功能交互 check：验证修复后正常业务流程不变（AWDP 检测手段 7）。"""

    def __init__(self, binary_path: str) -> None:
        self.binary_path = binary_path

    def run_script(self, script: str, timeout: int = 10) -> CheckResult:
        """运行交互片段；非零退出、交互异常或超时均判 fail。"""
        name = "functional_test"
        if not _IS_LINUX:
            return CheckResult(name, True, _SKIP_DETAIL)
        r = _exec_interaction(self.binary_path, script, timeout)
        if r["timeout"]:
            return CheckResult(name, False, f"交互超过 {timeout}s 未完成（超时）")
        if r["error"] is not None:
            return CheckResult(name, False, f"交互异常: {r['error']!r}")
        rc = r["returncode"]
        if rc is not None and rc != 0:
            return CheckResult(name, False, f"进程非零退出: returncode={rc}")
        note = "进程仍运行（已终止）" if rc is None else f"进程正常退出: returncode={rc}"
        return CheckResult(name, True, f"交互完成，{note}，收到输出 {len(r['captured'])} 字节")


def replay_exp(binary_path: str, exp_script: str, timeout: int = 15) -> CheckResult:
    """复验官方 exp（AWDP 检测手段 8）。

    exp 拿到 flag/shell（输出匹配 flag 特征，或片段中置 got_flag/success/pwned
    为真）则 passed=False（漏洞仍在）；exp 被拦截、崩溃、异常或超时则
    passed=True（防御成功）。
    """
    name = "replay_exp"
    if not _IS_LINUX:
        return CheckResult(name, True, _SKIP_DETAIL)
    r = _exec_interaction(binary_path, exp_script, timeout)
    if r["timeout"]:
        return CheckResult(name, True, f"exp 超过 {timeout}s 未成功（超时，防御成功）")
    if r["error"] is not None:
        return CheckResult(name, True, f"exp 执行异常（攻击失败，防御成功）: {r['error']!r}")

    captured = bytes(r["captured"])
    m = _FLAG_RE.search(captured)
    ns = r["ns"]
    claimed = any(bool(ns.get(k)) for k in ("got_flag", "success", "pwned", "got_shell"))
    if m or claimed:
        evidence = f"输出命中 flag 特征: {m.group(0)!r}" if m else "exp 脚本声明已拿到 flag/shell"
        return CheckResult(name, False, f"exp 复验失败——{evidence}，漏洞仍然可利用")

    rc = r["returncode"]
    if rc is not None and rc != 0:
        return CheckResult(name, True, f"exp 导致进程异常退出（returncode={rc}，崩溃即防御成功）")
    return CheckResult(name, True, "exp 未获取 flag/shell（防御成功）")
