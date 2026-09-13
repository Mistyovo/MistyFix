"""MistyFix 可选 seccomp 沙箱 stub 生成模块。

定位：出题人完善 checker 的自测工具 + 应急手段，**不是**常规修复路径。

绝大多数 AWDP 赛事规则明文禁止"通防"（一刀切 seccomp 沙箱），
且运行时检测（/proc/<pid>/status 的 Seccomp / TracerPid 字段）
在内核侧无法隐藏。合规场景应优先使用精准漏洞修复策略。
详见 :func:`rules_warning`。

本模块不依赖 mistyfix 包内其他模块；keystone 仅在 build_seccomp_stub
被调用时才需要，缺失时抛出带说明的 ImportError。
"""

from __future__ import annotations

import random
import struct

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

#: amd64 上 prctl 的系统调用号（157）
PRCTL_NR_AMD64 = 0x9D
#: i386 上 prctl 的系统调用号（172）
PRCTL_NR_I386 = 0xAC

#: AWDP 平台已知的 prctl 特征码（扫描 .eh_frame），绝不允许出现在输出中
FORBIDDEN_SIGNATURES: tuple[bytes, ...] = (
    b"\xb0\x9d\x0f\x05",  # amd64: mov al, 0x9d; syscall
    b"\xb0\xac\xcd\x80",  # i386:  mov al, 0xac; int 0x80
)

#: amd64 常用系统调用号表（build_seccomp_stub 白名单用）
SYSCALL_NR_AMD64: dict[str, int] = {
    "read": 0,
    "write": 1,
    "open": 2,
    "close": 3,
    "stat": 4,
    "fstat": 5,
    "lseek": 8,
    "mmap": 9,
    "mprotect": 10,
    "munmap": 11,
    "brk": 12,
    "rt_sigaction": 13,
    "rt_sigprocmask": 14,
    "rt_sigreturn": 15,
    "ioctl": 16,
    "pread64": 17,
    "pwrite64": 18,
    "readv": 19,
    "writev": 20,
    "access": 21,
    "pipe": 22,
    "select": 23,
    "sched_yield": 24,
    "mremap": 25,
    "dup": 32,
    "dup2": 33,
    "nanosleep": 35,
    "getpid": 39,
    "sendfile": 40,
    "socket": 41,
    "connect": 42,
    "accept": 43,
    "sendto": 44,
    "recvfrom": 45,
    "bind": 49,
    "listen": 50,
    "clone": 56,
    "fork": 57,
    "execve": 59,
    "execveat": 322,
    "exit": 60,
    "wait4": 61,
    "kill": 62,
    "uname": 63,
    "fcntl": 72,
    "getcwd": 79,
    "chdir": 80,
    "mkdir": 83,
    "unlink": 87,
    "readlink": 89,
    "getuid": 102,
    "getgid": 104,
    "geteuid": 107,
    "getegid": 108,
    "arch_prctl": 158,
    "gettid": 186,
    "futex": 202,
    "set_tid_address": 218,
    "exit_group": 231,
    "openat": 257,
    "openat2": 437,
    "mkdirat": 258,
    "set_robust_list": 273,
    "pipe2": 293,
    "getrandom": 318,
    "rseq": 334,
}

#: 支持的架构别名
_ARCH_ALIASES: dict[str, str] = {
    "amd64": "amd64",
    "x86_64": "amd64",
    "x64": "amd64",
    "i386": "i386",
    "x86": "i386",
    "i686": "i686",
}

_PRCTL_VARIANTS = ("mov-eax", "push-pop", "xor-add")


# ---------------------------------------------------------------------------
# 内部辅助
# ---------------------------------------------------------------------------


def _normalize_arch(arch: str) -> str:
    try:
        return _ARCH_ALIASES[arch.lower()]
    except KeyError:
        raise ValueError(
            f"不支持的架构: {arch!r}（支持 amd64 / x86_64 / i386 / x86）"
        ) from None


def _check_forbidden(data: bytes) -> bytes:
    for sig in FORBIDDEN_SIGNATURES:
        assert sig not in data, f"内部错误：生成了已知特征码 {sig.hex()}"
    return data


# ---------------------------------------------------------------------------
# 公开 API
# ---------------------------------------------------------------------------


def rules_warning() -> str:
    """返回中文警告文本：通防沙箱的赛事规则风险说明。"""
    return (
        "【警告】seccomp 通防沙箱是高风险应急手段，使用前请确认赛事规则：\n"
        "1. 多数 AWDP 赛事规则明文禁止使用通防（seccomp 一刀切沙箱）作为 fix 提交，"
        "一旦被判定违规可能直接取消成绩；\n"
        "2. seccomp 状态在内核侧无法隐藏：平台可通过运行时检测 "
        "/proc/<pid>/status 中的 Seccomp 字段与 TracerPid 字段发现沙箱/调试痕迹，"
        "任何用户态混淆都无法掩盖；\n"
        "3. 平台 checker 会扫描 .eh_frame 中的 prctl 特征码"
        "（amd64: B0 9D 0F 05；i386: B0 AC CD 80），本模块已做等价编码规避，"
        "但这只能绕过静态特征扫描，绕不过运行时检测与人工复核；\n"
        "4. 合规场景请优先使用精准修复：等长替换 / code cave 注入 / "
        "真修复替代 NOP / 改数据不改控制流，本模块仅应作为出题人自测 checker 的"
        "工具或万不得已的应急手段。"
    )


def prctl_syscall_bytes(arch: str, variant: str = "auto") -> bytes:
    """返回 ``prctl`` 系统调用（设置 rax/eax 并执行 syscall/int 0x80）的字节序列。

    用于在 stub / shellcode 中发起 prctl 调用，同时规避 AWDP 平台扫描的
    已知特征码 ``B0 9D 0F 05``（amd64）/ ``B0 AC CD 80``（i386）。

    :param arch: ``'amd64'`` 或 ``'i386'``（含 x86_64/x86 等别名）。
    :param variant: 编码方式：

        - ``'mov-eax'``  —— amd64: ``B8 9D 00 00 00 0F 05``
          （mov eax, 0x9d; syscall）；i386: ``B8 AC 00 00 00 CD 80``
        - ``'push-pop'`` —— amd64 按契约为 ``6A 9D 58 0F 05``
          （push 0x9d; pop rax; syscall。注意 6A 为符号扩展 imm8，
          仅供特征自测，勿用于需要真实执行的 stub）；
          i386 为保证可执行使用 push imm32: ``68 AC 00 00 00 58 CD 80``
        - ``'xor-add'``  —— amd64: ``31 C0 04 9D 0F 05``
          （xor eax, eax; add al, 0x9d; syscall）；
          i386: ``31 C0 04 AC CD 80``
        - ``'auto'``     —— 随机选择以上一种。

    返回值保证不含任何已知特征码序列。
    """
    a = _normalize_arch(arch)
    if variant == "auto":
        variant = random.choice(_PRCTL_VARIANTS)
    if variant not in _PRCTL_VARIANTS:
        raise ValueError(f"未知 variant: {variant!r}（支持 {_PRCTL_VARIANTS} 或 'auto'）")

    if a == "amd64":
        table = {
            # mov eax, 0x9d ; syscall
            "mov-eax": b"\xb8\x9d\x00\x00\x00\x0f\x05",
            # push 0x9d(符号扩展imm8) ; pop rax ; syscall —— 契约指定编码
            "push-pop": b"\x6a\x9d\x58\x0f\x05",
            # xor eax, eax ; add al, 0x9d ; syscall
            "xor-add": b"\x31\xc0\x04\x9d\x0f\x05",
        }
    else:
        table = {
            # mov eax, 0xac ; int 0x80
            "mov-eax": b"\xb8\xac\x00\x00\x00\xcd\x80",
            # push imm32 0xac ; pop eax ; int 0x80（push imm8 会符号扩展，故用 imm32）
            "push-pop": b"\x68\xac\x00\x00\x00\x58\xcd\x80",
            # xor eax, eax ; add al, 0xac ; int 0x80
            "xor-add": b"\x31\xc0\x04\xac\xcd\x80",
        }
    return _check_forbidden(table[variant])


def parse_syscall_list(raw: str) -> list[int]:
    """解析逗号分隔的系统调用名/编号列表（黑/白名单通用）。

    支持 ``execve,openat,59``、``sys_execve`` 等写法；未知名称抛 ValueError。
    """
    out: list[int] = []
    for token in raw.split(","):
        t = token.strip().lower()
        if not t:
            continue
        if t.startswith("sys_"):
            t = t[4:]
        try:
            nr = int(t, 0)
        except ValueError:
            nr = SYSCALL_NR_AMD64.get(t)
            if nr is None:
                raise ValueError(
                    f"未知 syscall: {token!r}（支持名称见 SYSCALL_NR_AMD64，或直接用编号）"
                ) from None
        if nr not in out:
            out.append(nr)
    return out


def build_seccomp_stub(
    arch: str,
    allow: tuple = ("read", "write", "exit", "exit_group"),
    blacklist: tuple | list = (),
    mode: str = "whitelist",
    obfuscate: bool = True,
    vaddr: int = 0,
    entry_jmp_to: int | None = None,
) -> bytes:
    """生成完整的 seccomp stub 机器码（amd64）。

    :param mode: 三种模式（移植自前身项目 AWD-Tools-For-PWN 并保留原有白名单）：

        - ``"whitelist"`` —— BPF 白名单：命中 ``allow`` 列表则 ALLOW，
          其余 ``ERRNO|EPERM``（默认，原 MistyFix 行为，破坏面最大）；
        - ``"blacklist"`` —— BPF 黑名单：命中 ``blacklist`` 列表则
          ``KILL_PROCESS``，其余 ALLOW（对正常业务破坏最小，适合只封
          ``execve/openat`` 的研究场景）；
        - ``"strict"`` —— ``PR_SET_SECCOMP`` 严格模式：内核仅放行
          read/write/exit/sigreturn，无 BPF、stub 最小，大概率破坏正常功能。

    :param vaddr: stub 落点虚拟地址，``entry_jmp_to`` 的 rel32 计算基准。
    :param entry_jmp_to: 非 None 时 stub 以 ``jmp rel32`` 收尾（用于
        .init_array[0] / e_entry 劫持安装，跳回原初始化函数/原入口），
        否则以 ``ret`` 收尾（供 trampoline 调用方使用）。
    :returns: stub 机器码字节。

    其余行为与原版一致：prctl 调用序列按 *obfuscate* 做特征码规避编码。
    """
    a = _normalize_arch(arch)
    if a != "amd64":
        raise NotImplementedError(
            "build_seccomp_stub 目前仅完整实现 amd64；i386 的 sock_filter 白名单/"
            "int 0x80 调用序列尚未实现。如需 i386，可仅使用 prctl_syscall_bytes('i386') "
            "自行拼接，但同样受 rules_warning() 所述规则风险约束。"
        )
    if mode not in ("whitelist", "blacklist", "strict"):
        raise ValueError(f"未知 mode: {mode!r}（支持 whitelist / blacklist / strict）")

    try:
        from keystone import KS_ARCH_X86, KS_MODE_64, Ks
    except ImportError as e:  # pragma: no cover
        raise ImportError(
            "build_seccomp_stub 需要 keystone-engine；请安装后重试"
        ) from e

    ks = Ks(KS_ARCH_X86, KS_MODE_64)

    def asm(code: str) -> bytes:
        encoding, _ = ks.asm(code)
        if encoding is None:
            raise ValueError(f"keystone 汇编失败: {code!r}")
        return bytes(encoding)

    def prctl_seq() -> bytes:
        # 只用可真实执行的编码（push-pop 的 6A imm8 符号扩展会破坏 rax，不可用）
        variant = random.choice(("mov-eax", "xor-add")) if obfuscate else "mov-eax"
        return prctl_syscall_bytes("amd64", variant)

    # ---- sock_filter 白名单（struct sock_filter = {u16 code; u8 jt; u8 jf; u32 k}）
    BPF_LD_W_ABS = 0x20          # BPF_LD|BPF_W|BPF_ABS
    BPF_JMP_JEQ_K = 0x15         # BPF_JMP|BPF_JEQ|BPF_K
    BPF_RET_K = 0x06             # BPF_RET|BPF_K
    SECCOMP_RET_ALLOW = 0x7FFF0000
    SECCOMP_RET_ERRNO_EPERM = 0x00050000 | 1  # SECCOMP_RET_ERRNO | EPERM
    SECCOMP_RET_KILL_PROCESS = 0x80000000     # 黑名单命中即杀进程（前身项目语义）

    filters: list[tuple[int, int]] = []  # (低dword: code|jt<<16|jf<<24, 高dword: k)

    def build_bpf_filters() -> None:
        filters.append((BPF_LD_W_ABS, 0))  # 加载 seccomp_data.nr (offset 0)
        if mode == "whitelist":
            unknown = [n for n in allow if n not in SYSCALL_NR_AMD64]
            if unknown:
                raise ValueError(
                    f"未知系统调用名: {unknown}（支持: {sorted(SYSCALL_NR_AMD64)}）")
            for name in allow:
                # 若 nr == 允许项 则顺序执行下一条(ALLOW)，否则跳过一条继续比对
                filters.append((BPF_JMP_JEQ_K | (0 << 16) | (1 << 24), SYSCALL_NR_AMD64[name]))
                filters.append((BPF_RET_K, SECCOMP_RET_ALLOW))
            filters.append((BPF_RET_K, SECCOMP_RET_ERRNO_EPERM))
        else:  # blacklist
            if not blacklist:
                raise ValueError("blacklist 模式需要至少一个 syscall（名或编号）")
            for nr in blacklist:
                filters.append((BPF_JMP_JEQ_K | (0 << 16) | (1 << 24), int(nr)))
                filters.append((BPF_RET_K, SECCOMP_RET_KILL_PROCESS))
            filters.append((BPF_RET_K, SECCOMP_RET_ALLOW))

    # ---- chunk1: 保存寄存器 + prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) 参数
    chunk1 = asm(
        "push rdi; push rsi; push rdx; push rcx;"
        "push r8; push r9; push r10; push r11;"
        "mov edi, 38;"          # PR_SET_NO_NEW_PRIVS
        "mov esi, 1;"
        "xor edx, edx;"
        "xor r10d, r10d;"
        "xor r8d, r8d;"
    )

    if mode == "strict":
        # PR_SET_SECCOMP, SECCOMP_SET_MODE_STRICT(1), NULL —— 无 BPF
        p1, p2 = prctl_seq(), prctl_seq()
        set_strict = asm("mov edi, 22; mov esi, 1; xor edx, edx;")
        chunk3 = asm(
            "pop r11; pop r10; pop r9; pop r8;"
            "pop rcx; pop rdx; pop rsi; pop rdi;"
        )
        body = chunk1 + p1 + set_strict + p2 + chunk3
        tail = _tail_bytes(vaddr, len(body), entry_jmp_to)
        return _check_forbidden(body + tail)

    build_bpf_filters()
    filter_count = len(filters)
    filters_size = filter_count * 8
    prog_off = filters_size                 # struct sock_fprog 紧接 filter 之后
    total_stack = (filters_size + 16 + 15) & ~0xF  # 16 字节对齐

    # ---- chunk2: 栈上构造 filter + sock_fprog，准备 prctl(PR_SET_SECCOMP,...) 参数
    lines = [f"sub rsp, {total_stack};"]
    for i, (lo, hi) in enumerate(filters):
        lines.append(f"mov dword ptr [rsp + {i * 8}], {lo};")
        lines.append(f"mov dword ptr [rsp + {i * 8} + 4], {hi};")
    # sock_fprog { unsigned short len; pad; struct sock_filter *filter; }
    lines.append(f"mov dword ptr [rsp + {prog_off}], {filter_count};")  # len + 2 字节 pad
    lines.append(f"mov dword ptr [rsp + {prog_off} + 4], 0;")
    lines.append("lea rax, [rsp];")
    lines.append(f"mov qword ptr [rsp + {prog_off} + 8], rax;")
    lines.append("mov edi, 22;")        # PR_SET_SECCOMP
    lines.append("mov esi, 2;")         # SECCOMP_MODE_FILTER
    lines.append(f"lea rdx, [rsp + {prog_off}];")
    lines.append("xor r10d, r10d;")
    lines.append("xor r8d, r8d;")
    chunk2 = asm("".join(lines))

    # ---- chunk3: 恢复栈与寄存器
    p1, p2 = prctl_seq(), prctl_seq()
    chunk3 = asm(
        f"add rsp, {total_stack};"
        "pop r11; pop r10; pop r9; pop r8;"
        "pop rcx; pop rdx; pop rsi; pop rdi;"
    )

    body = chunk1 + p1 + chunk2 + p2 + chunk3
    tail = _tail_bytes(vaddr, len(body), entry_jmp_to)
    return _check_forbidden(body + tail)


def _tail_bytes(vaddr: int, body_len: int, entry_jmp_to: int | None) -> bytes:
    """stub 收尾：ret（trampoline 调用方）或 jmp rel32（启动期劫持安装）。"""
    if entry_jmp_to is None:
        return b"\xc3"
    disp = entry_jmp_to - (vaddr + body_len + 5)
    if not -(1 << 31) <= disp < (1 << 31):
        raise ValueError(
            f"entry jmp 距离超出 rel32: 0x{vaddr + body_len:x} -> 0x{entry_jmp_to:x}")
    return b"\xe9" + struct.pack("<i", disp)
