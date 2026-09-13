"""MistyFix 修复策略层：在 Patcher/ELFBinary 之上实现四类合规修复。

原则：等长替换、code cave 注入、真修复替代 NOP、改数据不改控制流。
所有策略函数都不抛异常——失败时返回 ``PatchPlan(applied=False)`` 并在
``description`` 里说明原因。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from mistyfix.elf_utils import ELFBinary, Cave
from mistyfix.patcher import Patcher, PatchError

__all__ = [
    "PatchPlan",
    "fix_read_length",
    "true_fix_free",
    "dynstr_rename",
    "fix_int_compare",
]

SUPPORTED_ARCHES = ("amd64", "i386")

# ---------------------------------------------------------------------------
# 常用符号改名预设：危险函数 -> 等长/更短的无害函数（.dynstr 原地改写）
# ---------------------------------------------------------------------------
#: key -> (原符号, 新符号, 一句话说明)。全部满足 len(new) <= len(old)。
#: 语义：动态链接器会把对原函数的调用绑定到新函数——正常业务流程会被
#: 改变（这是改数据修复的代价），但漏洞利用路径被掐断。
RENAME_PRESETS: dict[str, tuple[str, str, str]] = {
    "system2printf": ("system", "printf", "命令执行变打印，经典通杀 system 漏洞"),
    "system2strlen": ("system", "strlen", "命令执行变取长度（返回值近似可用）"),
    "free2atoi": ("free", "atoi", "释放变整数解析（默认方案）"),
    "gets2atoi": ("gets", "atoi", "停止读入，解析旧缓冲区内容"),
    "gets2puts": ("gets", "puts", "读入变打印，不再写入缓冲区"),
    "scanf2puts": ("scanf", "puts", "停止读入，格式串原样打印"),
    "strcpy2strlen": ("strcpy", "strlen", "停止拷贝，消除溢出源"),
    "strcat2strlen": ("strcat", "strlen", "停止拼接，消除溢出源"),
    "execve2printf": ("execve", "printf", "停止执行外部程序"),
    "popen2fopen": ("popen", "fopen", "命令执行变文件打开（等长且返回同为 FILE*）"),
}


def rename_preset_by_symbol(old: str) -> tuple[str, str] | None:
    """按原符号名返回推荐预设 (old, new)；无匹配返回 None。"""
    for _key, (o, n, _desc) in RENAME_PRESETS.items():
        if o == old:
            return o, n
    return None


@dataclass
class PatchPlan:
    description: str
    changes: list[str] = field(default_factory=list)
    applied: bool = False


# ---------------------------------------------------------------------------
# 内部工具
# ---------------------------------------------------------------------------
def _fail(description: str, changes: list[str] | None = None) -> PatchPlan:
    return PatchPlan(description=description, changes=changes or [], applied=False)


def _check_arch(arch: str, strategy: str) -> PatchPlan | None:
    if arch not in SUPPORTED_ARCHES:
        return _fail(f"{strategy}: unsupported arch {arch!r} (only amd64/i386)")
    return None


def _parse_imm(token: str) -> int | None:
    """把 capstone 的立即数文本 ('0x10' / '16' / '-1') 解析成 int。"""
    token = token.strip()
    if not token:
        return None
    try:
        return int(token, 0)
    except ValueError:
        return None


def _splice_imm(raw: bytes, imm_off: int, width: int, value: int, signed_ok: bool) -> bytes | None:
    """等长替换 raw[imm_off:imm_off+width] 为 value（小端）。装不下返回 None。"""
    try:
        payload = value.to_bytes(width, "little", signed=False)
    except OverflowError:
        if not signed_ok:
            return None
        try:
            payload = value.to_bytes(width, "little", signed=True)
        except OverflowError:
            return None
    return raw[:imm_off] + payload + raw[imm_off + width :]


def _raw_insn(elf: ELFBinary, addr: int, length: int) -> bytes:
    off = elf.vaddr_to_offset(addr)
    return bytes(elf.data[off : off + length])


# ---------------------------------------------------------------------------
# 1) 修 read/recv/fgets 的长度参数（栈溢出真修复）
# ---------------------------------------------------------------------------
def _find_len_setter(patcher: Patcher, call_vaddr: int) -> tuple[int, str, int, int] | None:
    """从 call_vaddr 向前最多 10 条指令，找设置长度参数的指令。

    返回 (addr, text, insn_length, old_imm)，找不到返回 None。
    amd64: 第三条参数 -> 'mov edx, imm' / 'mov rdx, imm'
    i386 : 参数从右往左 push -> 紧邻 call 之前的第一个 'push imm' 即长度参数
    """
    arch = patcher.elf.arch
    start = max(0, call_vaddr - 64)
    # 定长回退起点可能落在指令中间导致 capstone 解码失败/错位；
    # 逐字节微调起点，直到解码流末尾指令恰好结束于 call_vaddr（即与真实边界对齐）
    insns: list[tuple[int, str, int]] = []  # (addr, text, length)
    for nudge in range(16):
        cand = [
            i for i in patcher._disasm_insns(start + nudge, call_vaddr - start - nudge)
            if i.address < call_vaddr
        ]
        if cand and cand[-1].address + cand[-1].size == call_vaddr:
            insns = [
                (i.address, i.mnemonic if not i.op_str else f"{i.mnemonic} {i.op_str}", i.size)
                for i in cand
            ]
            break
    insns = insns[-10:]
    if not insns:
        return None
    for i in range(len(insns) - 1, -1, -1):
        addr, text, length = insns[i]
        if length <= 0:
            continue
        low = text.lower()
        if arch == "amd64":
            if low.startswith("mov edx,") or low.startswith("mov rdx,"):
                imm = _parse_imm(low.split(",", 1)[1])
                if imm is not None:
                    return addr, text, length, imm
        else:  # i386
            if low.startswith("push "):
                imm = _parse_imm(low[len("push ") :])
                if imm is not None:
                    return addr, text, length, imm
    return None


def _rewrite_len_insn_amd64(raw: bytes, new_len: int) -> bytes | None:
    """等长改写 mov edx/rdx, imm 的立即数。"""
    if len(raw) >= 5 and raw[0] == 0xBA:  # mov edx, imm32
        return _splice_imm(raw, 1, 4, new_len, signed_ok=False)
    if len(raw) >= 2 and 0x48 <= raw[0] <= 0x4F:  # REX.W 前缀 -> rdx
        if raw[1] == 0xBA and len(raw) >= 10:  # mov rdx, imm64
            return _splice_imm(raw, 2, 8, new_len, signed_ok=False)
        if raw[1] == 0xC7 and len(raw) >= 7 and raw[2] == 0xC2:  # mov rdx, imm32 (sign-extended)
            return _splice_imm(raw, 3, 4, new_len, signed_ok=True)
    if len(raw) >= 6 and raw[0] == 0xC7 and raw[1] == 0xC2:  # mov edx, imm32 (C7 /0)
        return _splice_imm(raw, 2, 4, new_len, signed_ok=False)
    return None


def _rewrite_push_imm(raw: bytes, new_len: int) -> bytes | None:
    """等长改写 push imm（i386 传参）。"""
    if raw[0] == 0x6A and len(raw) == 2:  # push imm8（符号扩展）
        return _splice_imm(raw, 1, 1, new_len, signed_ok=True)
    if raw[0] == 0x68 and len(raw) == 5:  # push imm32
        return _splice_imm(raw, 1, 4, new_len, signed_ok=False)
    return None


def fix_read_length(patcher: Patcher, call_vaddr: int, new_len: int) -> PatchPlan:
    """把 call read/recv/fgets 之前设置长度参数的立即数等长改为 new_len。"""
    if (bad := _check_arch(patcher.elf.arch, "fix_read_length")) is not None:
        return bad
    if not 0 <= new_len <= 0xFFFFFFFFFFFFFFFF:
        return _fail(f"fix_read_length: new_len {new_len} out of range")

    try:
        found = _find_len_setter(patcher, call_vaddr)
        if found is None:
            kind = "mov edx/rdx, imm" if patcher.elf.arch == "amd64" else "push imm"
            return _fail(
                f"fix_read_length: no length-setting instruction ({kind}) found "
                f"within 10 instructions before 0x{call_vaddr:x}"
            )
        addr, text, length, old_imm = found
        raw = _raw_insn(patcher.elf, addr, length)
        if patcher.elf.arch == "amd64":
            new_raw = _rewrite_len_insn_amd64(raw, new_len)
        else:
            new_raw = _rewrite_push_imm(raw, new_len)
        if new_raw is None:
            return _fail(
                f"fix_read_length: cannot fit new_len {new_len:#x} into the immediate "
                f"of {text!r} at 0x{addr:x} ({raw.hex()}); equal-length replacement impossible"
            )
        patcher.patch_bytes(addr, new_raw)  # 等长替换，require_equal=True
    except Exception as e:  # noqa: BLE001 - 策略层不抛异常
        return _fail(f"fix_read_length: {type(e).__name__}: {e}")

    return PatchPlan(
        description=(
            f"shrink read length at 0x{addr:x}: {text!r} -> imm {new_len:#x} "
            f"(equal-length patch before call at 0x{call_vaddr:x})"
        ),
        changes=[
            f"0x{addr:x}: {raw.hex()} -> {new_raw.hex()} (imm {old_imm:#x} -> {new_len:#x})",
            "only the immediate is rewritten; instruction length and control flow unchanged",
        ],
        applied=True,
    )


# ---------------------------------------------------------------------------
# 2) call free 真修复：trampoline 到 cave，正常调用 free，可选置空指针防 UAF
# ---------------------------------------------------------------------------
def _build_free_stub(patcher: Patcher, free_plt: int, ptr_vaddr: int | None,
                     stub_vaddr: int = 0, pie: bool = False) -> bytes:
    arch = patcher.elf.arch
    lines: list[str] = []
    if arch == "amd64":
        # 偶数个 push 保持 ABI 栈对齐：hook 点（原 call 处）rsp % 16 == 0，
        # 4 次 push 后仍为 0，call 后 free 入口看到 rsp % 16 == 8（ABI 要求）。
        # 若用 3 次 push，首次 PLT 惰性绑定时 _dl_runtime_resolve 的 movaps 会 segfault。
        lines += ["push rax", "push rcx", "push rdx", "push rdi"]
        if pie:
            # PIE 下运行时基址未知，绝对 call 不可用；直接 rel32 call free@plt，
            # 以 stub 落点地址（cave vaddr）为基汇编，加载后平移关系不变。
            lines.append(f"call {free_plt:#x}")
        else:
            lines.append(f"mov rax, {free_plt:#x}")  # 绝对地址，stub 位置无关
            lines.append("call rax")
        if ptr_vaddr is not None:
            if pie:
                # PIE 置空同样可行：keystone 以 stub 落点为基汇编 [绝对地址] 时
                # 自动编码为 RIP 相对寻址，cave→.data 的差值随 ASLR 平移不变
                lines.append(f"mov qword ptr [{ptr_vaddr:#x}], 0")
            else:
                # 非 PIE 走寄存器绝对寻址（keystone vaddr=0 时 RIP 相对基址错误）
                lines.append(f"mov rax, {ptr_vaddr:#x}")
                lines.append("mov qword ptr [rax], 0")
        lines += ["pop rdi", "pop rdx", "pop rcx", "pop rax"]
    else:  # i386
        lines += ["push eax", "push ecx", "push edx", "push edi"]
        lines.append(f"mov eax, {free_plt:#x}")
        lines.append("call eax")
        if ptr_vaddr is not None:
            lines.append(f"mov dword ptr [{ptr_vaddr:#x}], 0")
        lines += ["pop edi", "pop edx", "pop ecx", "pop eax"]
    return patcher.asm("; ".join(lines), vaddr=stub_vaddr)


def true_fix_free(patcher: Patcher, call_vaddr: int, ptr_vaddr: int | None = None) -> PatchPlan:
    """把 call_vaddr 处的 call free@plt 通过 trampoline 改为 cave 里的真修复 stub。

    stub：保存现场 -> 正常 call free@plt -> 可选将指针变量置空（防 UAF）->
    恢复现场 -> 执行被覆盖的原指令 -> jmp 回去。绝不 NOP 掉 call free。

    PIE（ET_DYN）二进制：call 与指针置空均以 cave 落点为基汇编成 RIP 相对
    寻址（keystone 在给定 addr 时对 [绝对地址] 自动生成 rel32 RIP 相对编码），
    偏移随加载基址平移不变，PIE 下同样完整可用。
    """
    if (bad := _check_arch(patcher.elf.arch, "true_fix_free")) is not None:
        return bad
    pie = patcher.elf.is_pie

    try:
        free_plt = patcher.elf.plt_stub_addr("free")
        if free_plt is None:
            return _fail("true_fix_free: cannot locate free@plt (plt_stub_addr returned None)")

        # 确认 hook 点确实是 call 指令并测出指令长度（E8 为 5，FF /2 可能更长）
        insns = patcher.disasm(call_vaddr, 15)
        if not insns or not insns[0][1].lower().startswith("call"):
            got = insns[0][1] if insns else "<nothing>"
            return _fail(f"true_fix_free: expected a call at 0x{call_vaddr:x}, found {got!r}")

        # stub 自己完成 call free，原 call 指令（E8 rel32，位置相关）不能照搬重放。
        # rel32 call / RIP 相对置空都以 stub 落点为基汇编，先按探针选落点再生成
        # 最终 stub（指令定长，两阶段长度一致）。
        probe = _build_free_stub(patcher, free_plt, ptr_vaddr, stub_vaddr=0, pie=pie)
        from mistyfix.injector import apply_stub_space, plan_stub_space
        space = plan_stub_space(patcher.elf, len(probe) + 5)  # +5: 跳回 jmp

        if space.method == "cave":
            stub = _build_free_stub(patcher, free_plt, ptr_vaddr,
                                    stub_vaddr=space.stub_vaddr, pie=pie)
            cave_vaddr = patcher.build_trampoline(
                call_vaddr, stub, stolen=5, resteal=False,
                cave=Cave(section=space.method, file_offset=space.stub_file_off,
                          vaddr=space.stub_vaddr, size=space.stub_len))
            used_tail = False
        else:
            # 无 cave 二进制：段尾 padding 注入（扩容段头 16 字节）+ 手工 trampoline
            stolen = patcher._boundary_size(call_vaddr, 5)
            stub = _build_free_stub(patcher, free_plt, ptr_vaddr,
                                    stub_vaddr=space.stub_vaddr, pie=pie)
            back_src = space.stub_vaddr + len(stub)
            payload = stub + patcher.jmp_opcode(back_src, call_vaddr + stolen)
            apply_stub_space(patcher, space, payload)
            patcher.patch_bytes(call_vaddr,
                                patcher.jmp_opcode(call_vaddr, space.stub_vaddr))
            cave_vaddr = space.stub_vaddr
            used_tail = True
    except Exception as e:  # noqa: BLE001
        return _fail(f"true_fix_free: {type(e).__name__}: {e}")

    call_style = "rel32 call (PIE, base = stub)" if pie else "abs call via rax"
    changes = [
        f"hook 0x{call_vaddr:x}: call free@plt -> jmp stub 0x{cave_vaddr:x} ({stolen if used_tail else 5} bytes hooked)",
        f"{'tail padding' if used_tail else 'cave'} 0x{cave_vaddr:x}: save rax/rcx/rdx/rdi "
        f"(keeps 16-byte stack alignment) -> {call_style} free@plt (0x{free_plt:x})"
        + (f" -> null pointer at 0x{ptr_vaddr:x} (UAF fix)" if ptr_vaddr is not None else "")
        + " -> restore -> jmp back (original call instruction replaced by the stub, not re-executed)",
        "free is genuinely called (no NOP); file size unchanged"
        + ("; injected into tail padding with p_filesz/p_memsz grown (16 header bytes changed, "
           "no cave was available)" if used_tail
           else "; injected into existing code cave, section table/file size unchanged"),
    ]
    if ptr_vaddr is not None:
        changes.append(
            "note: pointer nulling uses "
            + ("RIP-relative addressing relative to the cave (PIE-safe)" if pie
               else "absolute addressing (non-PIE fixed address)"))
    return PatchPlan(
        description=(
            f"true-fix free at 0x{call_vaddr:x} via trampoline to "
            f"{'tail-padding stub' if used_tail else 'cave stub'} 0x{cave_vaddr:x}"
            + (f", nulls pointer at 0x{ptr_vaddr:x}" if ptr_vaddr is not None else "")
            + (" [PIE]" if pie else "")
        ),
        changes=changes,
        applied=True,
    )


# ---------------------------------------------------------------------------
# 3) .dynstr 改名（free -> atoi 等），改数据不改 GOT
# ---------------------------------------------------------------------------
def dynstr_rename(elf: ELFBinary, old: str = "free", new: str = "atoi") -> PatchPlan:
    """把 .dynstr 中 old 的符号名原地替换为 new（长度不够则失败），剩余填 0。"""
    if (bad := _check_arch(elf.arch, "dynstr_rename")) is not None:
        return bad
    if len(new) > len(old):
        return _fail(
            f"dynstr_rename: new name {new!r} ({len(new)} bytes) is longer than "
            f"old name {old!r} ({len(old)} bytes); in-place replacement impossible"
        )
    if not new:
        return _fail("dynstr_rename: new name must not be empty")

    try:
        off = elf.dynstr_offset(old)
        if off is None:
            return _fail(f"dynstr_rename: {old!r} not found in .dynstr")
        current = bytes(elf.data[off : off + len(old)])
        if current != old.encode():
            return _fail(
                f"dynstr_rename: bytes at .dynstr+0x{off:x} are {current!r}, expected {old!r}"
            )
        elf.data[off : off + len(old)] = new.encode() + b"\x00" * (len(old) - len(new))
    except Exception as e:  # noqa: BLE001
        return _fail(f"dynstr_rename: {type(e).__name__}: {e}")

    pad = len(old) - len(new)
    return PatchPlan(
        description=f"rename dynamic symbol {old!r} -> {new!r} at .dynstr file offset 0x{off:x}",
        changes=[
            f".dynstr+0x{off:x}: {old!r} -> {new!r}"
            + (f" (+{pad} NUL padding bytes)" if pad else ""),
            "this edits .dynstr (string table data) only; GOT/.got.plt and relocations are untouched",
            f"effect: the dynamic linker now binds the former {old!r} slot to {new!r}",
        ],
        applied=True,
    )


# ---------------------------------------------------------------------------
# 4) 整数比较修复：等长替换 cmp reg, imm 的立即数（改数据不改条件跳转）
# ---------------------------------------------------------------------------
def _rewrite_cmp_imm(raw: bytes, new_imm: int) -> bytes | None:
    """等长改写 cmp reg, imm（ModRM mod=3, /7）的立即数。"""
    i = 0
    while i < len(raw) and (raw[i] in (0x66, 0x67) or 0x40 <= raw[i] <= 0x4F):
        i += 1  # 跳过操作数/地址大小前缀与 REX
    if i + 1 >= len(raw):
        return None
    op = raw[i]
    if op not in (0x80, 0x81, 0x83):
        return None
    modrm = raw[i + 1]
    if (modrm >> 6) != 3 or ((modrm >> 3) & 7) != 7:  # 仅接受 cmp reg, imm（寄存器直接寻址）
        return None
    if op == 0x81:
        width = 2 if 0x66 in raw[:i] else 4
        signed_ok = False
    else:  # 0x80 / 0x83：imm8（0x83 符号扩展）
        width = 1
        signed_ok = op == 0x83
    return _splice_imm(raw, len(raw) - width, width, new_imm, signed_ok)


def fix_int_compare(patcher: Patcher, cmp_vaddr: int, new_imm: int) -> PatchPlan:
    """把 cmp_vaddr 处 'cmp reg, imm' 的立即数等长替换为 new_imm。"""
    if (bad := _check_arch(patcher.elf.arch, "fix_int_compare")) is not None:
        return bad

    try:
        insns = patcher.disasm(cmp_vaddr, 15)
        if not insns:
            return _fail(f"fix_int_compare: cannot disassemble at 0x{cmp_vaddr:x}")
        text = insns[0][1]
        low = text.lower()
        if not low.startswith("cmp ") or "," not in low:
            return _fail(f"fix_int_compare: expected 'cmp reg, imm' at 0x{cmp_vaddr:x}, found {text!r}")
        imm_token = low.split(",", 1)[1].strip()
        old_imm = _parse_imm(imm_token)
        if old_imm is None:
            return _fail(
                f"fix_int_compare: operand {imm_token!r} of {text!r} is not an immediate; "
                "only 'cmp reg, imm' is supported"
            )
        length = (insns[1][0] - cmp_vaddr) if len(insns) > 1 else 7
        raw = _raw_insn(patcher.elf, cmp_vaddr, length)
        new_raw = _rewrite_cmp_imm(raw, new_imm)
        if new_raw is None:
            return _fail(
                f"fix_int_compare: cannot fit new_imm {new_imm:#x} into {text!r} "
                f"({raw.hex()}); equal-length replacement impossible"
            )
        patcher.patch_bytes(cmp_vaddr, new_raw)
    except Exception as e:  # noqa: BLE001
        return _fail(f"fix_int_compare: {type(e).__name__}: {e}")

    return PatchPlan(
        description=f"fix compare at 0x{cmp_vaddr:x}: {text!r} -> imm {new_imm:#x}",
        changes=[
            f"0x{cmp_vaddr:x}: {raw.hex()} -> {new_raw.hex()} (imm {old_imm:#x} -> {new_imm:#x})",
            "only the immediate is rewritten; the conditional jump and control flow are unchanged",
        ],
        applied=True,
    )
