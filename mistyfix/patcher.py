"""Low-level patch primitives for MistyFix.

All writes go through :class:`~mistyfix.elf_utils.ELFBinary` (``elf.data``
mutated in place via ``vaddr_to_offset``); every mutation is recorded in
``self.log`` as a human-readable entry.
"""

from __future__ import annotations

import struct

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
from keystone import KS_ARCH_X86, KS_MODE_32, KS_MODE_64, Ks, KsError

from mistyfix.elf_utils import Cave, ELFBinary

__all__ = ["PatchError", "Patcher"]


class PatchError(Exception):
    """Raised when a patch cannot be applied safely."""


class Patcher:
    def __init__(self, elf: ELFBinary):
        self.elf: ELFBinary = elf
        self.log: list[str] = []

    # ------------------------------------------------------------------ tools

    def _ks_mode(self) -> int:
        return KS_MODE_64 if self.elf.arch == "amd64" else KS_MODE_32

    def _cs_mode(self) -> int:
        return CS_MODE_64 if self.elf.arch == "amd64" else CS_MODE_32

    def asm(self, code: str, vaddr: int = 0) -> bytes:
        """Assemble ``code`` with keystone for the binary's architecture."""
        ks = Ks(KS_ARCH_X86, self._ks_mode())
        try:
            encoding, _ = ks.asm(code, addr=vaddr)
        except KsError as e:
            raise PatchError(f"keystone failed to assemble {code!r}: {e}") from e
        if encoding is None:
            raise PatchError(f"keystone returned no encoding for {code!r}")
        return bytes(encoding)

    def _disasm_insns(self, vaddr: int, size: int):
        off = self.elf.vaddr_to_offset(vaddr)
        code = bytes(self.elf.data[off : off + size])
        md = Cs(CS_ARCH_X86, self._cs_mode())
        return list(md.disasm(code, vaddr))

    def disasm(self, vaddr: int, size: int) -> list[tuple[int, str]]:
        """Disassemble ``size`` bytes at ``vaddr`` -> [(addr, 'mov edx, 0x10'), ...]."""
        out: list[tuple[int, str]] = []
        for insn in self._disasm_insns(vaddr, size):
            text = insn.mnemonic if not insn.op_str else f"{insn.mnemonic} {insn.op_str}"
            out.append((insn.address, text))
        return out

    # ----------------------------------------------------------------- writes

    def _write(self, vaddr: int, data: bytes) -> None:
        off = self.elf.vaddr_to_offset(vaddr)
        self.elf.data[off : off + len(data)] = data

    def write_at_vaddr(self, vaddr: int, data: bytes) -> None:
        """Raw write (for code caves); no instruction-boundary checks."""
        self._write(vaddr, data)
        self.log.append(
            f"write {len(data)} bytes at 0x{vaddr:x} (raw): {data[:16].hex()}"
            + ("..." if len(data) > 16 else "")
        )

    def patch_bytes(self, vaddr: int, data: bytes, *, require_equal: bool = True) -> None:
        """Patch code at ``vaddr``.

        With ``require_equal=True`` (default) the patch must not extend past
        the whole instructions it overlaps: ``len(data)`` must be <= the
        total length of the complete instructions covering it, and the
        leftover bytes are filled with 0x90 NOPs. Otherwise PatchError.
        """
        if require_equal:
            insns = self._disasm_insns(vaddr, len(data) + 15)
            total = 0
            for insn in insns:
                total += insn.size
                if total >= len(data):
                    break
            if total < len(data):
                raise PatchError(
                    f"patch of {len(data)} bytes at 0x{vaddr:x} exceeds the "
                    f"disassemblable instruction region ({total} bytes)"
                )
            payload = data + b"\x90" * (total - len(data))
            self._write(vaddr, payload)
            self.log.append(
                f"patch {len(data)} bytes at 0x{vaddr:x} "
                f"(covers {total} bytes of instructions, "
                f"{total - len(data)} NOP padding): {data.hex()}"
            )
        else:
            self._write(vaddr, data)
            self.log.append(f"patch {len(data)} bytes at 0x{vaddr:x} (unchecked): {data.hex()}")

    # ------------------------------------------------------------ trampoline

    def _check_no_rip_relative(self, code: bytes, vaddr: int) -> None:
        """搬运的 stolen 字节中不得含 RIP 相对内存操作（照搬会错位）。

        移植自前身项目 AWD-Tools-For-PWN 的 elf-patcher 安全检查。
        """
        from capstone.x86_const import X86_OP_MEM, X86_REG_RIP

        md = Cs(CS_ARCH_X86, self._cs_mode())
        md.detail = True
        consumed = 0
        for insn in md.disasm(code, vaddr):
            consumed += insn.size
            for op in insn.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    raise PatchError(
                        f"stolen bytes contain a RIP-relative operand that cannot be "
                        f"relocated verbatim: 0x{insn.address:x} "
                        f"{insn.mnemonic} {insn.op_str}"
                    )
            if consumed >= len(code):
                break

    def jmp_opcode(self, src: int, dst: int) -> bytes:
        """E9 rel32 near jump from ``src`` to ``dst`` (5 bytes)."""
        rel = dst - src - 5
        if not -(1 << 31) <= rel < (1 << 31):
            raise PatchError(
                f"jmp 0x{src:x} -> 0x{dst:x} out of rel32 range (rel={rel:#x})"
            )
        return b"\xe9" + struct.pack("<i", rel)

    def _boundary_size(self, vaddr: int, minimum: int) -> int:
        """Smallest instruction-aligned size >= ``minimum`` starting at ``vaddr``."""
        insns = self._disasm_insns(vaddr, minimum + 15)
        total = 0
        for insn in insns:
            total += insn.size
            if total >= minimum:
                return total
        raise PatchError(
            f"cannot find instruction boundary >= {minimum} bytes at 0x{vaddr:x} "
            f"(disassembled {total} bytes)"
        )

    def build_trampoline(
        self, hook_vaddr: int, stub: bytes, *, stolen: int = 5, resteal: bool = True,
        cave: Cave | None = None,
    ) -> int:
        """Relocate ``stolen`` bytes at ``hook_vaddr`` into a cave behind ``stub``.

        ``stolen`` is rounded up to the next instruction boundary (and to at
        least 5 bytes so the hook jmp fits). With ``resteal=True`` the cave
        receives ``stub + stolen original bytes + jmp back to
        hook_vaddr + stolen``; with ``resteal=False`` the stolen bytes are not
        re-executed (use this when ``stub`` fully replaces the hooked
        instruction's effect, e.g. a hooked ``call``) and the cave receives
        ``stub + jmp back`` only. ``hook_vaddr`` is overwritten with
        ``jmp cave`` plus NOP padding. Returns the cave vaddr.

        ``cave`` 可显式指定（跳过自动搜索），供需要先知道落点地址再汇编
        stub 的策略（如 PIE 下的 RIP 相对 call）使用。

        Note: with ``resteal=True`` the stolen bytes are copied verbatim, so
        RIP-relative instructions (call/jmp/[rip+x]) among them would break;
        this is now detected and rejected (ported from the predecessor
        project's trampoline patcher safety check).
        """
        stolen = self._boundary_size(hook_vaddr, max(stolen, 5))
        restolen = stolen if resteal else 0
        needed = len(stub) + restolen + 5

        if cave is None:
            for c in self.elf.caves(min_size=needed):
                if c.size >= needed:
                    cave = c
                    break
        elif cave.size < needed:
            raise PatchError(
                f"provided cave at 0x{cave.vaddr:x} is too small: "
                f"{cave.size} < {needed} bytes"
            )
        if cave is None:
            raise PatchError(
                f"no code cave large enough for trampoline: need {needed} bytes "
                f"(stub={len(stub)}, stolen={restolen}, jmp=5)"
            )

        orig = b""
        if resteal:
            off = self.elf.vaddr_to_offset(hook_vaddr)
            orig = bytes(self.elf.data[off : off + stolen])
            self._check_no_rip_relative(orig, hook_vaddr)

        back_src = cave.vaddr + len(stub) + restolen
        payload = stub + orig + self.jmp_opcode(back_src, hook_vaddr + stolen)
        self.write_at_vaddr(cave.vaddr, payload)

        hook = self.jmp_opcode(hook_vaddr, cave.vaddr)
        hook_payload = hook + b"\x90" * (stolen - len(hook))
        self._write(hook_vaddr, hook_payload)
        self.log.append(
            f"trampoline: hook 0x{hook_vaddr:x} -> cave 0x{cave.vaddr:x} "
            f"({cave.section}), stub={len(stub)} bytes, stolen={stolen} bytes"
            f"{'' if resteal else ' (not re-executed)'}, "
            f"returns to 0x{hook_vaddr + stolen:x}"
        )
        return cave.vaddr

    # ------------------------------------------------------------------- save

    def save(self, out_path: str) -> None:
        self.elf.save(out_path)
        self.log.append(f"saved patched binary to {out_path}")
