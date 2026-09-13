"""ELF 解析与基础工具：LIEF 解析、cave 发现、地址换算、文件差异比对。

本模块严格遵守共享 API 契约（见项目说明），供其他模块调用。
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64


@dataclass
class Cave:
    section: str
    file_offset: int
    vaddr: int
    size: int


@dataclass
class SectionInfo:
    name: str
    vaddr: int
    size: int
    offset: int


class ELFError(Exception):
    """ELF 相关错误：文件不存在、不是 ELF、不支持的架构等。"""


class ELFBinary:
    def __init__(self, path: str):
        if not os.path.isfile(path):
            raise ELFError(f"file not found: {path}")
        try:
            self._binary = lief.parse(path)
        except Exception as exc:
            raise ELFError(f"failed to parse {path}: {exc}") from exc
        if self._binary is None or not isinstance(self._binary, lief.ELF.Binary):
            raise ELFError(f"not an ELF file: {path}")

        self.path: str = path
        with open(path, "rb") as f:
            self.data: bytearray = bytearray(f.read())

        # LIEF 1.0 起 machine_type 枚举为 lief.ELF.ARCH；旧版为 lief.ELF.Architecture
        _arch_enum = getattr(lief.ELF, "ARCH", None) or lief.ELF.Architecture
        machine = self._binary.header.machine_type
        if machine == _arch_enum.X86_64:
            self.arch: str = "amd64"
        elif machine == _arch_enum.I386:
            self.arch: str = "i386"
        else:
            raise ELFError(f"unsupported architecture: {machine} (only x86_64/i386 supported)")

        # PIE（ET_DYN）判定：LIEF 的 is_pie 不可用时退回 header.file_type
        try:
            self.is_pie: bool = bool(self._binary.is_pie)
        except Exception:
            _ft_enum = getattr(lief.ELF.Header, "FILE_TYPE", None)
            ft = self._binary.header.file_type
            self.is_pie = (_ft_enum is not None and ft == _ft_enum.DYN) or "DYN" in str(ft)

        # 段映射缓存：[(file_offset, vaddr, filesz, flags)] 与
        # 段表全量记录 [(phdr索引, off, vaddr, filesz, memsz, flags)]（injector 用）
        self._segments: list[tuple[int, int, int, int]] = []
        self.phdr_entries: list[tuple[int, int, int, int, int, int]] = []
        for i, seg in enumerate(self._binary.segments):
            if seg.type == lief.ELF.Segment.TYPE.LOAD:
                flags = int(seg.flags)
                self._segments.append(
                    (seg.file_offset, seg.virtual_address, seg.physical_size, flags))
                self.phdr_entries.append(
                    (i, seg.file_offset, seg.virtual_address,
                     seg.physical_size, seg.virtual_size, flags))

        # ELF 头中段表位置（injector 扩容 p_filesz/p_memsz 时需要）
        hdr = self._binary.header
        self.phoff: int = hdr.program_header_offset
        self.phentsize: int = 56 if self.arch == "amd64" else 32
        self.phnum: int = hdr.numberof_segments

    # ------------------------------------------------------------------
    # 地址换算
    # ------------------------------------------------------------------
    def vaddr_to_offset(self, vaddr: int) -> int:
        """虚拟地址 -> 文件偏移（基于 PT_LOAD 段映射）。找不到时抛 ELFError。"""
        for off, va, sz, _flags in self._segments:
            if va <= vaddr < va + sz:
                return off + (vaddr - va)
        raise ELFError(f"vaddr 0x{vaddr:x} is not mapped in any PT_LOAD segment")

    def offset_to_vaddr(self, off: int) -> int:
        """文件偏移 -> 虚拟地址。找不到时抛 ELFError。"""
        for foff, va, sz, _flags in self._segments:
            if foff <= off < foff + sz:
                return va + (off - foff)
        raise ELFError(f"file offset 0x{off:x} is not mapped in any PT_LOAD segment")

    # ------------------------------------------------------------------
    # 节信息
    # ------------------------------------------------------------------
    def sections(self) -> list[SectionInfo]:
        return [
            SectionInfo(
                name=s.name,
                vaddr=s.virtual_address,
                size=s.size,
                offset=s.offset,
            )
            for s in self._binary.sections
        ]

    def _get_section(self, name: str) -> lief.ELF.Section | None:
        for s in self._binary.sections:
            if s.name == name:
                return s
        return None

    def section_data(self, name: str) -> bytes:
        sec = self._get_section(name)
        if sec is None:
            raise ELFError(f"section not found: {name}")
        return bytes(sec.content)

    # ------------------------------------------------------------------
    # 合规检测相关的原始字节
    # ------------------------------------------------------------------
    def got_plt_bytes(self) -> bytes:
        return self.section_data(".got.plt")

    def entry_vaddr(self) -> int:
        return self._binary.entrypoint

    def start_bytes(self, size: int = 64) -> bytes:
        """读取 entrypoint 处的机器码。"""
        off = self.vaddr_to_offset(self.entry_vaddr())
        return bytes(self.data[off : off + size])

    # ------------------------------------------------------------------
    # code cave 发现
    # ------------------------------------------------------------------
    def caves(self, min_size: int = 32) -> list[Cave]:
        """在可执行 PT_LOAD 段的现有空隙中找 cave（连续 0x00 或 0x90）。

        优先返回位于 .eh_frame 节范围内的 cave，其余按段顺序排在后面。
        """
        # 可执行 LOAD 段的 (file_start, file_end)
        exec_ranges: list[tuple[int, int]] = []
        for seg in self._binary.segments:
            if seg.type != lief.ELF.Segment.TYPE.LOAD:
                continue
            if not seg.has(lief.ELF.Segment.FLAGS.X):
                continue
            start = seg.file_offset
            end = min(seg.file_offset + seg.physical_size, len(self.data))
            if end > start:
                exec_ranges.append((start, end))

        eh = self._get_section(".eh_frame")
        eh_range: tuple[int, int] | None = None
        if eh is not None and eh.size > 0:
            eh_range = (eh.offset, eh.offset + eh.size)

        result: list[Cave] = []
        for rstart, rend in exec_ranges:
            blob = bytes(self.data[rstart:rend])
            i = 0
            n = len(blob)
            while i < n:
                b = blob[i]
                if b != 0x00 and b != 0x90:
                    i += 1
                    continue
                j = i
                while j < n and blob[j] == b:
                    j += 1
                run = j - i
                if run >= min_size:
                    foff = rstart + i
                    try:
                        va = self.offset_to_vaddr(foff)
                    except ELFError:
                        i = j
                        continue
                    if eh_range is not None and eh_range[0] <= foff < eh_range[1]:
                        sec_name = ".eh_frame"
                    else:
                        sec_name = self._section_name_for_offset(foff) or "<segment>"
                    result.append(Cave(section=sec_name, file_offset=foff, vaddr=va, size=run))
                i = j

        # .eh_frame 优先
        result.sort(key=lambda c: (0 if c.section == ".eh_frame" else 1, c.file_offset))
        return result

    def _section_name_for_offset(self, foff: int) -> str | None:
        for s in self._binary.sections:
            if s.size > 0 and s.offset <= foff < s.offset + s.size:
                return s.name
        return None

    # ------------------------------------------------------------------
    # 符号 / PLT / call 定位
    # ------------------------------------------------------------------
    def dynstr_offset(self, func_name: str) -> int | None:
        """函数名在 .dynstr 中的文件偏移（精确匹配，避免 'free' 命中 'freopen'）。"""
        sec = self._get_section(".dynstr")
        if sec is None:
            return None
        data = bytes(sec.content)
        needle = func_name.encode()
        base = sec.offset
        start = 0
        while True:
            idx = data.find(needle, start)
            if idx < 0:
                return None
            before_ok = idx == 0 or data[idx - 1] == 0
            after_idx = idx + len(needle)
            after_ok = after_idx < len(data) and data[after_idx] == 0
            if before_ok and after_ok:
                return base + idx
            start = idx + 1

    def plt_stub_addr(self, func_name: str) -> int | None:
        """func@plt 的 vaddr。"""
        sec = self._get_section(".plt")
        if sec is None:
            return None
        try:
            relocations = list(self._binary.pltgot_relocations)
        except Exception:
            return None
        names: list[str] = []
        for r in relocations:
            if r.has_symbol and r.symbol:
                names.append(r.symbol.name)
            else:
                names.append("")
        try:
            idx = names.index(func_name)
        except ValueError:
            return None
        if self.arch == "amd64":
            # .plt: 1 个头 stub (16B) + 每项 16B
            return sec.virtual_address + 16 * (idx + 1)
        else:
            # i386: .plt 头 16B + 每项 16B（标准布局）
            return sec.virtual_address + 16 * (idx + 1)

    def find_calls_to(self, func_name: str) -> list[int]:
        """反汇编所有可执行节，找 `call func@plt` 指令的 vaddr。"""
        target = self.plt_stub_addr(func_name)
        if target is None:
            return []
        mode = CS_MODE_64 if self.arch == "amd64" else CS_MODE_32
        md = Cs(CS_ARCH_X86, mode)
        hits: list[int] = []
        for sec in self._binary.sections:
            if not (sec.flags & int(lief.ELF.Section.FLAGS.EXECINSTR)):
                continue
            content = bytes(sec.content)
            base = sec.virtual_address
            for insn in md.disasm(content, base):
                if insn.mnemonic == "call" and insn.op_str:
                    # 直接 call：操作数为绝对目标地址
                    try:
                        dst = int(insn.op_str, 0)
                    except ValueError:
                        continue
                    if dst == target:
                        hits.append(insn.address)
        return hits

    # ------------------------------------------------------------------
    # 启动期安装（injector）相关的查询
    # ------------------------------------------------------------------
    def init_array_first_entry(self) -> tuple[int, int] | None:
        """.init_array 第一项的 (文件偏移, 当前值)；无该节时返回 None。"""
        sec = self._get_section(".init_array")
        if sec is None or sec.size < 8:
            return None
        width = 8 if self.arch == "amd64" else 4
        off = sec.offset
        if off + width > len(self.data):
            return None
        return off, int.from_bytes(self.data[off : off + width], "little")

    def rela_relative_addends(self) -> dict[int, int]:
        """手工解析 .rela.dyn 中 R_X86_64_RELATIVE / R_386_RELATIVE（type=8）。

        返回 {r_offset: addend}。PIE 下 .init_array 条目通常带 RELATIVE
        重定位，加载器会用 addend 覆盖文件值——改文件里的 init_array 无效。
        """
        sec = self._get_section(".rela.dyn")
        if sec is None or sec.size == 0:
            return {}
        data = bytes(self.data[sec.offset : sec.offset + sec.size])
        out: dict[int, int] = {}
        if self.arch == "amd64":
            step, fmt = 24, "<QQq"
        else:
            step, fmt = 12, "<IIi"
        for i in range(len(data) // step):
            r_offset, r_info, addend = struct.unpack_from(fmt, data, i * step)
            if (r_info & 0xFFFFFFFF) == 8:  # R_*_RELATIVE
                out[r_offset] = addend
        return out

    def exec_load_segments(self) -> list[tuple[int, int, int, int, int, int]]:
        """可执行 PT_LOAD 段：[(phdr索引, off, vaddr, filesz, memsz, flags)]，按文件偏移排序。"""
        segs = [s for s in self.phdr_entries if s[5] & 0x1]  # PF_X
        return sorted(segs, key=lambda s: s[1])

    def load_segments_sorted(self) -> list[tuple[int, int, int, int, int, int]]:
        """全部 PT_LOAD 段（同 exec_load_segments 结构），按文件偏移排序。"""
        return sorted(self.phdr_entries, key=lambda s: s[1])

    def entry_header_offset(self) -> int:
        """e_entry 在 ELF 头中的文件偏移（amd64/32 位均为 24）。"""
        return 24

    # ------------------------------------------------------------------
    def save(self, out_path: str) -> None:
        with open(out_path, "wb") as f:
            f.write(self.data)


def diff_files(a: str, b: str) -> dict:
    """逐字节比对两个文件，返回差异统计，相邻差异合并为 range。"""
    for p in (a, b):
        if not os.path.isfile(p):
            raise ELFError(f"file not found: {p}")
    with open(a, "rb") as fa, open(b, "rb") as fb:
        da = fa.read()
        db = fb.read()

    size_equal = len(da) == len(db)
    n = min(len(da), len(db))
    changed: list[int] = [i for i in range(n) if da[i] != db[i]]
    # 长度不同部分也计入差异（公共前缀之外的字节视为 changed）
    if len(da) != len(db):
        changed.extend(range(n, max(len(da), len(db))))

    ranges: list[tuple[int, int]] = []
    for off in changed:
        if ranges and off == ranges[-1][0] + ranges[-1][1]:
            prev_off, prev_len = ranges[-1]
            ranges[-1] = (prev_off, prev_len + 1)
        else:
            ranges.append((off, 1))

    return {
        "size_equal": size_equal,
        "changed_bytes": len(changed),
        "changed_ranges": ranges,
    }
