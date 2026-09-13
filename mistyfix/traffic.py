#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ELF 流量镜像（traffic mirroring）：hook read/write@plt 把交互流量镜像到收集端。

移植自前身项目 AWD-Tools-For-PWN 的 6.Traffic_Reply.py，保持其自包含设计
（纯 stdlib struct 解析 ELF，不依赖 lief/keystone）。两种模式：

- ``patch``：改写 read/write/gets/printf@plt 指向注入的 wrapper，
  wrapper 先执行原调用、再用裸 syscall(socket/connect/write/close) 把
  数据帧发送给收集端；安装方式沿用 .init_array[0]（非 PIE）/ e_entry
  （PIE）劫持 + 段尾 padding 注入（必要时扩容 p_filesz/p_memsz）。
- ``receiver``：本地 TCP 接收端，按帧协议解析并写日志（text+hex 预览）。

定位与边界：传统 AWD 赛制的流量捕获/取证工具。改动了 PLT 与入口，
**不能**作为 AWDP fix 产物提交（合规检测会命中）。
"""

from __future__ import annotations

import argparse
import datetime
import socket
import struct
import sys
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1

ET_EXEC = 2
ET_DYN = 3
EM_X86_64 = 0x3E

PT_LOAD = 1
PF_X = 0x1
SHT_INIT_ARRAY = 14
SHT_RELA = 4

SYS_READ_X86_64 = 0
SYS_WRITE_X86_64 = 1
SYS_CLOSE_X86_64 = 3
SYS_SOCKET_X86_64 = 41
SYS_CONNECT_X86_64 = 42

FRAME_MAGIC = 0x474C5254  # 'TRLG' little-endian in memory.
FRAME_HEADER_STRUCT = struct.Struct("<IBBHiI")
FRAME_HEADER_SIZE = FRAME_HEADER_STRUCT.size

HOOK_WRAPPER_LABEL: Dict[str, str] = {
    "read": "read_wrapper",
    "write": "write_wrapper",
    "gets": "gets_wrapper",
    "printf": "printf_wrapper",
}

ORIG_CALL_REQUIRED = {"gets", "printf"}


@dataclass
class ElfHeader:
    endian: str
    e_type: int
    e_machine: int
    e_entry: int
    e_phoff: int
    e_shoff: int
    e_phentsize: int
    e_phnum: int
    e_shentsize: int
    e_shnum: int
    e_shstrndx: int


@dataclass
class ProgramHeader:
    index: int
    offset_in_file: int
    p_type: int
    p_flags: int
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_align: int


@dataclass
class SectionHeader:
    index: int
    sh_name: int
    sh_type: int
    sh_flags: int
    sh_addr: int
    sh_offset: int
    sh_size: int
    sh_link: int
    sh_info: int
    sh_addralign: int
    sh_entsize: int


@dataclass
class DynSymbol:
    index: int
    name: str


@dataclass
class RelaEntry:
    index: int
    r_offset: int
    sym_index: int
    r_type: int
    addend: int


@dataclass
class HookSite:
    name: str
    plt_vaddr: int
    plt_off: int
    plt_entry_size: int
    relocation_index: int
    orig_call_vaddr: Optional[int]


@dataclass
class PatchPlan:
    phdr: ProgramHeader
    inject_off: int
    inject_vaddr: int
    inject_len: int
    hook_off: int
    hook_original_value: int
    hook_label: str
    new_filesz: int
    new_memsz: int
    need_update_phdr_sizes: bool


class PatchError(Exception):
    pass


class CodeBuilder:
    def __init__(self) -> None:
        self.buf = bytearray()
        self.labels: Dict[str, int] = {}
        self._label_fixups: List[Tuple[int, int, str]] = []
        self._abs_fixups: List[Tuple[int, int, int]] = []

    def position(self) -> int:
        return len(self.buf)

    def emit(self, data: bytes) -> None:
        self.buf.extend(data)

    def mark(self, label: str) -> None:
        if label in self.labels:
            raise PatchError(f"duplicate label: {label}")
        self.labels[label] = self.position()

    def emit_rel32_label(self, opcode_prefix: bytes, label: str) -> None:
        self.emit(opcode_prefix)
        disp_off = self.position()
        self.emit(b"\x00\x00\x00\x00")
        base_off = self.position()
        self._label_fixups.append((disp_off, base_off, label))

    def emit_rel32_abs(self, opcode_prefix: bytes, target_vaddr: int) -> None:
        self.emit(opcode_prefix)
        disp_off = self.position()
        self.emit(b"\x00\x00\x00\x00")
        base_off = self.position()
        self._abs_fixups.append((disp_off, base_off, target_vaddr))

    def emit_disp32_to_label(self, opcode_prefix: bytes, label: str, suffix: bytes = b"") -> None:
        self.emit(opcode_prefix)
        disp_off = self.position()
        self.emit(b"\x00\x00\x00\x00")
        self.emit(suffix)
        base_off = disp_off + 4
        self._label_fixups.append((disp_off, base_off, label))

    def finalize(self, base_vaddr: int) -> bytes:
        out = bytearray(self.buf)

        for disp_off, base_off, label in self._label_fixups:
            if label not in self.labels:
                raise PatchError(f"unknown label: {label}")
            target_off = self.labels[label]
            disp = target_off - base_off
            if disp < -0x80000000 or disp > 0x7FFFFFFF:
                raise PatchError(f"label rel32 out of range: {label}")
            struct.pack_into("<i", out, disp_off, disp)

        for disp_off, base_off, target_vaddr in self._abs_fixups:
            disp = target_vaddr - (base_vaddr + base_off)
            if disp < -0x80000000 or disp > 0x7FFFFFFF:
                raise PatchError("absolute rel32 out of range")
            struct.pack_into("<i", out, disp_off, disp)

        return bytes(out)


def parse_elf_header(data: bytes) -> ElfHeader:
    if len(data) < 64:
        raise PatchError("file too small")
    if data[:4] != ELF_MAGIC:
        raise PatchError("bad ELF magic")
    if data[4] != ELFCLASS64:
        raise PatchError("only ELF64 is supported")
    if data[5] != ELFDATA2LSB:
        raise PatchError("only little-endian ELF is supported")

    endian = "<"
    fields = struct.unpack_from(endian + "HHIQQQIHHHHHH", data, 16)

    e_type = fields[0]
    e_machine = fields[1]
    e_entry = fields[3]
    e_phoff = fields[4]
    e_shoff = fields[5]
    e_phentsize = fields[8]
    e_phnum = fields[9]
    e_shentsize = fields[10]
    e_shnum = fields[11]
    e_shstrndx = fields[12]

    if e_machine != EM_X86_64:
        raise PatchError("only x86_64 ELF is supported")
    if e_type not in (ET_EXEC, ET_DYN):
        raise PatchError("only ET_EXEC/ET_DYN is supported")

    return ElfHeader(
        endian=endian,
        e_type=e_type,
        e_machine=e_machine,
        e_entry=e_entry,
        e_phoff=e_phoff,
        e_shoff=e_shoff,
        e_phentsize=e_phentsize,
        e_phnum=e_phnum,
        e_shentsize=e_shentsize,
        e_shnum=e_shnum,
        e_shstrndx=e_shstrndx,
    )


def parse_program_headers(data: bytes, ehdr: ElfHeader) -> List[ProgramHeader]:
    need_size = ehdr.e_phoff + ehdr.e_phnum * ehdr.e_phentsize
    if need_size > len(data):
        raise PatchError("program header table out of range")

    phdrs: List[ProgramHeader] = []
    for i in range(ehdr.e_phnum):
        off = ehdr.e_phoff + i * ehdr.e_phentsize
        fields = struct.unpack_from(ehdr.endian + "IIQQQQQQ", data, off)
        phdrs.append(
            ProgramHeader(
                index=i,
                offset_in_file=off,
                p_type=fields[0],
                p_flags=fields[1],
                p_offset=fields[2],
                p_vaddr=fields[3],
                p_paddr=fields[4],
                p_filesz=fields[5],
                p_memsz=fields[6],
                p_align=fields[7],
            )
        )
    return phdrs


def parse_section_headers(data: bytes, ehdr: ElfHeader) -> List[SectionHeader]:
    if ehdr.e_shoff == 0 or ehdr.e_shnum == 0:
        raise PatchError("section header table is required")

    need_size = ehdr.e_shoff + ehdr.e_shnum * ehdr.e_shentsize
    if need_size > len(data):
        raise PatchError("section header table out of range")

    shdrs: List[SectionHeader] = []
    for i in range(ehdr.e_shnum):
        off = ehdr.e_shoff + i * ehdr.e_shentsize
        fields = struct.unpack_from(ehdr.endian + "IIQQQQIIQQ", data, off)
        shdrs.append(
            SectionHeader(
                index=i,
                sh_name=fields[0],
                sh_type=fields[1],
                sh_flags=fields[2],
                sh_addr=fields[3],
                sh_offset=fields[4],
                sh_size=fields[5],
                sh_link=fields[6],
                sh_info=fields[7],
                sh_addralign=fields[8],
                sh_entsize=fields[9],
            )
        )
    return shdrs


def read_c_string(blob: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\x00", offset)
    if end < 0:
        end = len(blob)
    return blob[offset:end].decode("latin-1", errors="ignore")


def build_section_name_map(data: bytes, ehdr: ElfHeader, shdrs: List[SectionHeader]) -> Dict[str, SectionHeader]:
    if ehdr.e_shstrndx >= len(shdrs):
        raise PatchError("bad e_shstrndx")

    shstr = shdrs[ehdr.e_shstrndx]
    end = shstr.sh_offset + shstr.sh_size
    if end > len(data):
        raise PatchError("section string table out of range")
    blob = data[shstr.sh_offset:end]

    out: Dict[str, SectionHeader] = {}
    for sh in shdrs:
        name = read_c_string(blob, sh.sh_name)
        if name:
            out[name] = sh
    return out


def find_init_array_section(data: bytes, ehdr: ElfHeader, shdrs: List[SectionHeader]) -> SectionHeader:
    section_map = build_section_name_map(data, ehdr, shdrs)
    sec = section_map.get(".init_array")
    if sec is None:
        for item in shdrs:
            if item.sh_type == SHT_INIT_ARRAY:
                sec = item
                break
    if sec is None:
        raise PatchError(".init_array not found")
    if sec.sh_size < 8:
        raise PatchError(".init_array is too small")
    if sec.sh_offset + sec.sh_size > len(data):
        raise PatchError(".init_array out of range")
    return sec


def choose_hook_point(
    data: bytes,
    ehdr: ElfHeader,
    shdrs: List[SectionHeader],
) -> Tuple[int, int, str]:
    if ehdr.e_type == ET_DYN:
        return 24, ehdr.e_entry, "e_entry"

    init_sec = find_init_array_section(data, ehdr, shdrs)
    hook_off = init_sec.sh_offset
    original = struct.unpack_from(ehdr.endian + "Q", data, hook_off)[0]
    return hook_off, original, ".init_array[0]"


def choose_injection_plan(
    data: bytes,
    phdrs: List[ProgramHeader],
    hook_off: int,
    hook_original_value: int,
    hook_label: str,
    stub_len: int,
) -> PatchPlan:
    load_segments = [p for p in phdrs if p.p_type == PT_LOAD]
    load_segments.sort(key=lambda p: p.p_offset)

    if not load_segments:
        raise PatchError("no PT_LOAD segment")

    candidates: List[Tuple[int, int, ProgramHeader, int, int, int, int]] = []

    for idx, seg in enumerate(load_segments):
        if (seg.p_flags & PF_X) == 0:
            continue

        inject_off = seg.p_offset + seg.p_filesz
        next_off = len(data)
        for nxt in load_segments[idx + 1 :]:
            if nxt.p_offset > seg.p_offset:
                next_off = nxt.p_offset
                break

        if next_off < inject_off:
            continue

        available = next_off - inject_off
        if available < stub_len:
            continue

        align_cap = available
        if seg.p_align and seg.p_align > 1:
            boundary = ((inject_off + seg.p_align - 1) // seg.p_align) * seg.p_align
            if boundary > inject_off:
                align_cap = min(align_cap, boundary - inject_off)
        if align_cap < stub_len:
            continue

        new_filesz = seg.p_filesz + stub_len
        new_memsz = max(seg.p_memsz, new_filesz)

        cur_end_vaddr = seg.p_vaddr + new_memsz
        next_vaddr = None
        for nxt in load_segments[idx + 1 :]:
            if nxt.p_vaddr > seg.p_vaddr:
                next_vaddr = nxt.p_vaddr
                break
        if next_vaddr is not None and cur_end_vaddr > next_vaddr:
            continue

        inject_vaddr = seg.p_vaddr + (inject_off - seg.p_offset)
        score = 1 if (new_filesz != seg.p_filesz or new_memsz != seg.p_memsz) else 0
        candidates.append((score, -inject_off, seg, inject_off, inject_vaddr, new_filesz, new_memsz))

    if not candidates:
        raise PatchError("no executable cave can hold injected payload")

    candidates.sort(key=lambda item: (item[0], item[1]))
    _, _, seg, inject_off, inject_vaddr, new_filesz, new_memsz = candidates[0]

    return PatchPlan(
        phdr=seg,
        inject_off=inject_off,
        inject_vaddr=inject_vaddr,
        inject_len=stub_len,
        hook_off=hook_off,
        hook_original_value=hook_original_value,
        hook_label=hook_label,
        new_filesz=new_filesz,
        new_memsz=new_memsz,
        need_update_phdr_sizes=(new_filesz != seg.p_filesz or new_memsz != seg.p_memsz),
    )


def calc_diff_stats(a: bytes, b: bytes) -> Tuple[int, List[int]]:
    if len(a) != len(b):
        return abs(len(a) - len(b)), []
    changed = [idx for idx, pair in enumerate(zip(a, b)) if pair[0] != pair[1]]
    return len(changed), changed


def verify_post_patch(data_before: bytes, data_after: bytes) -> None:
    if len(data_before) != len(data_after):
        raise PatchError("patched file size changed")
    parse_elf_header(data_after)


def parse_dyn_symbols(
    data: bytes,
    shdrs: List[SectionHeader],
    section_map: Dict[str, SectionHeader],
) -> List[DynSymbol]:
    dynsym = section_map.get(".dynsym")
    if dynsym is None:
        raise PatchError(".dynsym not found (likely static binary)")

    if dynsym.sh_link >= len(shdrs):
        raise PatchError("bad dynsym sh_link")

    strtab = shdrs[dynsym.sh_link]
    str_end = strtab.sh_offset + strtab.sh_size
    sym_end = dynsym.sh_offset + dynsym.sh_size
    if str_end > len(data) or sym_end > len(data):
        raise PatchError("dynsym/dynstr out of range")

    str_blob = data[strtab.sh_offset:str_end]
    sym_blob = data[dynsym.sh_offset:sym_end]

    entsize = dynsym.sh_entsize if dynsym.sh_entsize else 24
    if entsize < 24:
        raise PatchError("unexpected dynsym entry size")

    count = dynsym.sh_size // entsize
    symbols: List[DynSymbol] = []
    for i in range(count):
        off = i * entsize
        st_name, _st_info, _st_other, _st_shndx, _st_value, _st_size = struct.unpack_from("<IBBHQQ", sym_blob, off)
        name = read_c_string(str_blob, st_name)
        symbols.append(DynSymbol(index=i, name=name))
    return symbols


def parse_rela_entries(data: bytes, rela_section: SectionHeader) -> List[RelaEntry]:
    if rela_section.sh_type != SHT_RELA:
        raise PatchError("relocation section is not SHT_RELA")

    end = rela_section.sh_offset + rela_section.sh_size
    if end > len(data):
        raise PatchError("relocation section out of range")

    blob = data[rela_section.sh_offset:end]
    entsize = rela_section.sh_entsize if rela_section.sh_entsize else 24
    if entsize < 24:
        raise PatchError("unexpected rela entry size")

    out: List[RelaEntry] = []
    count = rela_section.sh_size // entsize
    for i in range(count):
        off = i * entsize
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", blob, off)
        sym_index = r_info >> 32
        r_type = r_info & 0xFFFFFFFF
        out.append(
            RelaEntry(index=i, r_offset=r_offset, sym_index=sym_index, r_type=r_type, addend=r_addend)
        )
    return out


def pick_relocation_section(section_map: Dict[str, SectionHeader]) -> SectionHeader:
    for name in (".rela.plt.sec", ".rela.plt"):
        sec = section_map.get(name)
        if sec is not None:
            return sec
    for name, sec in section_map.items():
        if sec.sh_type == SHT_RELA and "plt" in name:
            return sec
    raise PatchError(".rela.plt(.sec) not found")


def pick_plt_section(section_map: Dict[str, SectionHeader]) -> Tuple[SectionHeader, bool]:
    sec = section_map.get(".plt.sec")
    if sec is not None:
        return sec, True
    sec = section_map.get(".plt")
    if sec is None:
        raise PatchError(".plt/.plt.sec not found")
    return sec, False


def resolve_plt_hook_sites(
    data: bytes,
    shdrs: List[SectionHeader],
    section_map: Dict[str, SectionHeader],
    target_symbols: List[str],
    require_all: bool = True,
) -> Dict[str, HookSite]:
    symbols = parse_dyn_symbols(data, shdrs, section_map)
    rela_section = pick_relocation_section(section_map)
    rela_entries = parse_rela_entries(data, rela_section)
    plt_section, uses_plt_sec = pick_plt_section(section_map)
    legacy_plt_section = section_map.get(".plt")

    entry_size = plt_section.sh_entsize if plt_section.sh_entsize else 16
    if entry_size < 5:
        raise PatchError("plt entry size is too small")

    plt_end = plt_section.sh_offset + plt_section.sh_size
    if plt_end > len(data):
        raise PatchError("plt section out of range")

    wanted = {name: None for name in target_symbols}
    for rel in rela_entries:
        if rel.sym_index >= len(symbols):
            continue
        sym_name = symbols[rel.sym_index].name
        if sym_name not in wanted or wanted[sym_name] is not None:
            continue

        idx = rel.index
        orig_call_vaddr: Optional[int] = None
        if uses_plt_sec:
            plt_vaddr = plt_section.sh_addr + idx * entry_size
            plt_off = plt_section.sh_offset + idx * entry_size
            if legacy_plt_section is not None:
                legacy_entry_size = legacy_plt_section.sh_entsize if legacy_plt_section.sh_entsize else entry_size
                legacy_end = legacy_plt_section.sh_offset + legacy_plt_section.sh_size
                legacy_entry_off = legacy_plt_section.sh_offset + (idx + 1) * legacy_entry_size
                if legacy_entry_off + 6 <= legacy_end:
                    orig_call_vaddr = legacy_plt_section.sh_addr + (idx + 1) * legacy_entry_size + 6
        else:
            plt_vaddr = plt_section.sh_addr + (idx + 1) * entry_size
            plt_off = plt_section.sh_offset + (idx + 1) * entry_size
            orig_call_vaddr = plt_vaddr + 6

        if plt_off + 5 > plt_end:
            continue

        wanted[sym_name] = HookSite(
            name=sym_name,
            plt_vaddr=plt_vaddr,
            plt_off=plt_off,
            plt_entry_size=entry_size,
            relocation_index=idx,
            orig_call_vaddr=orig_call_vaddr,
        )

    missing = [name for name, site in wanted.items() if site is None]
    if require_all and missing:
        raise PatchError(
            "missing dynamic symbol relocation for: " + ", ".join(missing) +
            " (target may be static or inlined syscall binary)"
        )

    return {name: wanted[name] for name in target_symbols if wanted[name] is not None}


def make_sockaddr_in(ip: str, port: int) -> bytes:
    if port <= 0 or port > 65535:
        raise PatchError("port must be in 1..65535")
    try:
        ip_raw = socket.inet_aton(ip)
    except OSError as exc:
        raise PatchError(f"invalid collector ip: {ip}") from exc

    return struct.pack("<H", socket.AF_INET) + struct.pack("!H", port) + ip_raw + (b"\x00" * 8)


def emit_mov_eax_imm32(builder: CodeBuilder, imm: int) -> None:
    builder.emit(b"\xB8" + struct.pack("<I", imm & 0xFFFFFFFF))


def emit_mov_edi_imm32(builder: CodeBuilder, imm: int) -> None:
    builder.emit(b"\xBF" + struct.pack("<I", imm & 0xFFFFFFFF))


def emit_mov_esi_imm32(builder: CodeBuilder, imm: int) -> None:
    builder.emit(b"\xBE" + struct.pack("<I", imm & 0xFFFFFFFF))


def emit_mov_edx_imm32(builder: CodeBuilder, imm: int) -> None:
    builder.emit(b"\xBA" + struct.pack("<I", imm & 0xFFFFFFFF))


def emit_mov_ecx_imm32(builder: CodeBuilder, imm: int) -> None:
    builder.emit(b"\xB9" + struct.pack("<I", imm & 0xFFFFFFFF))


def emit_syscall(builder: CodeBuilder) -> None:
    builder.emit(b"\x0F\x05")


def emit_mov_eax_from_rip_dword(builder: CodeBuilder, label: str) -> None:
    builder.emit_disp32_to_label(b"\x8B\x05", label)


def emit_mov_edi_from_rip_dword(builder: CodeBuilder, label: str) -> None:
    builder.emit_disp32_to_label(b"\x8B\x3D", label)


def emit_mov_rip_dword_from_eax(builder: CodeBuilder, label: str) -> None:
    builder.emit_disp32_to_label(b"\x89\x05", label)


def emit_mov_rip_dword_imm(builder: CodeBuilder, label: str, imm: int) -> None:
    builder.emit_disp32_to_label(b"\xC7\x05", label, struct.pack("<i", imm))


def emit_lea_rsi_from_rip(builder: CodeBuilder, label: str) -> None:
    builder.emit_disp32_to_label(b"\x48\x8D\x35", label)


def build_injected_payload(
    inject_vaddr: int,
    hook_target_vaddr: int,
    collector_ip: str,
    collector_port: int,
    max_payload: int,
) -> Tuple[bytes, Dict[str, int]]:
    return _build_injected_payload(
        inject_vaddr=inject_vaddr,
        hook_target_vaddr=hook_target_vaddr,
        collector_ip=collector_ip,
        collector_port=collector_port,
        max_payload=max_payload,
        enabled_symbols=["read", "write"],
        orig_call_targets={},
    )


def _build_injected_payload(
    inject_vaddr: int,
    hook_target_vaddr: int,
    collector_ip: str,
    collector_port: int,
    max_payload: int,
    enabled_symbols: List[str],
    orig_call_targets: Dict[str, int],
) -> Tuple[bytes, Dict[str, int]]:
    if max_payload <= 0 or max_payload > 0x7FFFFFFF:
        raise PatchError("max_payload must be in 1..2147483647")

    sock_addr = make_sockaddr_in(collector_ip, collector_port)
    enabled_wrappers = {HOOK_WRAPPER_LABEL[s] for s in enabled_symbols if s in HOOK_WRAPPER_LABEL}
    b = CodeBuilder()

    def emit_cstr_len(prefix: str) -> None:
        b.emit(b"\x45\x31\xED")  # xor r13d, r13d
        b.mark(f"{prefix}_len_loop")
        b.emit(b"\x41\x81\xFD" + struct.pack("<I", max_payload))  # cmp r13d, max_payload
        b.emit_rel32_label(b"\x0F\x8D", f"{prefix}_len_done")
        b.emit(b"\x43\x8A\x04\x2C")  # mov al, byte ptr [r12+r13]
        b.emit(b"\x84\xC0")  # test al, al
        b.emit_rel32_label(b"\x0F\x84", f"{prefix}_len_done")
        b.emit(b"\x41\xFF\xC5")  # inc r13d
        b.emit_rel32_label(b"\xE9", f"{prefix}_len_loop")
        b.mark(f"{prefix}_len_done")

    def emit_log_send_block(prefix: str, direction: int, logical_fd: int) -> None:
        emit_mov_eax_imm32(b, SYS_SOCKET_X86_64)
        emit_mov_edi_imm32(b, socket.AF_INET)
        emit_mov_esi_imm32(b, socket.SOCK_STREAM)
        b.emit(b"\x31\xD2")
        emit_syscall(b)
        b.emit(b"\x85\xC0")
        b.emit_rel32_label(b"\x0F\x88", f"{prefix}_send_done")
        b.emit(b"\x41\x89\xC2")  # mov r10d, eax

        b.emit(b"\x44\x89\xD7")  # mov edi, r10d
        emit_lea_rsi_from_rip(b, "sockaddr")
        emit_mov_edx_imm32(b, 16)
        emit_mov_eax_imm32(b, SYS_CONNECT_X86_64)
        emit_syscall(b)
        b.emit(b"\x85\xC0")
        b.emit_rel32_label(b"\x0F\x88", f"{prefix}_connect_fail")

        b.emit(b"\x48\x83\xEC\x10")
        b.emit(b"\xC7\x04\x24" + struct.pack("<I", FRAME_MAGIC))
        b.emit(b"\xC6\x44\x24\x04" + bytes((direction,)))
        b.emit(b"\xC6\x44\x24\x05\x01")
        b.emit(b"\x66\xC7\x44\x24\x06\x00\x00")
        b.emit(b"\xC7\x44\x24\x08" + struct.pack("<I", logical_fd & 0xFFFFFFFF))
        b.emit(b"\x44\x89\x6C\x24\x0C")  # [rsp+12] = r13d

        b.emit(b"\x44\x89\xD7")  # mov edi, r10d
        b.emit(b"\x48\x89\xE6")  # mov rsi, rsp
        emit_mov_eax_imm32(b, SYS_WRITE_X86_64)
        emit_mov_edx_imm32(b, FRAME_HEADER_SIZE)
        emit_syscall(b)

        b.emit(b"\x44\x89\xD7")  # mov edi, r10d
        b.emit(b"\x4C\x89\xE6")  # mov rsi, r12
        b.emit(b"\x44\x89\xEA")  # mov edx, r13d
        emit_mov_eax_imm32(b, SYS_WRITE_X86_64)
        emit_syscall(b)
        b.emit(b"\x48\x83\xC4\x10")

        b.emit(b"\x44\x89\xD7")
        emit_mov_eax_imm32(b, SYS_CLOSE_X86_64)
        emit_syscall(b)
        b.emit_rel32_label(b"\xE9", f"{prefix}_send_done")

        b.mark(f"{prefix}_connect_fail")
        b.emit(b"\x44\x89\xD7")
        emit_mov_eax_imm32(b, SYS_CLOSE_X86_64)
        emit_syscall(b)

        b.mark(f"{prefix}_send_done")

    # startup：只做跳回，避免在 RX 段写可变状态。
    b.mark("startup")
    if hook_target_vaddr:
        b.emit_rel32_abs(b"\xE9", hook_target_vaddr)
    else:
        b.emit(b"\xC3")

    if "read_wrapper" in enabled_wrappers:
        # read wrapper
        b.mark("read_wrapper")
        b.emit(b"\x53\x41\x54\x41\x55\x41\x56")  # push rbx,r12,r13,r14
        b.emit(b"\x49\x89\xFC")  # mov r12,rdi (fd)
        b.emit(b"\x49\x89\xF5")  # mov r13,rsi (buf)
        b.emit(b"\x49\x89\xD6")  # mov r14,rdx (count)
        emit_mov_eax_imm32(b, SYS_READ_X86_64)
        emit_syscall(b)
        b.emit(b"\x48\x89\xC3")  # mov rbx,rax
        b.emit(b"\x48\x83\xFB\x00")  # cmp rbx,0
        b.emit_rel32_label(b"\x0F\x8E", "read_done")  # jle

        b.emit(b"\x89\xD9")  # mov ecx,ebx
        b.emit(b"\x81\xF9" + struct.pack("<I", max_payload))  # cmp ecx,max_payload
        b.emit_rel32_label(b"\x0F\x8E", "read_len_ok")
        emit_mov_ecx_imm32(b, max_payload)
        b.mark("read_len_ok")
        b.emit(b"\x41\x89\xCE")  # mov r14d,ecx

        emit_mov_eax_imm32(b, SYS_SOCKET_X86_64)
        emit_mov_edi_imm32(b, socket.AF_INET)
        emit_mov_esi_imm32(b, socket.SOCK_STREAM)
        b.emit(b"\x31\xD2")
        emit_syscall(b)
        b.emit(b"\x85\xC0")
        b.emit_rel32_label(b"\x0F\x88", "read_done")  # js
        b.emit(b"\x41\x89\xC2")  # mov r10d,eax

        b.emit(b"\x44\x89\xD7")  # mov edi,r10d
        emit_lea_rsi_from_rip(b, "sockaddr")
        emit_mov_edx_imm32(b, 16)
        emit_mov_eax_imm32(b, SYS_CONNECT_X86_64)
        emit_syscall(b)
        b.emit(b"\x85\xC0")
        b.emit_rel32_label(b"\x0F\x88", "read_connect_fail")  # js

        b.emit(b"\x48\x83\xEC\x10")  # sub rsp,0x10
        b.emit(b"\xC7\x04\x24" + struct.pack("<I", FRAME_MAGIC))
        b.emit(b"\xC6\x44\x24\x04\x01")
        b.emit(b"\xC6\x44\x24\x05\x01")
        b.emit(b"\x66\xC7\x44\x24\x06\x00\x00")
        b.emit(b"\x44\x89\x64\x24\x08")  # [rsp+8]=fd(r12d)
        b.emit(b"\x44\x89\x74\x24\x0C")  # [rsp+12]=len(r14d)

        b.emit(b"\x44\x89\xD7")  # mov edi,r10d
        b.emit(b"\x48\x89\xE6")  # mov rsi,rsp
        emit_mov_eax_imm32(b, SYS_WRITE_X86_64)
        emit_mov_edx_imm32(b, FRAME_HEADER_SIZE)
        emit_syscall(b)

        b.emit(b"\x44\x89\xD7")  # mov edi,r10d
        b.emit(b"\x4C\x89\xEE")  # mov rsi,r13
        b.emit(b"\x44\x89\xF2")  # mov edx,r14d
        emit_mov_eax_imm32(b, SYS_WRITE_X86_64)
        emit_syscall(b)
        b.emit(b"\x48\x83\xC4\x10")  # add rsp,0x10

        b.emit(b"\x44\x89\xD7")
        emit_mov_eax_imm32(b, SYS_CLOSE_X86_64)
        emit_syscall(b)
        b.emit_rel32_label(b"\xE9", "read_done")

        b.mark("read_connect_fail")
        b.emit(b"\x44\x89\xD7")
        emit_mov_eax_imm32(b, SYS_CLOSE_X86_64)
        emit_syscall(b)

        b.mark("read_done")
        b.emit(b"\x48\x89\xD8")  # mov rax,rbx
        b.emit(b"\x41\x5E\x41\x5D\x41\x5C\x5B\xC3")  # pop r14,r13,r12,rbx; ret

    if "write_wrapper" in enabled_wrappers:
        # write wrapper
        b.mark("write_wrapper")
        b.emit(b"\x53\x41\x54\x41\x55\x41\x56")  # push rbx,r12,r13,r14
        b.emit(b"\x49\x89\xFC")  # mov r12,rdi (fd)
        b.emit(b"\x49\x89\xF5")  # mov r13,rsi (buf)
        b.emit(b"\x49\x89\xD6")  # mov r14,rdx (count)
        emit_mov_eax_imm32(b, SYS_WRITE_X86_64)
        emit_syscall(b)
        b.emit(b"\x48\x89\xC3")  # mov rbx,rax

        b.emit(b"\x48\x83\xFB\x00")
        b.emit_rel32_label(b"\x0F\x8E", "write_done")

        b.emit(b"\x89\xD9")
        b.emit(b"\x81\xF9" + struct.pack("<I", max_payload))
        b.emit_rel32_label(b"\x0F\x8E", "write_len_ok")
        emit_mov_ecx_imm32(b, max_payload)
        b.mark("write_len_ok")
        b.emit(b"\x41\x89\xCE")  # mov r14d,ecx

        emit_mov_eax_imm32(b, SYS_SOCKET_X86_64)
        emit_mov_edi_imm32(b, socket.AF_INET)
        emit_mov_esi_imm32(b, socket.SOCK_STREAM)
        b.emit(b"\x31\xD2")
        emit_syscall(b)
        b.emit(b"\x85\xC0")
        b.emit_rel32_label(b"\x0F\x88", "write_done")
        b.emit(b"\x41\x89\xC2")  # mov r10d,eax

        b.emit(b"\x44\x89\xD7")
        emit_lea_rsi_from_rip(b, "sockaddr")
        emit_mov_edx_imm32(b, 16)
        emit_mov_eax_imm32(b, SYS_CONNECT_X86_64)
        emit_syscall(b)
        b.emit(b"\x85\xC0")
        b.emit_rel32_label(b"\x0F\x88", "write_connect_fail")

        b.emit(b"\x48\x83\xEC\x10")
        b.emit(b"\xC7\x04\x24" + struct.pack("<I", FRAME_MAGIC))
        b.emit(b"\xC6\x44\x24\x04\x02")
        b.emit(b"\xC6\x44\x24\x05\x01")
        b.emit(b"\x66\xC7\x44\x24\x06\x00\x00")
        b.emit(b"\x44\x89\x64\x24\x08")
        b.emit(b"\x44\x89\x74\x24\x0C")

        b.emit(b"\x44\x89\xD7")
        b.emit(b"\x48\x89\xE6")
        emit_mov_eax_imm32(b, SYS_WRITE_X86_64)
        emit_mov_edx_imm32(b, FRAME_HEADER_SIZE)
        emit_syscall(b)

        b.emit(b"\x44\x89\xD7")
        b.emit(b"\x4C\x89\xEE")
        b.emit(b"\x44\x89\xF2")
        emit_mov_eax_imm32(b, SYS_WRITE_X86_64)
        emit_syscall(b)
        b.emit(b"\x48\x83\xC4\x10")

        b.emit(b"\x44\x89\xD7")
        emit_mov_eax_imm32(b, SYS_CLOSE_X86_64)
        emit_syscall(b)
        b.emit_rel32_label(b"\xE9", "write_done")

        b.mark("write_connect_fail")
        b.emit(b"\x44\x89\xD7")
        emit_mov_eax_imm32(b, SYS_CLOSE_X86_64)
        emit_syscall(b)

        b.mark("write_done")
        b.emit(b"\x48\x89\xD8")  # mov rax,rbx
        b.emit(b"\x41\x5E\x41\x5D\x41\x5C\x5B\xC3")

    if "gets_wrapper" in enabled_wrappers:
        orig_gets = orig_call_targets.get("gets")
        if orig_gets is None:
            raise PatchError("internal error: gets wrapper needs original call target")

        b.mark("gets_wrapper")
        b.emit(b"\x53\x41\x54\x41\x55")  # push rbx,r12,r13
        b.emit(b"\x49\x89\xFC")  # mov r12,rdi (char *buf)
        b.emit_rel32_abs(b"\xE8", orig_gets)
        b.emit(b"\x48\x89\xC3")  # mov rbx,rax
        b.emit(b"\x48\x85\xDB")  # test rbx,rbx
        b.emit_rel32_label(b"\x0F\x84", "gets_done")
        emit_cstr_len("gets")
        b.emit(b"\x41\x83\xFD\x00")  # cmp r13d,0
        b.emit_rel32_label(b"\x0F\x8E", "gets_done")
        emit_log_send_block("gets", direction=1, logical_fd=0)
        b.mark("gets_done")
        b.emit(b"\x48\x89\xD8")  # mov rax,rbx
        b.emit(b"\x41\x5D\x41\x5C\x5B\xC3")  # pop r13,r12,rbx; ret

    if "printf_wrapper" in enabled_wrappers:
        orig_printf = orig_call_targets.get("printf")
        if orig_printf is None:
            raise PatchError("internal error: printf wrapper needs original call target")

        b.mark("printf_wrapper")
        b.emit(b"\x53\x41\x54\x41\x55")  # push rbx,r12,r13
        b.emit(b"\x49\x89\xFC")  # mov r12,rdi (format)
        b.emit_rel32_abs(b"\xE8", orig_printf)
        b.emit(b"\x48\x89\xC3")  # mov rbx,rax
        b.emit(b"\x4D\x85\xE4")  # test r12,r12
        b.emit_rel32_label(b"\x0F\x84", "printf_done")
        emit_cstr_len("printf")
        b.emit(b"\x41\x83\xFD\x00")  # cmp r13d,0
        b.emit_rel32_label(b"\x0F\x8E", "printf_done")
        emit_log_send_block("printf", direction=2, logical_fd=1)
        b.mark("printf_done")
        b.emit(b"\x48\x89\xD8")  # mov rax,rbx
        b.emit(b"\x41\x5D\x41\x5C\x5B\xC3")  # pop r13,r12,rbx; ret

    # data region
    b.mark("sockaddr")
    b.emit(sock_addr)

    payload = b.finalize(inject_vaddr)
    label_vaddrs = {name: inject_vaddr + off for name, off in b.labels.items()}
    return payload, label_vaddrs


def estimate_payload_len(
    has_target: bool,
    collector_ip: str,
    collector_port: int,
    max_payload: int,
    enabled_symbols: List[str],
    orig_call_targets: Dict[str, int],
) -> int:
    dummy_target = 0x1000 if has_target else 0
    payload, _ = _build_injected_payload(
        inject_vaddr=0,
        hook_target_vaddr=dummy_target,
        collector_ip=collector_ip,
        collector_port=collector_port,
        max_payload=max_payload,
        enabled_symbols=enabled_symbols,
        orig_call_targets=orig_call_targets,
    )
    return len(payload)


def patch_plt_entry(out: bytearray, site: HookSite, target_vaddr: int) -> None:
    disp = target_vaddr - (site.plt_vaddr + 5)
    if disp < -0x80000000 or disp > 0x7FFFFFFF:
        raise PatchError(f"rel32 out of range for {site.name}@plt")
    jmp = b"\xE9" + struct.pack("<i", disp)
    out[site.plt_off : site.plt_off + 5] = jmp


def apply_patch(
    data: bytes,
    ehdr: ElfHeader,
    plan: PatchPlan,
    payload: bytes,
    hook_sites: Dict[str, HookSite],
    hook_label_map: Dict[str, str],
    labels: Dict[str, int],
) -> Tuple[bytes, bytes]:
    out = bytearray(data)

    if len(payload) != plan.inject_len:
        raise PatchError("payload length mismatch")

    end = plan.inject_off + len(payload)
    if end > len(out):
        raise PatchError("payload write out of range")
    out[plan.inject_off:end] = payload

    struct.pack_into(ehdr.endian + "Q", out, plan.hook_off, labels["startup"])

    for sym, site in hook_sites.items():
        wrapper_label = hook_label_map[sym]
        if wrapper_label not in labels:
            raise PatchError(f"internal error: wrapper label missing: {wrapper_label}")
        patch_plt_entry(out, site, labels[wrapper_label])

    if plan.need_update_phdr_sizes:
        phoff = plan.phdr.offset_in_file
        struct.pack_into(ehdr.endian + "Q", out, phoff + 32, plan.new_filesz)
        struct.pack_into(ehdr.endian + "Q", out, phoff + 40, plan.new_memsz)

    if len(out) != len(data):
        raise PatchError("patched file size changed")
    return data, bytes(out)


def patch_elf(
    input_path: str,
    output_path: str,
    collector_ip: str,
    collector_port: int,
    max_payload: int,
    dry_run: bool,
) -> None:
    with open(input_path, "rb") as f:
        raw = f.read()

    ehdr = parse_elf_header(raw)
    phdrs = parse_program_headers(raw, ehdr)
    shdrs = parse_section_headers(raw, ehdr)
    section_map = build_section_name_map(raw, ehdr, shdrs)

    hook_off, hook_original, hook_label = choose_hook_point(raw, ehdr, shdrs)
    available_sites = resolve_plt_hook_sites(
        raw,
        shdrs,
        section_map,
        ["read", "write", "gets", "printf"],
        require_all=False,
    )

    hook_sites: Dict[str, HookSite] = {}
    hook_label_map: Dict[str, str] = {}
    orig_call_targets: Dict[str, int] = {}

    # 优先 read/write；对 stdio 函数则要求可调用原始入口以保持语义。
    for sym in ("read", "write", "gets", "printf"):
        site = available_sites.get(sym)
        if site is None:
            continue

        if sym in ORIG_CALL_REQUIRED and site.orig_call_vaddr is None:
            continue

        hook_sites[sym] = site
        hook_label_map[sym] = HOOK_WRAPPER_LABEL[sym]
        if sym in ORIG_CALL_REQUIRED:
            orig_call_targets[sym] = site.orig_call_vaddr  # type: ignore[assignment]

    if not hook_sites:
        raise PatchError(
            "no supported dynamic hook symbols found. expected one of: "
            "read, write, gets, printf"
        )

    enabled_symbols = list(hook_sites.keys())

    stub_len = estimate_payload_len(
        has_target=(hook_original != 0),
        collector_ip=collector_ip,
        collector_port=collector_port,
        max_payload=max_payload,
        enabled_symbols=enabled_symbols,
        orig_call_targets=orig_call_targets,
    )

    plan = choose_injection_plan(
        data=raw,
        phdrs=phdrs,
        hook_off=hook_off,
        hook_original_value=hook_original,
        hook_label=hook_label,
        stub_len=stub_len,
    )

    payload, labels = _build_injected_payload(
        inject_vaddr=plan.inject_vaddr,
        hook_target_vaddr=plan.hook_original_value,
        collector_ip=collector_ip,
        collector_port=collector_port,
        max_payload=max_payload,
        enabled_symbols=enabled_symbols,
        orig_call_targets=orig_call_targets,
    )
    if len(payload) != plan.inject_len:
        raise PatchError("payload length changed after planning")

    elf_type = "PIE(ET_DYN)" if ehdr.e_type == ET_DYN else "No-PIE(ET_EXEC)"
    print("[+] target:", input_path)
    print("[+] elf type:", elf_type)
    print("[+] collector:", f"{collector_ip}:{collector_port}")
    print("[+] hook point:", hook_label, "@", hex(hook_off))
    print("[+] hook original:", hex(hook_original))
    print("[+] payload off:", hex(plan.inject_off), "vaddr:", hex(plan.inject_vaddr), "len:", len(payload))
    hooked_desc = ", ".join(
        f"{sym}@{hex(site.plt_vaddr)}->{hook_label_map[sym]}"
        for sym, site in hook_sites.items()
    )
    print("[+] hooked symbols:", hooked_desc)
    if plan.need_update_phdr_sizes:
        print(
            "[+] update PT_LOAD size:",
            "filesz",
            hex(plan.phdr.p_filesz),
            "->",
            hex(plan.new_filesz),
            "memsz",
            hex(plan.phdr.p_memsz),
            "->",
            hex(plan.new_memsz),
        )
    else:
        print("[+] PT_LOAD size update not needed")

    if dry_run:
        print("[+] dry-run mode: no output file written")
        return

    before, after = apply_patch(raw, ehdr, plan, payload, hook_sites, hook_label_map, labels)
    verify_post_patch(before, after)
    changed_cnt, changed_idx = calc_diff_stats(before, after)
    print("[+] changed bytes:", changed_cnt)
    if changed_idx:
        print("[+] changed range:", hex(changed_idx[0]), "..", hex(changed_idx[-1]))

    with open(output_path, "wb") as f:
        f.write(after)

    print("[+] output:", output_path)
    print("[+] output size:", len(after), "(same as input)")


def recv_exact(sock_obj: socket.socket, size: int) -> Optional[bytes]:
    chunks: List[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = sock_obj.recv(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def sanitize_text_preview(data: bytes, limit: int) -> str:
    view = data[:limit]
    text = view.decode("utf-8", errors="replace")
    return text.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n")


def hex_preview(data: bytes, limit: int) -> str:
    return data[:limit].hex()


def handle_client(
    conn: socket.socket,
    addr: Tuple[str, int],
    log_handle,
    lock: threading.Lock,
    max_frame: int,
    preview_bytes: int,
    stdout: bool,
) -> None:
    peer = f"{addr[0]}:{addr[1]}"
    try:
        while True:
            head = recv_exact(conn, FRAME_HEADER_SIZE)
            if head is None:
                break

            magic, direction, version, _reserved, fd, payload_len = FRAME_HEADER_STRUCT.unpack(head)
            if magic != FRAME_MAGIC:
                raise PatchError(f"invalid frame magic from {peer}: {hex(magic)}")
            if version != 1:
                raise PatchError(f"unsupported frame version from {peer}: {version}")
            if payload_len > max_frame:
                raise PatchError(f"frame too large from {peer}: {payload_len}")

            payload = recv_exact(conn, payload_len)
            if payload is None:
                break

            ts = datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat(timespec="milliseconds")
            dir_name = "read" if direction == 1 else "write" if direction == 2 else f"unknown({direction})"
            text_view = sanitize_text_preview(payload, preview_bytes)
            hex_view = hex_preview(payload, preview_bytes)
            line = (
                f"{ts} src={peer} dir={dir_name} fd={fd} len={payload_len} "
                f"text=\"{text_view}\" hex={hex_view}"
            )

            with lock:
                log_handle.write(line + "\n")
                log_handle.flush()
                if stdout:
                    print(line)

    except (OSError, PatchError) as exc:
        with lock:
            err_line = f"[receiver] {peer} disconnected: {exc}"
            log_handle.write(err_line + "\n")
            log_handle.flush()
            if stdout:
                print(err_line)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def run_receiver(
    listen_ip: str,
    listen_port: int,
    log_file: str,
    max_frame: int,
    preview_bytes: int,
    stdout: bool,
) -> None:
    if listen_port <= 0 or listen_port > 65535:
        raise PatchError("listen port must be in 1..65535")
    if max_frame <= 0:
        raise PatchError("max_frame must be positive")
    if preview_bytes <= 0:
        raise PatchError("preview_bytes must be positive")

    lock = threading.Lock()

    with open(log_file, "a", encoding="utf-8") as log_handle:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((listen_ip, listen_port))
        server.listen(128)

        print(f"[+] receiver listening on {listen_ip}:{listen_port}")
        print(f"[+] logging to {log_file}")

        try:
            while True:
                conn, addr = server.accept()
                t = threading.Thread(
                    target=handle_client,
                    args=(conn, addr, log_handle, lock, max_frame, preview_bytes, stdout),
                    daemon=True,
                )
                t.start()
        finally:
            server.close()


def build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "ELF traffic logger injector for x86_64 dynamic ELF. "
            "Patch mode rewrites read/write@plt and injects TCP mirroring stub; "
            "receiver mode accepts mirrored frames and writes local logs."
        )
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    p_patch = subparsers.add_parser("patch", help="patch ELF and inject traffic mirroring")
    p_patch.add_argument("input", help="input ELF file")
    p_patch.add_argument("output", nargs="?", help="output ELF file (default: <input>.traffic.patched)")
    p_patch.add_argument("--collector-ip", required=True, help="collector IPv4 address")
    p_patch.add_argument("--collector-port", required=True, type=int, help="collector TCP port")
    p_patch.add_argument("--max-payload", type=int, default=1024, help="max bytes mirrored per read/write call")
    p_patch.add_argument("--dry-run", action="store_true", help="analyze only, do not write output")

    p_recv = subparsers.add_parser("receiver", help="run local traffic receiver")
    p_recv.add_argument("--listen-ip", default="0.0.0.0", help="listen IPv4 (default: 0.0.0.0)")
    p_recv.add_argument("--listen-port", required=True, type=int, help="listen TCP port")
    p_recv.add_argument("--log-file", default="traffic_capture.log", help="local log file")
    p_recv.add_argument("--max-frame", type=int, default=262144, help="maximum allowed frame payload bytes")
    p_recv.add_argument("--preview-bytes", type=int, default=128, help="bytes shown in text/hex preview")
    p_recv.add_argument("--silent", action="store_true", help="disable stdout live printing")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_argparser()
    args = parser.parse_args(argv)

    try:
        if args.command == "patch":
            output = args.output if args.output else args.input + ".traffic.patched"
            patch_elf(
                input_path=args.input,
                output_path=output,
                collector_ip=args.collector_ip,
                collector_port=args.collector_port,
                max_payload=args.max_payload,
                dry_run=args.dry_run,
            )
            return 0

        if args.command == "receiver":
            run_receiver(
                listen_ip=args.listen_ip,
                listen_port=args.listen_port,
                log_file=args.log_file,
                max_frame=args.max_frame,
                preview_bytes=args.preview_bytes,
                stdout=not args.silent,
            )
            return 0

        raise PatchError(f"unknown command: {args.command}")

    except (OSError, PatchError, struct.error) as exc:
        print("[-] failed:", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())

