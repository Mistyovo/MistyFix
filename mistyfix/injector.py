"""stub 安装器：把一段机器码安装为程序启动期执行的初始化逻辑。

安装方案移植自前身项目 AWD-Tools-For-PWN（2.add_seccomp.py / 6.Traffic_Reply.py），
并接入 MistyFix 的 cave 优先原则：

- **落点**：优先现有 code cave（等长、不动段头、不新增节）；
  没有足够 cave 时退回「段尾 padding 注入 + 扩容 p_filesz/p_memsz」
  （会修改 16 字节段头，字节比对检测下更显眼，仅在无 cave 时使用）。
- **hook 点**：
  - 非 PIE：改写 ``.init_array[0]``（纯数据修改，不触碰任何代码字节；
    若该条目被 R_*_RELATIVE 重定位覆盖则自动退回 e_entry）；
  - PIE：改写 ELF 头 ``e_entry``（``.init_array`` 在 PIE 下会被加载器用
    重定位 addend 覆盖文件值，文件修改无效）。
- stub 由调用方通过 ``make_stub(stub_vaddr, hook_orig_value)`` 生成，
  便于把落点地址编进 rel32 跳转；安装器负责写入与段头扩容。

合规提示：改 e_entry / 扩容段头都会改变运行行为，在 AWDP fix 检测下
属于高风险操作——本模块主要服务于 sandbox（研究）与流量镜像（传统 AWD）。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Callable

from mistyfix.elf_utils import ELFBinary, ELFError
from mistyfix.patcher import Patcher, PatchError

__all__ = ["InstallPlan", "plan_install", "apply_install", "InstallError"]


class InstallError(Exception):
    """无法为 stub 找到合法落点或安装失败。"""


@dataclass
class StubSpace:
    """stub 落点空间计划（与 hook 方式无关，可被修复策略复用）。"""
    method: str                 # "cave" / "tail"
    stub_vaddr: int
    stub_file_off: int
    stub_len: int
    need_phdr_grow: bool = False
    phdr_off: int | None = None
    new_filesz: int = 0
    new_memsz: int = 0


@dataclass
class InstallPlan:
    method: str                 # "cave+init_array" / "tail+init_array" / "cave+entry" / "tail+entry"
    stub_vaddr: int             # stub 链接视图虚拟地址
    stub_file_off: int          # stub 写入的文件偏移
    stub_len: int
    hook_off: int               # hook 点文件偏移（.init_array[0] 或 e_entry）
    hook_label: str
    hook_orig_value: int        # 原值（stub 应在结尾跳回它）
    need_phdr_grow: bool
    phdr_off: int | None        # 需要扩容的段头文件偏移
    new_filesz: int = 0
    new_memsz: int = 0
    notes: list[str] = field(default_factory=list)

    def describe(self) -> str:
        lines = [
            f"安装方式: {self.method}",
            f"stub 落点: vaddr 0x{self.stub_vaddr:x} (file 0x{self.stub_file_off:x}), {self.stub_len} 字节",
            f"hook 点: {self.hook_label} @ file 0x{self.hook_off:x} (原值 0x{self.hook_orig_value:x})",
        ]
        if self.need_phdr_grow and self.phdr_off is not None:
            lines.append(
                f"段头扩容: phdr@0x{self.phdr_off:x} -> p_filesz=0x{self.new_filesz:x}, "
                f"p_memsz=0x{self.new_memsz:x}（修改 16 字节段头，检测下更明显）")
        else:
            lines.append("段头不变（cave 等长注入）")
        lines.extend(f"注: {n}" for n in self.notes)
        return "\n".join(lines)


def plan_stub_space(elf: ELFBinary, stub_len: int) -> StubSpace:
    """为长 stub_len 的机器码选择落点：cave 优先，段尾 padding 扩容兜底。"""
    if stub_len <= 0:
        raise InstallError("stub 长度必须为正")

    caves = elf.caves(min_size=stub_len)
    if caves:
        cave = caves[0]  # .eh_frame 优先（caves() 内部已排序）
        return StubSpace(method="cave", stub_vaddr=cave.vaddr,
                         stub_file_off=cave.file_offset, stub_len=stub_len)

    all_segs = elf.load_segments_sorted()
    for phdr_idx, off, vaddr, filesz, memsz, _flags in reversed(elf.exec_load_segments()):
        inject_off = off + filesz
        # 下一个段（任意类型）的文件起点，注入不得越过它
        next_off = len(elf.data)
        next_vaddr = None
        for _s_idx, s_off, s_vaddr, _fsz, _msz, _fl in all_segs:
            if s_off > off:
                next_off = min(next_off, s_off)
                if next_vaddr is None or s_vaddr < next_vaddr:
                    next_vaddr = s_vaddr
        if next_off - inject_off < stub_len:
            continue
        inject_vaddr = vaddr + filesz
        # vaddr 侧不得与相邻段重叠
        if next_vaddr is not None and inject_vaddr + stub_len > next_vaddr:
            continue

        return StubSpace(
            method="tail", stub_vaddr=inject_vaddr, stub_file_off=inject_off,
            stub_len=stub_len, need_phdr_grow=True,
            phdr_off=elf.phoff + phdr_idx * elf.phentsize,
            new_filesz=filesz + stub_len, new_memsz=max(memsz, filesz + stub_len))

    raise InstallError(
        f"没有可用落点：无 ≥{stub_len} 字节的 code cave，可执行段尾 padding 也放不下")


def grow_segment(elf: ELFBinary, phdr_off: int, new_filesz: int, new_memsz: int) -> None:
    """扩容 PT_LOAD 的 p_filesz/p_memsz 并同步 ELFBinary 的段映射缓存。

    缓存不同步的话，同会话内的后续注入（批量修复第二个 stub）会按旧
    filesz 规划，落点与本次注入区重叠。
    """
    width = 8 if elf.arch == "amd64" else 4
    if width == 8:  # Elf64_Phdr: p_filesz@32, p_memsz@40
        struct.pack_into("<Q", elf.data, phdr_off + 32, new_filesz)
        struct.pack_into("<Q", elf.data, phdr_off + 40, new_memsz)
    else:           # Elf32_Phdr: p_filesz@16, p_memsz@20
        struct.pack_into("<I", elf.data, phdr_off + 16, new_filesz)
        struct.pack_into("<I", elf.data, phdr_off + 20, new_memsz)

    # 同步 phdr_entries / _segments 缓存（按 phdr_off 反查段索引）
    idx = (phdr_off - elf.phoff) // elf.phentsize
    for i, (p_idx, off, va, filesz, memsz, flags) in enumerate(elf.phdr_entries):
        if p_idx != idx:
            continue
        elf.phdr_entries[i] = (p_idx, off, va, new_filesz, new_memsz, flags)
        for j, (o2, v2, f2, fl2) in enumerate(elf._segments):
            if o2 == off and v2 == va:
                elf._segments[j] = (o2, v2, max(f2, new_filesz), fl2)


def apply_stub_space(patcher: Patcher, space: StubSpace, payload: bytes) -> int:
    """把 payload 写到计划落点（tail 时扩容段头）。返回落点 vaddr。

    payload 允许比 space.stub_len 短（混淆变体随机长度），但不得更长。
    """
    elf = patcher.elf
    if len(payload) > space.stub_len:
        raise InstallError(
            f"payload 长度超出计划: {len(payload)} > {space.stub_len}")
    elf.data[space.stub_file_off : space.stub_file_off + len(payload)] = payload
    patcher.log.append(
        f"inject {len(payload)}B at 0x{space.stub_vaddr:x} "
        f"(file 0x{space.stub_file_off:x}, {space.method})")
    if space.need_phdr_grow and space.phdr_off is not None:
        grow_segment(elf, space.phdr_off, space.new_filesz, space.new_memsz)
    return space.stub_vaddr


def plan_install(elf: ELFBinary, stub_len: int) -> InstallPlan:
    """为长 stub_len 的机器码选择落点与 hook 点。找不到时抛 InstallError。"""
    space = plan_stub_space(elf, stub_len)

    notes: list[str] = []
    # ---- hook 点选择 --------------------------------------------------
    hook_off = hook_orig = None
    hook_label = ""
    if not elf.is_pie:
        ia = elf.init_array_first_entry()
        if ia is not None:
            ia_off, ia_value = ia
            try:
                ia_vaddr = elf.offset_to_vaddr(ia_off)
            except ELFError:
                ia_vaddr = None
            if ia_vaddr is not None and ia_vaddr in elf.rela_relative_addends():
                notes.append(
                    ".init_array[0] 带 R_*_RELATIVE 重定位（加载器会覆盖文件值），改用 e_entry")
            else:
                hook_off, hook_orig, hook_label = ia_off, ia_value, ".init_array[0]"
        else:
            notes.append("未找到 .init_array（静态二进制？），改用 e_entry")
    else:
        notes.append("PIE: .init_array 会被 RELATIVE 重定位覆盖，使用 e_entry")

    if hook_off is None:
        hook_off, hook_orig, hook_label = elf.entry_header_offset(), elf.entry_vaddr(), "e_entry"

    return InstallPlan(
        method=f"{space.method}+{'init_array' if hook_label == '.init_array[0]' else 'entry'}",
        stub_vaddr=space.stub_vaddr, stub_file_off=space.stub_file_off,
        stub_len=space.stub_len, hook_off=hook_off, hook_label=hook_label,
        hook_orig_value=hook_orig, need_phdr_grow=space.need_phdr_grow,
        phdr_off=space.phdr_off, new_filesz=space.new_filesz,
        new_memsz=space.new_memsz, notes=notes)


def apply_install(patcher: Patcher, plan: InstallPlan,
                  make_stub: Callable[[int, int], bytes]) -> int:
    """按计划写入 stub 并改 hook 点（必要时扩容段头）。返回 stub vaddr。

    make_stub(stub_vaddr, hook_orig_value) 需返回不超 plan.stub_len 字节的
    机器码（stub 应在结尾跳回 hook_orig_value，e_entry/.init_array 两种
    hook 语义下都是尾跳转）。
    """
    elf = patcher.elf
    orig_size = len(elf.data)
    stub = make_stub(plan.stub_vaddr, plan.hook_orig_value)
    if len(stub) > plan.stub_len:
        raise InstallError(
            f"stub 长度超出计划: make_stub 返回 {len(stub)} 字节，计划上限 {plan.stub_len}"
            "（探针请用 obfuscate=False 的最长变体估算）")

    apply_stub_space(patcher, StubSpace(
        method=plan.method.split("+")[0], stub_vaddr=plan.stub_vaddr,
        stub_file_off=plan.stub_file_off, stub_len=plan.stub_len,
        need_phdr_grow=plan.need_phdr_grow, phdr_off=plan.phdr_off,
        new_filesz=plan.new_filesz, new_memsz=plan.new_memsz), stub)

    # hook 点改写为 stub 地址
    width = 8 if elf.arch == "amd64" else 4
    struct.pack_into("<Q" if width == 8 else "<I",
                     elf.data, plan.hook_off, plan.stub_vaddr)
    patcher.log.append(
        f"hook {plan.hook_label} (file 0x{plan.hook_off:x}): "
        f"0x{plan.hook_orig_value:x} -> 0x{plan.stub_vaddr:x}")

    if len(elf.data) != orig_size:
        raise PatchError("install must not change file size")
    return plan.stub_vaddr
