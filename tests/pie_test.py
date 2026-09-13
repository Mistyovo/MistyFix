"""PIE 支持专项测试：对 tmp/vuln_pie（gcc -pie 编译）跑全部功能的静态验证。

运行: python tests/pie_test.py
矩阵: is_pie 检测 / info / caves / fix-read / fix-free(含 ptr 置空) /
rename(+预设) / fix-cmp / patch(通用 trampoline) / sandbox 安装(e_entry) /
traffic patch 计划 / 合规检测 / GUI 不在此列(见 gui_smoke 的 PIE 用例)。
运行时(WSL)验证: 见本文件末尾输出的指引或 README。
"""

from __future__ import annotations

import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mistyfix import (  # noqa: E402
    ELFBinary,
    Patcher,
    RENAME_PRESETS,
    ComplianceChecker,
    dynstr_rename,
    fix_int_compare,
    fix_read_length,
    true_fix_free,
)
from mistyfix.cli import main as cli_main  # noqa: E402
from mistyfix.injector import plan_install  # noqa: E402
from mistyfix.sandbox import build_seccomp_stub  # noqa: E402

from capstone import Cs, CS_ARCH_X86, CS_MODE_64  # noqa: E402

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "tmp", "vuln_pie")

_failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    mark = "PASS" if cond else "FAIL"
    print(f"  [{mark}] {name}" + (f": {detail}" if detail else ""))
    if not cond:
        _failures.append(name)


def compliance_all(orig: str, patched: str) -> tuple[bool, str]:
    results = ComplianceChecker(orig, patched).run_all()
    ok = all(r.passed for r in results)
    detail = "; ".join(f"{r.name}={'PASS' if r.passed else 'FAIL'}" for r in results)
    return ok, detail


def main() -> int:
    if not os.path.isfile(SAMPLE):
        print(f"[!] PIE 样例不存在: {SAMPLE}（WSL: gcc -pie -o tmp/vuln_pie tmp/vuln.c）")
        return 1
    td = tempfile.mkdtemp(prefix="mistyfix_pie_")

    print("== 基础解析 ==")
    elf = ELFBinary(SAMPLE)
    check("is_pie = True", elf.is_pie)
    check("架构 amd64", elf.arch == "amd64")
    check("节表非空", len(elf.sections()) > 10)
    check("cave 发现可用", len(elf.caves(min_size=32)) >= 1)
    check("定位 call free@plt", len(elf.find_calls_to("free")) == 2)
    check("定位 call read@plt", len(elf.find_calls_to("read")) == 1)
    check(".dynstr 含 free", elf.dynstr_offset("free") is not None)
    check("g_ptr 符号定位", elf.plt_stub_addr("free") is not None)

    free_calls = elf.find_calls_to("free")
    read_calls = elf.find_calls_to("read")

    print("== fix-read（栈溢出长度）==")
    p = Patcher(ELFBinary(SAMPLE))
    plan = fix_read_length(p, read_calls[0], 0x20)
    check("应用成功", plan.applied, plan.description[:70])
    out = os.path.join(td, "pie.fixread")
    p.save(out)
    ok, detail = compliance_all(SAMPLE, out)
    check("合规检测全部通过", ok, detail[:90])
    patched = ELFBinary(out)
    check("read 长度立即数 0x200 -> 0x20",
          b"\xba\x20\x00\x00\x00" in bytes(patched.data),
          "mov edx, 0x20 编码已写入")

    print("== fix-free（UAF/double-free，含 PIE 指针置空）==")
    # g_ptr 在 PIE 样例的 .bss @ 0x4050（not stripped，LIEF 符号表定位）
    g_ptr = next(s.value for s in elf._binary.symbols if s.name == "g_ptr")
    check("g_ptr 符号定位", g_ptr == 0x4050, hex(g_ptr))

    p = Patcher(ELFBinary(SAMPLE))
    plan = true_fix_free(p, free_calls[0], ptr_vaddr=None)
    check("无 ptr 应用成功", plan.applied, plan.description[:70])
    p2 = Patcher(ELFBinary(SAMPLE))
    plan2 = true_fix_free(p2, free_calls[0], ptr_vaddr=g_ptr)
    check("PIE + ptr 置空应用成功（RIP 相对）", plan2.applied, plan2.description[:70])
    out2 = os.path.join(td, "pie.fixfree")
    p2.save(out2)
    ok, detail = compliance_all(SAMPLE, out2)
    check("合规检测全部通过", ok, detail[:90])
    # 字节级验证 stub：rel32 call free@plt + RIP 相对置空写入 g_ptr
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    patched2 = ELFBinary(out2)
    hook_off = patched2.vaddr_to_offset(free_calls[0])
    check("hook 点改写为 E9 jmp", patched2.data[hook_off] == 0xE9)
    orig_cave = ELFBinary(SAMPLE).caves(min_size=64)[0]
    stub_off = patched2.vaddr_to_offset(orig_cave.vaddr)
    stub = bytes(patched2.data[stub_off:stub_off + 64])
    free_plt = elf.plt_stub_addr("free")
    found_call = found_rip_store = False
    from capstone.x86_const import X86_OP_MEM, X86_REG_RIP
    for i in md.disasm(stub, orig_cave.vaddr):
        if i.mnemonic == "call" and "rax" not in i.op_str \
                and int(i.op_str, 0) == free_plt:
            found_call = True
        if i.mnemonic == "mov":
            for op in i.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    target = i.address + i.size + op.mem.disp
                    if target == g_ptr:
                        found_rip_store = True
        if i.mnemonic == "jmp":
            break
    check("stub 内 rel32 call free@plt", found_call)
    check("stub 内 RIP 相对置空且目标 == g_ptr", found_rip_store)

    print("== 批量 fix-free（2 处，叠加 ptr 置空）==")
    p3 = Patcher(ELFBinary(SAMPLE))
    plans = [true_fix_free(p3, a, ptr_vaddr=g_ptr) for a in free_calls]
    check("两处全部应用", all(pl.applied for pl in plans))
    out3 = os.path.join(td, "pie.fixfree2")
    p3.save(out3)
    ok, detail = compliance_all(SAMPLE, out3)
    check("合规检测全部通过", ok, detail[:90])
    check("文件等长", os.path.getsize(out3) == os.path.getsize(SAMPLE))

    print("== rename（含预设）==")
    elf4 = ELFBinary(SAMPLE)
    plan = dynstr_rename(elf4, old="free", new="atoi")
    check("free->atoi 应用成功", plan.applied)
    out4 = os.path.join(td, "pie.rename")
    elf4.save(out4)
    ok, detail = compliance_all(SAMPLE, out4)
    check("合规检测全部通过", ok, detail[:90])

    print("== fix-cmp ==")
    p5 = Patcher(ELFBinary(SAMPLE))
    # 与非 PIE 样例同源的 cmp rax, imm（0x3D 短格式）策略本就不支持——
    # 这里验证 PIE 下行为一致：明确拒绝而非错误应用
    plan = fix_int_compare(p5, 0x10d5, 0x10)
    check("0x3D 形式 cmp 一致地拒绝(非 PIE 限制)", not plan.applied,
          plan.description[:60])

    print("== patch（通用 trampoline）==")
    rc = cli_main(["patch", SAMPLE, hex(read_calls[0]), "90",
                   "-o", os.path.join(td, "pie.patched")])
    check("CLI patch 应用成功", rc == 0)
    ok, detail = compliance_all(SAMPLE, os.path.join(td, "pie.patched"))
    check("合规检测全部通过", ok, detail[:90])

    print("== sandbox（e_entry 安装路径）==")
    probe = build_seccomp_stub("amd64", mode="blacklist", blacklist=(59,),
                               obfuscate=False, vaddr=0, entry_jmp_to=0)
    splan = plan_install(ELFBinary(SAMPLE), len(probe))
    check("安装方式为 cave+entry", splan.method == "cave+entry", splan.method)
    check("hook 点为 e_entry", splan.hook_label == "e_entry")
    rc = cli_main(["sandbox", SAMPLE, "-o", os.path.join(td, "pie.sb"),
                   "--mode", "blacklist", "--i-know-the-risk"])
    check("CLI sandbox 安装成功", rc == 0)
    sb = open(os.path.join(td, "pie.sb"), "rb").read()
    new_entry = struct.unpack_from("<Q", sb, 24)[0]
    check("e_entry 已改写为 stub 地址",
          new_entry == splan.stub_vaddr, f"entry -> {new_entry:#x}")
    # 已知边界：改 e_entry 必然命中 AWDP 检测④（入口机器码比对），
    # 其余 6 项应通过——这正是文档所说"高可见度改动"的量化体现
    sb_results = ComplianceChecker(SAMPLE, os.path.join(td, "pie.sb")).run_all()
    by_name = {r.name: r.passed for r in sb_results}
    check("e_entry 方案命中 check_start（预期高可见度代价）",
          by_name.get("check_start") is False)
    check("其余 6 项合规通过",
          all(v for k, v in by_name.items() if k != "check_start"))

    print("== traffic（e_entry 注入计划）==")
    from mistyfix import traffic
    out_traffic = os.path.join(td, "pie.traffic")
    try:
        traffic.patch_elf(SAMPLE, out_traffic, "127.0.0.1", 9001, 1024, dry_run=True)
        check("traffic dry-run 计划成功(e_entry)", True)
    except Exception as exc:  # noqa: BLE001
        check("traffic dry-run 计划成功(e_entry)", False, str(exc)[:80])

    print()
    if _failures:
        print(f"[!] {len(_failures)} 项失败: {_failures}")
        return 1
    print("[+] PIE 专项测试全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
