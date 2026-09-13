"""MistyFix 冒烟测试：基于真实 amd64 ELF（tests/vuln）做静态级验证。

覆盖：ELF 解析 / cave 发现 / call 定位 / 三种修复策略 / trampoline 注入 /
合规检测 / diff_files / sandbox stub 特征码规避。

运行：python tests/smoke_test.py（在项目根目录，无需 Linux；运行时验证另见
WSL 端到端记录）。退出码 0 = 全部通过。
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mistyfix import (  # noqa: E402
    ComplianceChecker,
    ELFBinary,
    Patcher,
    RENAME_PRESETS,
    diff_files,
    dynstr_rename,
    fix_read_length,
    true_fix_free,
)
from mistyfix.sandbox import FORBIDDEN_SIGNATURES, build_seccomp_stub, rules_warning  # noqa: E402

SAMPLE = os.path.join(os.path.dirname(__file__), "vuln")

_failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    mark = "PASS" if cond else "FAIL"
    print(f"  [{mark}] {name}" + (f": {detail}" if detail else ""))
    if not cond:
        _failures.append(name)


def main() -> int:
    print("[*] 样本:", SAMPLE)
    elf = ELFBinary(SAMPLE)

    # ---- ELF 解析与定位 ----
    check("arch is amd64", elf.arch == "amd64")
    check("has .text/.plt/.got.plt/.dynstr/.eh_frame",
          all(any(s.name == n for s in elf.sections())
              for n in (".text", ".plt", ".got.plt", ".dynstr", ".eh_frame")))
    caves = elf.caves(min_size=64)
    check("found executable cave >= 64B", len(caves) > 0,
          f"{len(caves)} caves, largest {max((c.size for c in caves), default=0)}B")
    free_calls = elf.find_calls_to("free")
    read_calls = elf.find_calls_to("read")
    check("found call free@plt", len(free_calls) >= 1, [hex(a) for a in free_calls])
    check("found call read@plt", len(read_calls) >= 1, [hex(a) for a in read_calls])
    check("dynstr has 'free'", elf.dynstr_offset("free") is not None)
    check("plt_stub_addr('free')", elf.plt_stub_addr("free") is not None)

    # ---- 自对自合规检测 ----
    results = ComplianceChecker(SAMPLE, SAMPLE).run_all()
    check("self-vs-self compliance all PASS", all(r.passed for r in results),
          f"{len(results)} checks")

    with tempfile.TemporaryDirectory() as td:
        # ---- rename free -> atoi ----
        out = os.path.join(td, "vuln.rename")
        elf_r = ELFBinary(SAMPLE)
        plan = dynstr_rename(elf_r, old="free", new="atoi")
        check("dynstr_rename applied", plan.applied, plan.description)
        elf_r.save(out)
        diff = diff_files(SAMPLE, out)
        check("rename changes exactly 4 bytes in .dynstr",
              diff["size_equal"] and diff["changed_bytes"] == 4)
        check("renamed dynstr no longer binds 'free'",
              ELFBinary(out).dynstr_offset("free") is None)
        results = ComplianceChecker(SAMPLE, out).run_all()
        check("rename compliance all PASS", all(r.passed for r in results))

        # ---- fix-read ----
        out = os.path.join(td, "vuln.fixread")
        elf2 = ELFBinary(SAMPLE)
        patcher2 = Patcher(elf2)
        plan = fix_read_length(patcher2, read_calls[0], 0x40)
        check("fix_read_length applied", plan.applied, plan.description)
        patcher2.save(out)
        results = ComplianceChecker(SAMPLE, out).run_all()
        check("fix-read compliance all PASS", all(r.passed for r in results))

        # ---- fix-free（trampoline 注入 + 置空指针） ----
        out = os.path.join(td, "vuln.fixfree")
        elf3 = ELFBinary(SAMPLE)
        patcher3 = Patcher(elf3)
        ptr = next((s.value for s in elf3._binary.symtab_symbols if s.name == "g_ptr"), None)
        check("located g_ptr symbol", ptr is not None, hex(ptr or 0))
        plan = true_fix_free(patcher3, free_calls[0], ptr)
        check("true_fix_free applied", plan.applied, plan.description)
        patcher3.save(out)
        results = ComplianceChecker(SAMPLE, out).run_all()
        check("fix-free compliance all PASS", all(r.passed for r in results),
              "; ".join(f"{r.name}={'PASS' if r.passed else 'FAIL'}" for r in results))
        # trampoline 内容验证：hook 处为 jmp，cave 中含真实 call free（非 NOP）
        fixed = ELFBinary(out)
        hook_off = fixed.vaddr_to_offset(free_calls[0])
        check("hook site rewritten to E9 jmp (not NOP)",
              fixed.data[hook_off] == 0xE9
              and not all(b == 0x90 for b in fixed.data[hook_off:hook_off + 5]))
        cave_va = fixed.caves(min_size=64)
        # cave 已被 stub 占用，重新从 hook 的 jmp 目标读 stub
        rel = int.from_bytes(fixed.data[hook_off + 1:hook_off + 5], "little", signed=True)
        stub_va = free_calls[0] + 5 + rel
        stub_off = fixed.vaddr_to_offset(stub_va)
        stub = bytes(fixed.data[stub_off:stub_off + 64])
        # keystone 会把小立即数编码为 imm32 形式（48 C7 C0 + imm32），两种形态都接受
        free_plt = elf3.plt_stub_addr("free")
        check("stub contains absolute call target free@plt",
              free_plt.to_bytes(4, "little") in stub
              or free_plt.to_bytes(8, "little") in stub)
        if ptr is not None:
            check("stub nulls g_ptr (UAF fix)",
                  ptr.to_bytes(4, "little") in stub
                  or ptr.to_bytes(8, "little") in stub)

        # ---- sandbox stub 特征码规避（静态，不注入） ----
        check("rules_warning non-empty", len(rules_warning()) > 50)
        stub = build_seccomp_stub("amd64", obfuscate=False)
        check("seccomp stub built (mov-eax variant)", len(stub) > 100, f"{len(stub)} bytes")
        check("stub free of known prctl signatures",
              all(sig not in stub for sig in FORBIDDEN_SIGNATURES))
        for _ in range(8):  # 混淆路径随机化多次采样
            stub = build_seccomp_stub("amd64", obfuscate=True)
            if any(sig in stub for sig in FORBIDDEN_SIGNATURES):
                check("obfuscated stub free of signatures", False)
                break
        else:
            check("obfuscated stub free of signatures (8 samples)", True)

    print()
    print("-- 改名预设 --")
    check("预设表非空", len(RENAME_PRESETS) >= 8)
    check("预设全部满足等长约束",
          all(len(new) <= len(old) for old, new, _d in RENAME_PRESETS.values()))
    check("预设符号均非空且不含空白",
          all(old and new and " " not in old and " " not in new
              for old, new, _d in RENAME_PRESETS.values()))
    # CLI --preset 实际跑通（free2atoi 对样例成立）
    from mistyfix.cli import main as cli_main
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "vuln.preset")
        rc = cli_main(["rename", SAMPLE, "--preset", "free2atoi", "-o", out])
        check("CLI rename --preset free2atoi 成功", rc == 0 and os.path.isfile(out))
        rc2 = cli_main(["rename", SAMPLE, "--preset", "no_such", "-o", out])
        check("CLI rename 未知预设报错退出", rc2 == 2)

    print()
    if _failures:
        print(f"[!] {len(_failures)} 项失败: {_failures}")
        return 1
    print("[+] 冒烟测试全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
