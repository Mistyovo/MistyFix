# MistyFix

AWDP（CTF 攻防赛）PWN 方向的**合规漏洞修复（Fix）工具**。

> **v0.2.0 融合版**：本项目由前身 [AWD-Tools-For-PWN](https://github.com/Mistyovo/AWD-Tools-For-PWN)
> 演化而来，v0.2.0 完成了两者的取长补短——前身的注入机制（PIE 支持、
> `.init_array`/`e_entry` 劫持安装、段尾注入兜底、seccomp 黑名单/strict 模式、
> 通用 trampoline、RIP 相对指令搬运检查）已并入本工具核心，其 AWD 攻击侧
> 工具（exp 模板 / 批量攻击 / 流量镜像）作为独立命令共存；MistyFix 原有的
> 合规检测闭环继续覆盖所有 patch 能力。

在 AWDP 赛制中，选手需要在不破坏程序正常业务功能的前提下修补二进制漏洞，并通过平台的多维度 fix 检测。MistyFix 的目标是把"找到漏洞 → 精准修复 → 验证合规"这条链路自动化，所有修改均遵循以下原则：

- **等长替换**：修改立即数、指令时保持字节长度不变，不改变文件大小；
- **code cave 注入**：只利用可执行段中已有的空隙（连续 `0x00`/`0x90`，优先 `.eh_frame`），不新增节、不改节表；
- **真修复替代 NOP**：例如 UAF/Double-Free 用"free 后置空指针"真修复，而不是把 `call free` NOP 掉；
- **改数据不改控制流**：优先改 `.dynstr`、立即数等数据，尽量不劫持跳转；
- **不碰 GOT / `_start`**：`.got.plt` 内容与入口机器码保持逐字节一致。

## 检测原理与应对策略对照表

| AWDP 检测手段 | 原理 | MistyFix 应对策略 |
| --- | --- | --- |
| ① 文件 size/字节数比对 | 修复后文件大小必须与原文件一致 | 所有 patch 均为原地等长写入，绝不增删字节；`check` 子命令自动比对 size 与变化字节区间 |
| ② LIEF 解析节数量/地址/大小 | 节表结构必须不变 | 不新增/删除/扩展节，stub 只写进已有节的 cave；`check` 用 LIEF 逐节比对 |
| ③ `.got.plt` 内容比对 | GOT 不能被改写 | 修复不触碰 GOT；`check` 逐字节比对 `.got.plt` |
| ④ `_start` 机器码比对 | 入口代码不能动 | 不在 entrypoint 注入任何代码；`check` 比对 entry 处机器码 |
| ⑤ `.eh_frame` 内 prctl 特征码扫描 | amd64: `B0 9D 0F 05`；i386: `B0 AC CD 80`，检测是否塞了通防沙箱 | **不提供、不鼓励通防**。`sandbox` 命令生成的 stub 会对特征字节做混淆拆分（`obfuscate=True`），仅用于学习研究；且必须显式 `--i-know-the-risk` 才执行 |
| ⑥ `call free` 被 NOP 的特征检测 | NOP 掉 free 属于假修复，会被判负 | `fix-free` 实现真修复（free 后将指针置空），不用 NOP；`check` 扫描 `call free` 被 NOP 的特征 |
| ⑦ 功能交互 check | 正常业务流程必须不变 | 修复只收敛非法行为，不改变正常输入的处理路径；`test` 子命令支持用交互脚本回归验证 |
| ⑧ 官方 exp 复验 | 修复后原漏洞 exp 必须失效 | 修复策略针对漏洞根因（长度、释放后使用等）；`checker.replay_exp` 可复跑 exp 确认已失效 |

## 安装

```bash
pip install .
# 或开发模式
pip install -e .
```

依赖：`lief`、`capstone`、`keystone-engine`（`pwntools` 为可选依赖，缺失时相关功能优雅降级）。安装后即可使用 `mistyfix` 命令，或等价的 `python -m mistyfix`。

## 图形界面（GUI）

所有功能都有图形界面版本，基于 tkinter（Python 自带，零额外依赖）：

```bash
mistyfix gui [binary]      # 推荐：启动 GUI，可顺带加载目标文件
mistyfix-gui [binary]      # 安装后等价的独立入口
python -m mistyfix.gui [binary]
```

GUI 在 CLI 之上的增强：

- **概览页**：节表与 code cave 表格化展示，cave 最小尺寸可调；
- **批量修复**：修复 read/free 页扫描调用点后得到**可勾选清单**（默认全选，支持全选/全不选/手动添加地址），一键对全部勾选点批量修复——同一内存副本上叠加补丁、单次保存、单次合规检测；部分点失败不影响其余点，逐项报告结果；
- **自动定位调用点**：一键扫描 `call read@plt` / `call free@plt` 的全部位置，不用手动找地址；
- **叠加修复**：默认开启「修复后自动加载产物」，修复产物自动成为目标文件，可直接切到其他标签页继续叠加（如先修 read 再修 free），无需手动重载；
- **指令预览**：点击清单行自动显示其前后反汇编（目标指令高亮）；
- **实时参数校验**：如符号改名页的等长校验（过长立即红色提示）、地址栏支持 `0x` 前缀 / 十进制 / 纯十六进制；
- **合规检测表格**：7 项检测 PASS/FAIL/WARN 彩色分栏显示，每次修复保存后自动检测并回填；
- **内置交互脚本编辑器**：功能测试 / exp 复验无需单独建文件，直接在 GUI 里写 `recvuntil`/`sendline` 脚本运行；
- **后台执行 + 彩色日志**：所有耗时操作后台线程执行界面不卡死，底部类终端日志区统一记录（可导出）；
- **整数比较修复**：`fix-cmp`（等长替换 `cmp reg, imm` 立即数）为 GUI 独有入口，CLI 暂未提供；
- **通用补丁页**：任意地址插入任意机器码（trampoline，前身 elf-patcher 移植），支持 vaddr/文件偏移切换与指令预览；
- **沙箱三模式**：白名单 / 黑名单（命中即杀，破坏面最小）/ strict，自动选择安装方式（cave + `.init_array[0]` / `e_entry` 劫持，无 cave 时段尾注入），带 dry-run 安装计划预览；
- **PIE 支持**：信息条直接标记 PIE；修复 free 在 PIE 下自动改用 rel32 call（随加载基址平移依然正确）；
- **环境检查**：帮助菜单内置 doctor；
- **沙箱页保留双重确认**：警告全文展示 + 显式勾选风险确认后按钮才可用。

## 子命令用法

### info —— 查看二进制基本信息

```bash
mistyfix info ./vuln
```

打印架构（amd64/i386）、入口地址、节列表（vaddr/size/offset）以及默认大小（≥32 字节）的可用 cave 列表。

### caves —— 列出可用 code cave

```bash
mistyfix caves ./vuln
mistyfix caves ./vuln --min-size 64
```

在可执行段的现有空隙中查找连续 `0x00`/`0x90` 区域，优先 `.eh_frame`，输出所在节、vaddr、文件偏移与大小。

### fix-read —— 修复 read 长度（栈溢出等）

```bash
mistyfix fix-read ./vuln 0x4011a3 0x100 -o ./vuln.fix
```

定位 `call_vaddr` 处的 `call read@plt`，将长度参数立即数等长替换为 `new_len`。

### fix-free —— 真修复 UAF / Double-Free

```bash
mistyfix fix-free ./vuln 0x4012c0 -o ./vuln.fix
mistyfix fix-free ./vuln 0x4012c0 --ptr 0x404060 -o ./vuln.fix
```

对 `call free@plt` 做真修复（free 后置空指针），**不是 NOP**，可通过平台的 NOP 特征检测。

### rename —— .dynstr 符号改名

```bash
mistyfix rename ./vuln -o ./vuln.fix            # 默认 free -> atoi
mistyfix rename ./vuln --old system --new atoi -o ./vuln.fix
```

等长改写 `.dynstr` 中的符号名（要求新旧名字等长），将危险函数替换为无害函数，改数据不改控制流。

### check —— 合规性对比

```bash
mistyfix check ./vuln ./vuln.fix
```

运行 `ComplianceChecker.run_all()`，逐条打印 PASS/FAIL 与细节（文件大小、节结构、`.got.plt`、`_start`、`.eh_frame` 特征码、NOP free 特征等）。任一项失败时退出码为 1。

### test —— 功能交互回归

```bash
mistyfix test ./vuln.fix --script my_check.py
```

`--script` 指定一个用 `subprocess` 与程序交互的 Python 代码片段，验证正常业务流程未被破坏。测试失败时退出码为 1。

### sandbox —— 安装 seccomp 沙箱 stub（规则敏感）

```bash
mistyfix sandbox ./vuln -o ./vuln.sandbox --i-know-the-risk            # 白名单（默认）
mistyfix sandbox ./vuln -o out --mode blacklist --i-know-the-risk      # 黑名单（命中即杀）
mistyfix sandbox ./vuln --mode blacklist --dry-run                     # 只看安装计划，无需确认
```

三种模式（黑名单/strict 移植自前身项目）：`whitelist` 白名单（默认，其余 EPERM）、
`blacklist` 黑名单（`--blacklist execve,openat`，命中即 KILL_PROCESS，其余放行，
对正常功能破坏最小）、`strict` 内核严格模式（仅 read/write/exit）。

安装机制（v0.2.0 补全，前身项目移植）：自动选择落点与 hook——优先 code cave +
`.init_array[0]` 劫持（非 PIE，纯数据修改）；PIE 用 `e_entry` 劫持（`.init_array`
会被 RELATIVE 重定位覆盖）；无 cave 时段尾 padding 注入并扩容 `p_filesz/p_memsz`
（会改 16 字节段头，仅在无 cave 时使用）。stub 以跳回原初始化函数/原入口收尾，
prctl 特征码同样做混淆规避。**此功能仅供学习研究，在正式比赛中使用通防属于违规行为，详见下方警告。**

### patch —— 通用 trampoline 补丁（前身项目移植）

```bash
mistyfix patch ./vuln 0x40123a 5058 -o ./vuln.patched        # 按 vaddr
mistyfix patch ./vuln 0x123a 5058 --offset-mode -o out       # 按文件偏移
mistyfix patch ./vuln 0x40123a "50 58" --dry-run             # 只看计划
```

在任意地址插入任意机器码：hook 点跳入 cave → 先执行插入代码 → 重放被覆盖的
原指令 → 跳回。被覆盖指令含 RIP 相对寻址时会被拒绝（照搬会错位，前身项目的
安全检查）。等长、不改节表、不碰 GOT/_start。

### doctor —— 环境检查

```bash
mistyfix doctor
```

检查 Python 版本、lief/capstone/keystone 必需依赖、pwntools/tkinter 可选依赖、
Linux 运行能力（功能测试/exp 复验需 Linux 实际运行 ELF）。

### exp —— 生成 pwntools EXP 模板（AWD 攻击侧）

```bash
mistyfix exp ./vuln -o exp.py
python exp.py [host port]     # 无参数走本地 process
```

前身项目模板的升级版：本地/远程自适应、自动尝试 `cat /flag` 并输出
`FOUND FLAG: ` 关键字（与 batch 命令联动）。

### batch —— 批量攻击（AWD 攻击侧）

```bash
mistyfix batch --hosts 10.1.1.1,10.1.1.2 --ports 9999,8888 --exp exp.py -o flags.txt
```

对 hosts × ports 组合逐一调用 exp 脚本，输出命中 `--keyword`（默认 `FOUND FLAG: `）
的行并追加写入 `flags.txt`（前身 8 号脚本的参数化版本）。

### traffic —— 流量镜像（前身项目移植，传统 AWD 赛制）

```bash
# 1. 先开接收端
python -m mistyfix.traffic receiver --listen-port 9001
# 2. 再给 ELF 注入流量镜像（hook read/write/gets/printf@plt，镜像到收集端）
python -m mistyfix.traffic patch ./pwn ./pwn.traffic --collector-ip 127.0.0.1 --collector-port 9001
```

防守方捕获交互流量用于取证/重放分析。注意：改写了 PLT 与入口，
**不能**作为 AWDP fix 产物提交（合规检测会命中）。

每个 fix 类命令（fix-read / fix-free / rename / patch / sandbox）成功后会打印 `PatchPlan` 的 `description` 与 `changes` 列表，并自动对原文件与产物跑一次 `ComplianceChecker` 提示合规性。

## 合规警告

> **禁止使用本工具或任何"通防"（通用 seccomp 沙箱）手段在比赛中作弊。**
>
> - AWDP 平台会在 `.eh_frame` 等区域扫描 prctl/seccomp 特征码（amd64: `B0 9D 0F 05`；i386: `B0 AC CD 80`），简单注入立刻会被判负；
> - 即便做了特征混淆，**运行时行为检测无法隐藏**——沙箱对 syscall 的拦截会改变程序在正常业务流和 exp 下的行为，功能 check 与 exp 复验阶段照样暴露；
> - 使用通防属于违反比赛规则的行为，可能导致扣分、判负或取消成绩。
>
> 本工具的正当用途是：**针对具体漏洞做精准、等长、不改变正常功能的修复**，以及帮助**出题方完善 checker**（验证各项检测手段是否能识别假修复与违规通防）。`sandbox` 子命令仅为研究检测与反检测机制而保留，默认拒绝执行，必须显式确认风险。

## 项目结构

```
mistyfix/
├── __init__.py      # 包入口，暴露核心符号
├── __main__.py      # python -m mistyfix
├── cli.py           # argparse 命令行
├── gui.py           # tkinter 图形界面（mistyfix gui / mistyfix-gui）
├── elf_utils.py     # ELF 解析、cave 查找、地址换算、PIE/init_array/RELA 查询
├── patcher.py       # keystone/capstone 汇编反汇编、等长 patch、trampoline（RIP 检查）
├── strategies.py    # 修复策略（fix-read / fix-free（含 PIE）/ rename / 整数比较）
├── checker.py       # 合规检测、功能测试、exp 复验
├── injector.py      # stub 安装器（cave/init_array/e_entry/段尾兜底，前身移植）
├── sandbox.py       # seccomp stub 生成（白/黑名单 + strict，带规则警告）
└── traffic.py       # 流量镜像 patch + receiver（前身项目移植，自包含）

tests/
├── smoke_test.py    # CLI/核心逻辑冒烟测试
├── gui_smoke.py     # GUI 自动化冒烟测试（拦截弹窗，可直接跑）
├── vuln             # 测试样例（栈溢出 + UAF/double-free）
└── vuln_pie         # PIE 测试样例（gcc -pie 编译）
```
