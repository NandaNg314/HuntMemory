## v1.2.1 新增与修复 (子线程枚举、动态寄存器改写与 KPM 内核伴侣模块修复)

这个版本带来了第 **29、30 个** MCP 原生工具，并将伴侣内核模块完全对齐 KernelPatch 规范：

### 1. 枚举进程子线程（`list_threads`，第 29 个工具）
- **子线程一览无余**：自动遍历 `/proc/<pid>/task/`，提取所有子线程的 TID、线程名（`comm`，如 `UnityMain`、`RenderThread`、`Jit thread pool`）与运行状态（`state`）。
- **精准狙击游戏主逻辑**：彻底解决多线程游戏（Unity、Unreal）难以确定游戏主循环 TID 的痛点，便于后续针对性挂起、单步或设置断点。

### 2. 动态改写寄存器（`set_register`，第 30 个工具）
- **任意寄存器热改写**：在线程被挂起或单步执行时，直接修改 `PC`、`SP`、`LR`、`FP`、`X0`~`X30`、`W0`~`W30` 或 `PSTATE`。
- **劫持执行流与返回值**：直接修改 `X0` 伪造函数返回结果（绕过校验），或修改 `PC` 强制跳转指定汇编逻辑。

### 3. KernelPatch 伴侣模块重构与 APatch 加载修复 (`companion_kpm/hm_hwbp.kpm`)
- **根治 APatch 加载 -1 报错**：排查内核日志精确定位 `overflow in relocation type 261 val ...` 错误，禁用 unwinding 表并彻底剔除 `.eh_frame`，根除 ARM64 `R_AARCH64_PREL32` 32位相对寻址溢出。
- **对齐 KernelPatch ABI 规范**：使用规范的 `KPM_INIT`、`KPM_CTL0`、`KPM_EXIT` 宏和 `hook_fargs3_t` 系统调用短路回调，支持在 APatch 中平滑加载。

---

## v1.2.0 新增了什么 (ARM64 硬件断点/数据断点与线程单步控制)

这个版本带来了第 **25 ~ 28 个** MCP 原生工具，构筑了完整的 ARM64 硬件级逆向与动态调试能力：

### 1. 硬件断点与数据观察点（`trace_watchpoint`，第 25 个工具）
直接利用骁龙 8 Gen 3 等 ARM64 芯片底层的调试寄存器（`DBGBVR`/`DBGBCR` 指令执行断点，`DBGWVR`/`DBGWCR` 数据读写观察点）：
- **设/清硬件断点**：支持对指令地址（`type="exec"`）或数据变量（`type="write"|"read"|"access"`）布设断点；监控结束后自动清理硬件寄存器并恢复目标执行。
- **现场完整寄存器快照**：断点命中时自动捕获 `PC`、`SP`、`LR`、`FP`、`PSTATE` 以及通用寄存器 `X0 ~ X30`。
- **调用栈回溯（Call Stack Unwinding）**：自动解析调用方 `LR`，并基于 ARM64 AAPCS-64 帧指针（`X29`/`FP`）递归回溯函数调用链（提取每一帧的 `frame`、`pc`、`module` 与 `rva` 偏移）。
- **指令反汇编解码**：AArch64 原生反汇编，实时反解如 `STR W0, [X19, #0x28]`、`LDP X29, X30, [SP]` 等。

### 2. 线程停止与恢复（`thread_suspend` / `thread_resume`，第 26、27 个工具）
- **按线程粒度暂停/恢复**：支持针对特定 TID（或整个进程）执行挂起与恢复控制。
- **现场寄存器与调用链查看**：挂起瞬间即可直接读取目标线程的 PC、全套寄存器与调用栈，便于现场分析。

### 3. 单步步进控制（`thread_step`，第 28 个工具）
- **指令级单步执行**：对挂起的目标线程执行指定数量（`steps`）的单步步进。
- **轨迹记录**：记录每一步执行的 PC、反汇编指令、模块 RVA 以及关键寄存器的即时变化。

### 4. 双引擎架构（Dual Engine）
- **引擎 A（KernelPatch 伴侣驱动 `hm_hwbp.kpm`）**：针对 APatch 环境，通过独立系统调用通道静默下发断点并接管调试异常，目标应用零感知运行（无 TracerPid、无信号投递）。
- **引擎 B（原生硬件调试调试器）**：在未加载内核伴侣模块时自动激活，基于 Linux ARM64 原生调试寄存器全自动完成多线程挂载、命中捕获与单步步过，即开即用。

---

## v1.1.1 修复了什么 (MilkCode / SSE 客户端兼容性修复)

这个补丁版本修复了 MilkCode 与 Operit 等客户端在平板端直连时的协议兼容性问题：

1. **修复 MilkCode 客户端报错「MCP 响应 id 不匹配」**
   - 之前服务端对根路径 `/` 的 GET/POST 未做区分，将健康检查 JSON 返回给了客户端的 JSON-RPC 初始化请求，导致客户端因为返回缺少匹配的 `id` 而抛出「响应 id 不匹配」。
   - 现在健康检查严格限定在 `GET /health` 或 `GET /`；`POST /` 与 `POST /mcp` 统一无缝转发至 MCP Streamable HTTP 引擎。

2. **修复标准 HTTP 客户端 406 Not Acceptable**
   - 部分客户端在请求 MCP 时仅携带 `Accept: application/json`，Streamable HTTP 规范强校验 `application/json, text/event-stream` 导致返回 406 且 `id: null`。
   - 服务端在进入 Streamable HTTP 传输层前自动补齐兼容媒体协商头部，保证通用客户端正常调用。

3. **修复 SSE 模式无限递归崩溃与连接中断**
   - 移除 `index.js` 中重复调用的 `sseTransport.start()`（`server.connect()` 内部已自动启动）。
   - 修复 `sseTransport.onclose` 回调中重入调用 `server.close()` 触发的 `RangeError: Maximum call stack size exceeded` 栈溢出崩溃。

---

## v1.1.0 新增了什么

这个小版本把工具从 16 个扩到 **24 个**，并加入了脚本能力。

**Lua 脚本（`run_lua`，第 24 个工具）**

一次调用就能完成「扫描 → 过滤 → 确认 → 写值 → 复查」多步操作，不再为每一步付一次往返。脚本**在目标进程之外**运行（不是注入），只通过 `hm.*` 访问内存：

```lua
local hits = hm.scan("i32", 100, { perms = "rw-p" })
hm.sleep(500)
local keep = {}
for _, h in ipairs(hits) do
  local v = hm.read(h.addr, "i32")
  if v and v ~= 100 then keep[#keep + 1] = h.addr end
end
for _, a in ipairs(keep) do hm.write(a, "i32", 999) end
return #hits, #keep
```

可用：`hm.read` / `hm.write` / `hm.read_bytes` / `hm.write_bytes` / `hm.chain`（多级指针链）/ `hm.scan` / `hm.freeze` / `hm.unfreeze` / `hm.module` / `hm.map` / `hm.b64` / `hm.log` / `hm.sleep`。

Lua 5.4.7 已静态编译进 `hmkpm_cli`，平板上不需要另装解释器，产物仍是单个自包含二进制。

**安全边界**：脚本只有 `string` / `table` / `math` / `utf8`，没有 `io` / `os` / `require` / `dofile` / `load` / `string.dump`，无法自行读写文件或启动进程。超过 `timeoutS`（默认 30 秒）会被强制中断，响应带 `timed_out: true`——用 `pcall` 包住死循环也一样。

**注意 `limit`**：省略时返回全部命中。显式传很小的 `limit` 会让内核提前停止扫描而漏报（实测 `limit=2048` 只报 1050 条），要完整结果就不要设置它。

## v1.1.0 之前加入的 7 个工具

| 工具 | 用途 |
|---|---|
| `pointer_chain` | 多级指针链 `base+rva -> [off1] -> [off2] -> ...`，一次解析到底；失败会告诉你断在第几步 |
| `freeze_value` / `unfreeze_value` / `list_freezes` | 冻结某个地址的值，由独立守护进程持续回写。覆写后能抢回来，解除后立刻停止 |
| `dump_memory` | 把内存或整个模块导出到文件，附带 `.txt` 映射表（文件偏移 ↔ 地址 ↔ 权限），可直接拖进 IDA / Ghidra |
| `scan_rva` | 在单个模块内搜索，**结果以模块偏移（RVA）输出**，跨重启有效 |
| `find_instructions` | ARM64 指令搜索，支持掩码通配（如 `B9000000/FFF00000` 匹配任意寄存器的 STR），用来定位「谁在写这个字段」 |

## 本版本修复了什么

这个版本修掉了一条会让人误以为「工具坏了」的链路问题：

**平板端（重点）**
- 开机自启脚本现在用 Termux Node 的**绝对路径**启动。此前直接调用 `node`，而开机服务的 `PATH` 里没有 Termux，日志里只留下一行 `node: not found`，服务从未真正起来。
- `start_tablet.sh` 会设置 `TMPDIR`、加上单实例保护，并提供 `/data/local/tmp/hmkpm_mcp.disabled` 开关。

**helper（`hmkpm_cli`）**
- `scan_seed` 之前对每个命中地址单独读一次，而单地址读取在部分页面上会返回 `EFAULT`，导致种子几乎全被丢弃 → 现在直接以内核命中表作为基线。
- 进程映射数过多时（例如 systemui 约 6400 个 map），内核扫描会返回 `E2BIG`，`scan_seed` 之前直接报错 → 现在自动回退到用户态精确扫描。
- `scan_filter` 之前对每个候选地址发一次 syscall，百万级候选下像是卡死 → 现在批量读取，并返回 `scanned` / `readable` 便于判断结果为空的原因。
- `scan_unknown` 遇到单个坏页会丢掉整段 1 MiB → 现在逐页重试。

**构建**
- aarch64 helper 改为**静态链接**。su / magisk 域读不到 Termux 的分类化依赖库，动态版无法从 `/data/local/tmp` 启动。CI 现在会校验 `DT_NEEDED`，防止这个问题回归。

## 下载内容

| 文件 | 用途 |
|---|---|
| `hmkpm_cli` | 静态链接的 aarch64 helper，放到 `/data/local/tmp/` |
| `hmkpm-mcp-server.zip` | MCP Server 源码与 `package.json` |
| `start_tablet.sh` | 平板启动脚本（含路径与环境变量处理） |
| `service_boot.sh` | 开机自启脚本，安装为 `/data/adb/service.d/hmkpm_mcp.sh` |

## 部署到平板

```bash
adb push hmkpm_cli /data/local/tmp/hmkpm_cli
adb push start_tablet.sh /data/local/tmp/start_tablet.sh
adb push service_boot.sh /data/local/tmp/hmkpm_mcp.sh
adb shell "chmod 755 /data/local/tmp/hmkpm_cli /data/local/tmp/start_tablet.sh /data/local/tmp/hmkpm_mcp.sh"

# MCP Server
adb shell "mkdir -p /data/local/tmp/hmkpm-mcp"
unzip hmkpm-mcp-server.zip -d /tmp/x
adb push /tmp/x/hmkpm-mcp/. /data/local/tmp/hmkpm-mcp/
adb shell "su -c 'cd /data/local/tmp/hmkpm-mcp && npm install --omit=dev'"

# 开机自启
adb shell "su -c 'cp /data/local/tmp/hmkpm_mcp.sh /data/adb/service.d/ && chmod 755 /data/adb/service.d/hmkpm_mcp.sh'"

# 立即启动
adb shell "su -c '/data/local/tmp/start_tablet.sh'"
adb shell "curl -s http://127.0.0.1:8799/health"
```

## 连接方式

支持两种传输：

- **SSE**：`http://127.0.0.1:8799/sse`
- **Streamable HTTP**：`http://127.0.0.1:8799/mcp`

> `hmkpm-mcp-server.zip` **不含 `node_modules`**，需要在平板上执行一次 `npm install`。

## 环境要求

- ARM64 Android 设备，已通过 APatch / KernelSU / Magisk 获得 root
- 已加载 HMKPM 内核模块（版本 2.8.0 已测）
- 平板自带运行需要 Termux 提供 Node.js（`/data/data/com.termux/files/usr/bin/node`）
