# hmkpm-mcp

> **双端通吃**的 KernelPatch (HMKPM) 内存调试与分析 MCP 服务器。
> 既支持**平板单端完全独立运行**（Operit 本机 127.0.0.1 直连，完全脱离电脑），也支持**电脑远程调试**（OpenCode / Claude Desktop 通过 ADB 通信）。

---

## 目录结构

```
hmkpm-mcp/
├── helper/              # 平板端原生执行核心 (C语言，极致性能与轻量)
│   ├── hmkpm_cli.c      # 直接发 getresuid(0x484D4B504D...) 的 native 程序
│   ├── Makefile         # 用平板上的 clang 或电脑 NDK 编译为 arm64 ELF
│   └── hmkpm_cli        # 已编译的 arm64-v8a 原生可执行文件
│
├── mcp-server/          # MCP 协议层 (Node.js ESM)
│   ├── package.json     # 依赖 @modelcontextprotocol/sdk
│   ├── index.js         # 双模运行入口 (stdio 模式 & HTTP/SSE 模式)
│   ├── server.js        # MCP Server 与工具注册定义
│   ├── tools.js         # 工具业务实现 (数据打包、类型转换、UTF-8解析)
│   ├── device.js        # 适配层 (支持电脑 ADB 远程调用与安卓 Termux 本地直接调用)
│   └── test-client.mjs  # 自动化测试套件
│
├── start_tablet.sh      # 平板单端一键启动脚本
└── service_boot.sh      # APatch / KernelSU 开机自动后台启动脚本
```

---

## 提供的 MCP 工具列表

| 工具名称 | 功能描述 | 核心参数 |
|---|---|---|
| `hmkpm_probe` | 检查 KPM 内核模块加载状态、版本、mmap 偏移与特性掩码 | 无 |
| `list_processes` | 枚举正在运行的游戏与应用进程（过滤常用包名、PID） | `filter` (可选，字符串或PID) |
| `list_maps` | 读取目标进程 `/proc/<pid>/maps` 内存映射段 | `pid`, `filter` (可选模块名) |
| `read_memory` | 读取指定内存地址的原始数据（返回 Hex、ASCII 与 UTF-8） | `pid`, `address`, `size` |
| `read_value` | 按指定类型读取单个数值 (`i8`~`i64`, `u8`~`u64`, `f32`, `f64`) | `pid`, `address`, `type` |
| `write_memory` | 向目标内存地址写入原始十六进制字节 | `pid`, `address`, `hex_data` |
| `write_value` | 按指定类型修改数值（金币、血量、浮点坐标等） | `pid`, `address`, `type`, `value` |
| `scan_kernel` | **内核空间 NEON SIMD 极速数值搜索** (HMKPM_MAGIC_SCAN_KERNEL) | `pid`, `value`, `type`, `align`, `perms` |
| `scan_seed` | **模糊搜索第一步（快）**：先把精确值命中写进会话，再配合 `scan_filter` 收敛 | `pid`, `value`, `type`, `align`, `perms` |
| `scan_unknown` | 模糊搜索第一步（慢）：快照所有对齐槽位（结果可能被 `SESSION_MAX` 截断） | `pid`, `type`, `align`, `perms` |
| `scan_filter` | 后续轮次：按 `changed/unchanged/increased/decreased/eq/ne/gt/lt/range` 收敛候选 | `pid`, `type`, `mode`, `value` |
| `scan_results` / `scan_reset` | 列出剩余候选地址（上限 4096）/ 删除会话 | `pid`, `type` |
| `read_values` | **批量读值**：一次调用读多个地址，每个地址带 `readable` 标志，用于筛完候选后快速查看 | `pid`, `addresses`, `type` |
| `find_string` | 字面量字符串搜索（配置键、URL、JSON 片段），用于从字符串反查数据结构 | `pid`, `pattern`, `perms`, `limit` |
| `module_base` | 模块加载基址 + 可选 RVA，并返回模块结束地址与 VMA 数量 | `pid`, `module`, `rva` |
| `pointer_chain` | **多级指针链解析**：`base+rva -> [off1] -> [off2] -> ...`，最后一段偏移不解析、直接作为字段地址。基址可直接写模块名，重启后依然有效 | `pid`, `base`, `rva`, `offsets`, `type` |
| `freeze_value` | **数值冻结**：让守护进程持续回写指定地址，应用覆写不掉。不传 `addresses` 时冻结当前扫描会话的全部幸存地址 | `pid`, `type`, `value`, `addresses`, `intervalMs` |
| `unfreeze_value` | 解除冻结（不传地址则全部解除，守护进程退出） | `pid`, `addresses` |
| `list_freezes` | 查看已冻结地址、写入的字节与守护进程存活状态 | `pid` |
| `dump_memory` | **内存/模块导出到文件**：流式写盘，附带 `.txt` 映射表（文件偏移 ↔ 地址 ↔ 权限），可直接导入 IDA/Ghidra | `pid`, `target`, `size`, `outPath`, `perms` |
| `scan_rva` | **模块内搜索，输出 RVA**：结果以模块偏移表示，跨重启有效 | `pid`, `module`, `value`, `type`, `align` |
| `find_instructions` | **ARM64 指令搜索**：支持掩码通配，例如 `B9000000/FFF00000` 匹配任意寄存器的 32 位 STR；结果带模块名与 RVA | `pid`, `pattern`, `where`, `limit` |
| `run_lua` | **Lua 脚本批量操作**：一次调用内完成「扫描 → 过滤 → 确认 → 写值 → 复查」多步操作，省掉每步一个来回 | `pid`, `script`, `timeoutS` |
| `trace_watchpoint` | **ARM64 硬件断点与数据观察点**：直接利用芯片底层的 `DBGBVR`/`DBGBCR`（执行断点）与 `DBGWVR`/`DBGWCR`（数据读写）监控任意指令与变量，自动捕获触发指令反汇编、调用方 LR、AAPCS-64 完整回溯调用栈、模块与 RVA 偏移及全套寄存器快照（PC, SP, LR, FP, X0-X30, PSTATE） | `pid`, `address`, `size`, `type` (`write`/`read`/`access`/`exec`), `durationMs`, `maxHits` |
| `thread_suspend` | **挂起目标线程或进程**：暂停目标指定线程（或主线程），现场抓取当前 PC、LR、全套通用寄存器（X0-X30, SP, FP）与调用栈回溯 | `pid`, `tid` |
| `thread_resume` | **恢复目标线程或进程**：恢复之前暂停的目标线程或整个进程执行 | `pid`, `tid` |
| `thread_step` | **单步控制执行**：对挂起线程执行 N 条指令单步步进，记录每步的 PC、反汇编指令与关键寄存器变化 | `pid`, `tid`, `steps` |
| `list_threads` | **枚举进程子线程**：列出目标进程所有子线程的 TID、线程名（`comm`，如 `UnityMain`、`RenderThread`）与运行状态（`state`） | `pid` |
| `set_register` | **动态改写寄存器**：在挂起或单步状态下直接改写通用寄存器或 PC（如伪造返回值 `X0`、跳转指定指令 `PC`） | `pid`, `tid`, `reg`, `value` |

### Lua 脚本（`run_lua`）

脚本**在目标进程之外**运行（不是注入），只通过 `hm.*` 访问目标内存。适合把固定流程固化成一次调用：

```lua
-- 找到血量字段：扫描 -> 只保留变化过的 -> 改成 999
local hits = hm.scan("i32", 100, { perms = "rw-p" })
hm.log("初筛命中", #hits)
hm.sleep(500)
local keep = {}
for _, h in ipairs(hits) do
  local v = hm.read(h.addr, "i32")
  if v and v ~= 100 then keep[#keep + 1] = h.addr end
end
hm.log("收敛后", #keep)
for _, a in ipairs(keep) do hm.write(a, "i32", 999) end
return #hits, #keep
```

可用 API：

| 函数 | 说明 |
| --- | --- |
| `hm.pid` | 当前目标 pid |
| `hm.read(addr, type)` | 读值，失败返回 `nil, errno` |
| `hm.write(addr, type, value)` | 写值，成功返回 `true` |
| `hm.read_bytes(addr, n)` / `hm.write_bytes(addr, str)` | 原始字节读写。`read_bytes` 返回 `字符串[, 缺失字节数]`：完全读不到时返回 `nil, errno`；部分页不可读时仍返回缓冲区，第二个值告诉你有多少字节是零填充的空洞 |
| `hm.chain(base_or_module, rva, {off1, off2, ...})` | 多级指针链，末段偏移不解析；失败返回 `nil, 第几步` |
| `hm.scan(type, value, {align, perms, module, limit})` | 搜索，返回 `{{addr=..., value=...}, ...}` |
| `hm.freeze(addr_list, type, value, interval_ms)` / `hm.unfreeze()` | 冻结/解除，与 `freeze_value` 共用同一个守护进程 |
| `hm.module(name)` | `{base, stop, vmas}` |
| `hm.map(path_filter)` | VMA 列表 |
| `hm.b64(data)` / `hm.log(...)` / `hm.sleep(ms)` | 编码、日志（进 `log` 字段）、等待 |

约束：可用标准库仅 `string` / `table` / `math` / `utf8`；**没有** `io` / `os` / `require` / `dofile` / `load` / `string.dump`，脚本无法自行读写文件或启动进程。脚本超过 `timeoutS`（默认 30 秒）会被中断，响应里带 `timed_out: true`——即使脚本用 `pcall` 包住了死循环也一样。

关于 `limit`：省略时返回全部命中。**显式传一个很小的 limit 会让内核提前停止扫描而漏报**（实测 limit=2048 只报 1050 条），需要全部结果时不要设置它。

### 典型工作流

```
list_processes                      -> 拿到 pid
scan_seed    i32=100                -> 初筛（约 0.2s）
scan_filter  changed                -> 数值变化后收敛
scan_filter  eq 200                 -> 再收敛
read_values  剩下的地址             -> 逐个确认当前值
write_value / freeze_value          -> 改值，或冻结让值稳定
```

原生（C++/Unity）应用的稳定定位方式：

```
module_base  libil2cpp.so                -> 拿基址
pointer_chain libil2cpp.so 0x1A2B3C0 [0x18, 0x20, 0x8]
                                         -> 一次解析整条链，重启后只需重跑
dump_memory  libil2cpp.so -> /sdcard/lib.so
find_instructions B9000000/FFF00000
                                         -> 找到写该字段的指令，定位更新函数
```

把上面几步固化成脚本，以后一次调用完成：

```
run_lua  <pid>  <脚本：module 取基址 -> chain 解析 -> read 确认 -> write 改值>
```

**关于冻结**：`freeze_value` 会启动一个独立守护进程（同一二进制 `_freeze_daemon`），在设备上持续回写。实测每 50ms 回写一次时 CPU 占用约 0.4% 单核。目标进程退出或执行 `unfreeze_value` 后守护进程自动结束，不会残留。

---

## 核心使用场景

### 场景一：平板单端完全独立运行（脱离电脑，给 Operit 使用）

整个 MCP Server 与核心执行程序已完整部署在平板 `/data/local/tmp/` 并在 Termux Node.js 环境中原生运行，**完全不需要连接电脑**！

#### 1. 开机自启（已配置好）
我们已将开机服务脚本部署至 APatch 的开机脚本目录：
`/data/adb/service.d/hmkpm_mcp.sh`
* 平板每次开机后，会自动检查并加载 `hmkpm.kpm` 驱动，并在后台自动拉起 MCP Server，监听 `http://0.0.0.0:8799`。
* 开机服务的 `PATH` 里**没有** Termux，所以启动脚本必须用绝对路径调用 Node：
  `/data/data/com.termux/files/usr/bin/node`（脚本 `start_tablet.sh` 已内置，可用 `HMKPM_NODE` 覆盖）。
  旧版本脚本用 `node index.js` 直接启动，日志里只会留下 `node: not found`，服务永远起不来。
* 排障看 `/data/local/tmp/mcp.log`；想临时禁用自启，`touch /data/local/tmp/hmkpm_mcp.disabled`。

#### 2. 手动启动/重启（若需要）
在平板 Termux 或 Root 终端中直接执行：
```bash
su -c '/data/local/tmp/start_tablet.sh'
# 已经在跑时会直接返回；要重启先 ps 找到 node 进程 kill 掉再执行
```

#### 2.1 重新部署（电脑端）
```bash
adb push helper/hmkpm_cli /data/local/tmp/hmkpm_cli
adb push mcp-server/server.js mcp-server/tools.js mcp-server/device.js mcp-server/test-client.mjs /data/local/tmp/hmkpm-mcp/
adb push start_tablet.sh /data/local/tmp/start_tablet.sh
adb push service_boot.sh /data/local/tmp/hmkpm_mcp.sh
adb shell "chmod 755 /data/local/tmp/hmkpm_cli /data/local/tmp/start_tablet.sh /data/local/tmp/hmkpm_mcp.sh"
adb shell "su -c 'cp /data/local/tmp/hmkpm_mcp.sh /data/adb/service.d/ && chmod 755 /data/adb/service.d/hmkpm_mcp.sh'"
```
> 注意：`adb push mcp-server /data/local/tmp/hmkpm-mcp` 会多套一层 `mcp-server/` 目录（服务器会加载旧文件），必须按上面逐个文件推送。

#### 2.2 自检
```bash
adb shell "curl -s http://127.0.0.1:8799/health"          # 健康检查
adb shell "su -c /data/local/tmp/run_suite.sh"            # 跑 mcp-server/test-client.mjs
```

#### 3. 平板端 Operit 连接配置
打开 Operit 的 **设置 -> MCP 服务器 -> 添加**：
* **协议类型**：`SSE`
* **URL 地址**：`http://127.0.0.1:8799/sse`
* **名称**：`hmkpm`

点击连接即可在平板上脱离电脑、单端使用！

---

### 场景二：电脑端通过 ADB 连接（OpenCode / Claude Desktop）

#### OpenCode 配置 (`~/.config/opencode/opencode.json`)
已默认配置并自动连接：
```json
{
  "mcp": {
    "hmkpm": {
      "type": "local",
      "command": ["node", "D:\\ai\\hmkpm-mcp\\mcp-server\\index.js"],
      "enabled": true
    }
  }
}
```

#### Claude Desktop 配置 (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "hmkpm": {
      "command": "node",
      "args": ["D:\\ai\\hmkpm-mcp\\mcp-server\\index.js"]
    }
  }
}
```

---

## 硬件断点内核伴侣模块 (`companion_kpm`)

在逆向具有强反作弊、反调试（如检测 `TracerPid != 0`）的目标进程时，可选用我们提供的内核伴侣驱动：
* **模块路径**：`companion_kpm/hm_hwbp.kpm`
* **安装方法**：直接在 **APatch 管理器 -> 模块 -> 加载 KPM 模块**，点选该文件刷入即可。
* **特性**：通过拦截系统调用 150 隐蔽投递断点事件，目标进程无感知运行。即使未刷入该 KPM，底层也会自动回退至 Linux 原生 ARM64 硬件调试引擎正常运作。
