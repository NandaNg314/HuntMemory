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
