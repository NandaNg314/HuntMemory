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
