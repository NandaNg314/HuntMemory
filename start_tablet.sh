#!/system/bin/sh
# Start HMKPM MCP Server on tablet (HTTP / SSE mode for Operit)
export PATH=/data/data/com.termux/files/usr/bin:$PATH
cd /data/local/tmp/hmkpm-mcp || exit 1
echo "[hmkpm-mcp] Starting tablet native MCP Server..."
exec node index.js --http --port 8799
