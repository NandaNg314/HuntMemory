#!/system/bin/sh
# Auto-start HMKPM MCP Server on tablet boot (for APatch / KernelSU service.d)

# Wait until Android boot completed
while [ "$(getprop sys.boot_completed)" != "1" ]; do
    sleep 2
done

# Ensure KPM kernel module is loaded
if ! /data/local/tmp/hmkpm_cli probe >/dev/null 2>&1; then
    if [ -f /data/local/tmp/hmkpm.kpm ] && [ -x /data/adb/ap/bin/apd ]; then
        /data/adb/ap/bin/apd insmod /data/local/tmp/hmkpm.kpm
    fi
fi

# Start native MCP Server in background
export PATH=/data/data/com.termux/files/usr/bin:$PATH
cd /data/local/tmp/hmkpm-mcp || exit 1
node index.js --http --port 8799 > /data/local/tmp/mcp.log 2>&1 &
