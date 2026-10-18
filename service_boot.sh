#!/system/bin/sh
# Auto-start the HMKPM MCP Server on tablet boot.
#
# Install as /data/adb/service.d/hmkpm_mcp.sh (APatch / KernelSU / Magisk) with
# mode 755, then reboot. All the PATH/TMPDIR/TERMUX_PREFIX juggling lives in
# start_tablet.sh; this file only waits for boot and makes sure the kernel
# module is loaded first.

LOG=/data/local/tmp/mcp.log

# Wait until Android boot completed
i=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ $i -lt 120 ]; do
    sleep 2
    i=$((i + 1))
done

# Ensure the KPM kernel module is loaded
if ! /data/local/tmp/hmkpm_cli probe >/dev/null 2>&1; then
    if [ -f /data/local/tmp/hmkpm.kpm ] && [ -x /data/adb/ap/bin/apd ]; then
        /data/adb/ap/bin/apd insmod /data/local/tmp/hmkpm.kpm >> "$LOG" 2>&1
    fi
fi

# Start the MCP server on 0.0.0.0:8799 (SSE for Operit, /mcp for HTTP clients)
exec /data/local/tmp/start_tablet.sh
