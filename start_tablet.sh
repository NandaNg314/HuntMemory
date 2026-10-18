#!/system/bin/sh
# Start the HMKPM MCP Server on the tablet (HTTP / SSE mode for Operit).
#
# Runs as root (from /data/adb/service.d on boot, or manually with
# `su -c /data/local/tmp/start_tablet.sh`). Node.js comes from Termux, whose
# binaries are not on the Android system PATH, but Node does **not** need
# Termux's LD_LIBRARY_PATH — adding it would shadow Android's libc and break
# process spawning. TMPDIR points at /data/local/tmp because Termux's own tmp
# directory is not reachable from the root service context.
#
# Kill switch: /data/local/tmp/hmkpm_mcp.disabled -> the server will not start.
# Overrides: HMKPM_NODE, HMKPM_PORT, HMKPM_HOME, HMKPM_CLI, HMKPM_LOG.

TERMUX_PREFIX=${TERMUX_PREFIX:-/data/data/com.termux/files/usr}
NODE=${HMKPM_NODE:-$TERMUX_PREFIX/bin/node}
PORT=${HMKPM_PORT:-8799}
HOME_DIR=${HMKPM_HOME:-/data/local/tmp/hmkpm-mcp}
CLI=${HMKPM_CLI:-/data/local/tmp/hmkpm_cli}
LOG=${HMKPM_LOG:-/data/local/tmp/mcp.log}
PIDFILE=/data/local/tmp/hmkpm-mcp.pid

[ -f /data/local/tmp/hmkpm_mcp.disabled ] && exit 0

if [ ! -x "$NODE" ]; then
    echo "[hmkpm-mcp] node not found at $NODE" >> "$LOG"
    exit 1
fi
if [ ! -f "$HOME_DIR/index.js" ]; then
    echo "[hmkpm-mcp] missing $HOME_DIR/index.js" >> "$LOG"
    exit 1
fi

# Single instance guard
if [ -f "$PIDFILE" ]; then
    OLD=$(cat "$PIDFILE" 2>/dev/null)
    if [ -n "$OLD" ] && kill -0 "$OLD" 2>/dev/null; then
        echo "[hmkpm-mcp] already running (pid $OLD)" >> "$LOG"
        exit 0
    fi
fi

export TERMUX_PREFIX
export TMPDIR=/data/local/tmp
export HOME=${HOME:-/data/local/tmp}
export PATH="$TERMUX_PREFIX/bin:/system/bin:/system/xbin"
export HMKPM_CLI="$CLI"
export HMKPM_NODE="$NODE"
export HMKPM_SU=/system/bin/su
export LOCAL_ANDROID=1
unset LD_LIBRARY_PATH LD_PRELOAD

cd "$HOME_DIR" || exit 1
echo "[hmkpm-mcp] starting on port $PORT ($(date))" >> "$LOG"
"$NODE" index.js --http --host 0.0.0.0 --port "$PORT" >> "$LOG" 2>&1 &
echo $! > "$PIDFILE"
