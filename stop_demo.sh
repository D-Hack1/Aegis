#!/usr/bin/env bash
# Aegis — stop everything start_demo.sh started.
#
# Usage:
#   ./stop_demo.sh          # stop the python/node processes and tcpdump,
#                            # leave the Docker lab running (fine overnight)
#   ./stop_demo.sh --down   # also docker compose down -v (deletes lab state)

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

RUN_DIR="logs/run"
PID_FILE="$RUN_DIR/pids"

echo "== Stopping python/node services =="
if [[ -f "$PID_FILE" ]]; then
    while IFS=: read -r name pid; do
        [[ -z "$pid" ]] && continue
        if kill -0 "$pid" 2>/dev/null; then
            # npm spawns a vite child that outlives the parent if we only
            # kill the recorded PID — kill children first, then the parent.
            pkill -P "$pid" 2>/dev/null
            kill "$pid" 2>/dev/null
            echo "  stopped $name (pid $pid)"
        fi
    done < "$PID_FILE"
    : > "$PID_FILE"
else
    echo "  no pid file found — nothing to stop"
fi

# Belt-and-suspenders: catch a dashboard vite process even if the recorded
# PID was stale (npm's PID can drift from what $! captured through nohup).
pkill -f "dashboard/node_modules/.bin/vite" 2>/dev/null && echo "  stopped stray vite process"
true

echo "== Stopping tcpdump on victim =="
docker exec victim python3 -c "
import os, signal
for p in os.listdir('/proc'):
    if p.isdigit():
        try:
            with open(f'/proc/{p}/comm') as f:
                if f.read().strip() == 'tcpdump':
                    os.kill(int(p), signal.SIGTERM)
        except Exception:
            pass
" 2>/dev/null || true

if [[ "${1:-}" == "--down" ]]; then
    echo "== Tearing down Docker lab (docker compose down -v) =="
    make down
else
    echo "== Docker lab left running (use --down to also tear it down) =="
fi

echo "Done."
