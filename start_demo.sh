#!/usr/bin/env bash
# Aegis — one-shot demo startup.
#
# Brings up the Docker lab, waits for Kafka/Elasticsearch to be healthy,
# creates the ES index (with the correct mapping — see demo.md's
# troubleshooting table for why that matters), starts tcpdump on the
# victim, and starts the watcher/producer, Kafka consumer, FastAPI
# backend, and dashboard — all using the project's .venv so we don't
# accidentally run against a different Python (see demo.md section 0).
#
# Logs go to ./logs/run/*.log. PIDs go to ./logs/run/pids so stop_demo.sh
# can clean up. Safe to re-run without calling stop_demo.sh first — it
# stops any pipeline/consumer/API/dashboard processes from a previous
# run before starting fresh ones (running this twice without that used
# to silently spawn a SECOND kafka.consumer fighting over the same
# consumer group, causing confusing duplicate/missing alert symptoms).
#
# Usage:
#   ./start_demo.sh          # start everything
#   ./start_demo.sh --clean  # also wipe stale zeek logs / features / ES alerts first

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
REPO_ROOT="$(pwd)"

RUN_DIR="$REPO_ROOT/logs/run"
PID_FILE="$RUN_DIR/pids"
VENV_PY="$REPO_ROOT/.venv/bin/python3"
VENV_UVICORN="$REPO_ROOT/.venv/bin/uvicorn"
CLEAN=false
[[ "${1:-}" == "--clean" ]] && CLEAN=true

mkdir -p "$RUN_DIR"
: > "$PID_FILE"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
warn() { echo -e "  ${YELLOW}!${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; }
step() { echo -e "\n== $1 =="; }

# ---------------------------------------------------------------------------
# Sanity checks
# ---------------------------------------------------------------------------
step "Sanity checks"

if [[ ! -x "$VENV_PY" ]]; then
    fail ".venv not found at $VENV_PY — create it first: python3.12 -m venv .venv && .venv/bin/pip install -r requirements.txt"
    exit 1
fi
ok ".venv found"

if ! docker info >/dev/null 2>&1; then
    fail "Docker daemon isn't reachable — is Docker running?"
    exit 1
fi
ok "Docker is up"

# ---------------------------------------------------------------------------
# Stop any leftover services from a previous run (idempotent re-run —
# see the header comment for why this matters).
# ---------------------------------------------------------------------------
if pgrep -f "run_pipeline.py|kafka\.consumer|uvicorn api.main|dashboard/node_modules/.bin/vite" >/dev/null 2>&1; then
    step "Stopping leftover services from a previous run"
    pkill -f "run_pipeline.py" 2>/dev/null
    pkill -f "kafka\.consumer" 2>/dev/null
    pkill -f "uvicorn api.main" 2>/dev/null
    pkill -f "dashboard/node_modules/.bin/vite" 2>/dev/null
    sleep 2
    ok "Stopped"
fi

# ---------------------------------------------------------------------------
# 1. Docker lab
# ---------------------------------------------------------------------------
step "Starting Docker lab (make up)"
if ! make up; then
    fail "docker compose up failed — check the output above"
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. Wait for Kafka — retry once for the ZooKeeper stale-ephemeral-node
#    issue (NodeExistsException after an unclean shutdown, see demo.md)
# ---------------------------------------------------------------------------
step "Waiting for Kafka"
kafka_up() {
    docker exec kafka kafka-topics --bootstrap-server localhost:9092 --list >/dev/null 2>&1
}

KAFKA_READY=false
for attempt in 1 2 3 4 5 6; do
    if kafka_up; then
        KAFKA_READY=true
        break
    fi
    if ! docker compose ps kafka 2>/dev/null | grep -q "Up"; then
        warn "kafka container not running — restarting it (attempt $attempt)"
        docker compose up -d kafka >/dev/null 2>&1
    fi
    sleep 5
done

if [[ "$KAFKA_READY" == true ]]; then
    ok "Kafka is up"
else
    fail "Kafka never came up — check 'docker logs kafka'"
    exit 1
fi

# ---------------------------------------------------------------------------
# 3. Wait for Elasticsearch, then create the index
# ---------------------------------------------------------------------------
step "Waiting for Elasticsearch"
ES_READY=false
for attempt in $(seq 1 24); do
    if curl -sf "http://localhost:9200" >/dev/null 2>&1; then
        ES_READY=true
        break
    fi
    sleep 5
done

if [[ "$ES_READY" == true ]]; then
    ok "Elasticsearch is up"
else
    fail "Elasticsearch never came up — check 'docker logs elasticsearch'"
    exit 1
fi

"$VENV_PY" es/init_index.py

# ---------------------------------------------------------------------------
# 4. Optional cleanup — stale zeek logs / features / ES alerts / Kafka backlog
# ---------------------------------------------------------------------------
if [[ "$CLEAN" == true ]]; then
    step "Cleaning stale state (--clean)"
    docker exec zeek sh -c 'rm -f /zeek/logs/*.log' 2>/dev/null
    docker exec victim sh -c 'rm -f /pcaps/capture*.pcap /pcaps/attack_*.pcap' 2>/dev/null
    rm -f data/features/live_*.parquet
    curl -s -X POST "http://localhost:9200/alerts/_delete_by_query" \
        -H 'Content-Type: application/json' \
        -d '{"query": {"match_all": {}}}' >/dev/null
    # Deleting ES alerts doesn't touch the Kafka topic itself — any
    # not-yet-consumed backlog from earlier rehearsals/testing sits in
    # raw-features and will get replayed the moment the consumer starts,
    # silently re-appearing as "new" alerts. Skip straight to the tail
    # (the consumer is confirmed stopped above, so this is safe).
    docker exec kafka kafka-consumer-groups --bootstrap-server localhost:9092 \
        --group aegis-consumer --topic raw-features \
        --reset-offsets --to-latest --execute >/dev/null 2>&1
    ok "Cleared zeek/logs, old attack pcaps, data/features/live_*.parquet, ES alerts, and Kafka backlog"
fi

# ---------------------------------------------------------------------------
# 5. Capture is handled per-attack by run_attack.sh (a fresh pcap file
#    each time — see its header comment for why a single shared,
#    accumulating capture file causes duplicate/stale alerts). Just make
#    sure nothing stale is left running from a previous session.
# ---------------------------------------------------------------------------
step "Clearing any stray tcpdump on victim"
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
" 2>/dev/null
ok "Ready — run ./run_attack.sh <script> [args...] to fire an attack and feed it through Zeek"

# ---------------------------------------------------------------------------
# 6. Watcher/producer, Kafka consumer, FastAPI — all via .venv
# ---------------------------------------------------------------------------
step "Starting watcher/producer, Kafka consumer, and FastAPI"

nohup "$VENV_PY" run_pipeline.py > "$RUN_DIR/pipeline.log" 2>&1 &
echo "pipeline:$!" >> "$PID_FILE"
sleep 1

nohup "$VENV_PY" -m kafka.consumer > "$RUN_DIR/consumer.log" 2>&1 &
echo "consumer:$!" >> "$PID_FILE"

nohup "$VENV_UVICORN" api.main:app --host 0.0.0.0 --port 8000 > "$RUN_DIR/api.log" 2>&1 &
echo "api:$!" >> "$PID_FILE"

step "Waiting for FastAPI to report ready"
API_READY=false
for attempt in $(seq 1 20); do
    if curl -sf "http://localhost:8000/health" | grep -q '"status":"ok"'; then
        API_READY=true
        break
    fi
    sleep 2
done

if [[ "$API_READY" == true ]]; then
    ok "FastAPI ready — $(curl -s http://localhost:8000/health)"
else
    fail "FastAPI never became healthy — check $RUN_DIR/api.log"
    tail -n 30 "$RUN_DIR/api.log"
    exit 1
fi

# ---------------------------------------------------------------------------
# 7. Dashboard
# ---------------------------------------------------------------------------
step "Starting dashboard"
if [[ ! -d dashboard/node_modules ]]; then
    warn "dashboard/node_modules missing — running npm install (this will take a while)"
    (cd dashboard && npm install)
fi

(cd dashboard && nohup npm run dev > "$RUN_DIR/dashboard.log" 2>&1 &
 echo "dashboard:$!" >> "$PID_FILE")
sleep 2
ok "Dashboard starting — http://localhost:5173"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "============================================================"
echo " Aegis is up"
echo "============================================================"
echo "  Dashboard   : http://localhost:5173"
echo "  API health  : http://localhost:8000/health"
echo "  Logs        : $RUN_DIR/{pipeline,consumer,api,dashboard}.log"
echo "  PIDs        : $PID_FILE"
echo
echo "  Next: run an attack and see it land on the dashboard —"
echo "    ./run_attack.sh port_scan.py --profile fast_sequential"
echo
echo "  To stop everything: ./stop_demo.sh"
echo "============================================================"
