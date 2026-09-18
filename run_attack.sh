#!/usr/bin/env bash
# Aegis — fire an attack script inside the attacker container, then feed
# the victim's capture through Zeek offline so the running pipeline
# (started by start_demo.sh) picks it up and an alert appears within a
# few seconds. See demo.md section 2 for why this two-step dance is
# needed instead of true live Zeek capture.
#
# Usage:
#   ./run_attack.sh port_scan.py --profile fast_sequential
#   ./run_attack.sh syn_flood.py --profile low_steady
#   ./run_attack.sh exfiltration.py --flows 5 --send-live
#   ./run_attack.sh benign_traffic.py --flows 50 --send-live   (run in the benign container)
#
# The script name decides which container it runs in: benign_traffic.py
# runs in the `benign` container, everything else runs in `attacker`.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <script.py> [args...]"
    echo "  e.g. $0 port_scan.py --profile fast_sequential"
    exit 1
fi

SCRIPT="$1"
shift

CONTAINER="attacker"
[[ "$SCRIPT" == "benign_traffic.py" ]] && CONTAINER="benign"

echo "== Running $SCRIPT in $CONTAINER =="
docker exec "$CONTAINER" python3 "/scripts/$SCRIPT" "$@"
STATUS=$?
if [[ $STATUS -ne 0 ]]; then
    echo "!! $SCRIPT exited with status $STATUS — not processing through Zeek"
    exit $STATUS
fi

echo "== Feeding capture through Zeek =="
docker exec zeek zeek -C -r /pcaps/capture.pcap /zeek/site/main.zeek Log::default_logdir=/zeek/logs

echo "== Done — check the dashboard (http://localhost:5173) in a few seconds =="
