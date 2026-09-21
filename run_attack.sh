#!/usr/bin/env bash
# Aegis — fire an attack script inside the attacker container, capturing
# ONLY that attack's traffic into its own fresh pcap, then feed it
# through Zeek offline so the running pipeline (started by
# start_demo.sh) picks it up and an alert appears within a few seconds.
# See demo.md section 2 for why this two-step dance is needed instead of
# true live Zeek capture.
#
# Why a fresh pcap per attack (not one shared, accumulating capture.pcap):
# Zeek assigns each flow a UID, and that UID is NOT deterministic across
# separate `zeek -C -r` invocations — reprocessing the exact same pcap
# twice produces two different sets of UIDs for the identical flows
# (verified 2026-09-18). If capture.pcap accumulates every attack and
# gets reprocessed in full each time, every old flow gets a brand-new
# random flow_id on every run and sails straight past the watcher's
# flow_id dedup — so every attack silently re-floods the whole pipeline
# with every previous attack's traffic relabeled as "new". That's what
# was behind alerts ballooning into the thousands and new attacks taking
# longer and longer to actually surface on the dashboard (a growing
# duplicate backlog ahead of them in the Kafka topic). Capturing each
# attack into its own small, disposable pcap sidesteps the problem
# entirely — there's never anything old left to reprocess.
#
# Do NOT "fix" this with `zeek -D` (deterministic seeds) instead —
# tried and reverted 2026-09-18. -D doesn't key UIDs off actual packet
# content, it just resets Zeek's UID counter to the same starting state
# every run — so two DIFFERENT attacks with the same flow count (e.g.
# two separate syn_flood runs) get assigned the SAME UIDs despite having
# completely different traffic. That makes the watcher's flow_id dedup
# silently swallow the second attack's genuinely new alerts instead of
# preventing duplicates — a worse, silent failure. A fresh pcap per
# attack is the actual fix; leave Zeek's seeding alone.
#
# Usage — one example per attack class we detect:
#   ./run_attack.sh port_scan.py --profile fast_sequential          (class: port_scan)
#   ./run_attack.sh syn_flood.py --profile low_steady                (class: ddos)
#   ./run_attack.sh udp_flood.py --profile low_steady                (class: ddos)
#   ./run_attack.sh exfiltration.py --flows 5 --send-live            (class: exfiltration)
#   ./run_attack.sh benign_traffic.py --flows 50 --send-live         (class: benign)
#                                                        (run in the benign container)
#
# c2_beaconing, dns_anomaly (DGA/DNS tunneling), and malware_tls have no
# live-fire script here — c2_beacon.py, dga.py, and dns_tunnel.py only
# ever generate offline training pcaps (see the guard below); there's no
# malware_tls generator script at all. To demo those classes, use
# pre-existing labeled data (data/features/*.parquet) rather than this
# script.
#
# The script name decides which container it runs in: benign_traffic.py
# runs in the `benign` container, everything else runs in `attacker`.
#
# NEVER pass --output pointing inside /pcaps/ at all — this script
# manages its own capture file per run. A script's own --output (used
# for its offline/dataset archival copy) writes inside the container's
# own filesystem by default, which is fine; only /pcaps paths are
# guarded against here since that's the shared, host-visible directory.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <script.py> [args...]"
    echo "  e.g. $0 port_scan.py --profile fast_sequential"
    exit 1
fi

SCRIPT="$1"
shift

for arg in "$@"; do
    if [[ "$arg" == /pcaps/* ]]; then
        echo "!! Refusing to run: an argument points inside /pcaps/ ($arg)."
        echo "   This script captures each attack into its own file there —"
        echo "   writing there yourself can collide with or corrupt that"
        echo "   capture. Drop --output (or point it somewhere else, e.g."
        echo "   /tmp/) and let this script handle the capture."
        exit 1
    fi
done

case "$SCRIPT" in
    c2_beacon.py|dga.py|dns_tunnel.py)
        echo "!! $SCRIPT is an offline dataset generator — it never transmits"
        echo "   real packets, so running it here won't produce a new alert."
        echo "   Use port_scan.py, syn_flood.py, udp_flood.py, exfiltration.py"
        echo "   (--send-live), or benign_traffic.py (--send-live) instead."
        exit 1
        ;;
esac

CONTAINER="attacker"
[[ "$SCRIPT" == "benign_traffic.py" ]] && CONTAINER="benign"

CAPTURE="/pcaps/attack_$(date +%s).pcap"

echo "== Starting fresh capture on victim ($CAPTURE) =="
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
docker exec -d victim tcpdump -i eth0 -U -w "$CAPTURE"
sleep 1

echo "== Running $SCRIPT in $CONTAINER =="
docker exec "$CONTAINER" python3 "/scripts/$SCRIPT" "$@"
STATUS=$?
if [[ $STATUS -ne 0 ]]; then
    echo "!! $SCRIPT exited with status $STATUS — not processing through Zeek"
    exit $STATUS
fi

# Give tcpdump a moment to flush the last few packets (it's already
# unbuffered via -U, but the capture and the exec above race slightly).
sleep 1

echo "== Feeding capture through Zeek =="
docker exec zeek zeek -C -r "$CAPTURE" /zeek/site/main.zeek Log::default_logdir=/zeek/logs

echo "== Done — check the dashboard (http://localhost:5173) in a few seconds =="
