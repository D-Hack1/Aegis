# main.zeek — Aegis NIDS Zeek script entry point
#
# This file is the loader for all custom Zeek scripts.  It contains no logic.
# Pass this file to the zeek command when monitoring a live interface or
# replaying a PCAP.
#
# Usage (inside the zeek container):
#
#   Live interface:
#     zeek -i eth0 /usr/local/zeek/share/zeek/site/main.zeek \
#          Log::default_logdir=/zeek/logs
#
#   PCAP replay:
#     zeek -C -r /path/to/capture.pcap \
#          /usr/local/zeek/share/zeek/site/main.zeek \
#          Log::default_logdir=/zeek/logs
#
#   Don't add -D (deterministic seeds) here — it doesn't key UIDs off
#   actual packet content, it resets Zeek's UID counter to the same
#   starting state every run, so two DIFFERENT captures with the same
#   flow count get assigned the SAME UIDs. If something downstream dedups
#   by flow_id/uid, that makes it silently swallow a genuinely new
#   capture's alerts instead of only catching real duplicates. Give every
#   replay its own, never-reprocessed pcap file instead (see run_attack.sh).
#
# Logs written to /zeek/logs (volume-mounted to ./zeek/logs on the host).
# The feature pipeline reads from ./zeek/logs:
#   python3 features/pipeline.py --zeek-dir zeek/logs --scenario-name <name>

# ---------------------------------------------------------------------------
# Base protocols — must load before custom scripts so that SSL::Info,
# Conn::Info, and DNS::Info record types exist when ja3.zeek and quic.zeek
# extend them via redef.
# ---------------------------------------------------------------------------
@load base/protocols/conn
@load base/protocols/ssl
@load base/protocols/dns

# ---------------------------------------------------------------------------
# Custom scripts
#   ja3.zeek  — JA3/JA3S TLS fingerprinting (appends to ssl.log)
#   quic.zeek — QUIC-like UDP/443 heuristic detection (creates quic.log)
# ---------------------------------------------------------------------------
@load ./ja3
@load ./quic
