# quic.zeek — QUIC-like UDP/443 traffic detection for Aegis NIDS
#
# Creates quic.log with one row per completed UDP/443 connection.
# Compatible with zeek/zeek:6.0.3. No external packages required.
#
# IMPORTANT — HEURISTIC DETECTION:
#   This script uses a UDP/443 port heuristic to identify traffic that is
#   *likely* QUIC (RFC 9000 uses UDP/443 by convention), but is_quic=T does
#   NOT constitute confirmed protocol-level QUIC identification.  Any UDP
#   traffic to destination port 443 will be logged here.  The field and all
#   downstream consumers must be interpreted as "QUIC-like UDP/443 traffic".
#
# Zeek 6.0.3 limitation:
#   The native quic.log (QUIC::Info) was added in Zeek 6.1.  The spicy-quic
#   package requires cmake/C++ compilation not available in this image.
#   Therefore:
#     - zero_rtt is always F  (no handshake-level visibility)
#     - packet_sizes column is absent  (pipeline defaults: mean=0.0, std=0.0)
#   This is consistent with the pipeline QUIC_ALIASES fallback behaviour.
#
# Pipeline contract (features/pipeline.py):
#   QUIC_ALIASES = {
#       "uid":          ("uid",),
#       "zero_rtt":     ("quic_0rtt", "0rtt", "zero_rtt", "is_0rtt"),
#       "packet_sizes": ("packet_sizes", "pkt_sizes", "packet_size", "pkt_size"),
#   }
#   uid       → join key (must match conn.log uid exactly)
#   zero_rtt  → FeatureRow.quic_0rtt  (always False here)
#   (absent)  → FeatureRow.quic_pkt_size_mean = 0.0, quic_pkt_size_std = 0.0
#   (presence)→ FeatureRow.is_quic = True

module QUIC_DETECT;

export {
    redef enum Log::ID += { LOG };

    ## Log record written for each completed UDP/443 flow.
    type Info: record {
        ## Connection timestamp (flow start).
        ts:      time   &log;
        ## Zeek connection UID — matches conn.log uid for pipeline join.
        uid:     string &log;
        ## Source (originator) IP address.
        orig_h:  addr   &log;
        ## Source (originator) port.
        orig_p:  port   &log;
        ## Destination (responder) IP address.
        resp_h:  addr   &log;
        ## Destination (responder) port — always 443 for rows in this log.
        resp_p:  port   &log;
        ## Heuristic QUIC-like label.  Always T for UDP/443 flows.
        ## WARNING: T means "UDP/443 — likely QUIC", NOT confirmed QUIC.
        ## Do not treat this as protocol-level QUIC detection.
        is_quic: bool   &log &default=T;
        ## 0-RTT resumption flag.  Always F under Zeek 6.0.3 — no Spicy
        ## parser is available so handshake-level 0-RTT detection is not
        ## possible.  FeatureRow.quic_0rtt will be False for all rows.
        zero_rtt: bool  &log &default=F;
    };
}

# Register the quic.log stream.
event zeek_init()
{
    Log::create_stream(QUIC_DETECT::LOG, [$columns=Info, $path="quic"]);
}

# ---------------------------------------------------------------------------
# connection_state_remove fires exactly once per Zeek connection, guaranteeing
# that each uid appears at most once in quic.log.  This satisfies the
# pipeline's validate="one_to_one" merge constraint.
# ---------------------------------------------------------------------------
event connection_state_remove(c: connection)
{
    # Heuristic: UDP traffic to port 443 is treated as QUIC-like.
    # Use get_conn_transport_proto() — always available on the base connection
    # record regardless of whether base/protocols/conn has attached c$conn.
    if ( get_conn_transport_proto(c$id) != udp )
        return;
    if ( c$id$resp_p != 443/udp )
        return;

    local rec: QUIC_DETECT::Info = [
        $ts       = c$start_time,
        $uid      = c$uid,
        $orig_h   = c$id$orig_h,
        $orig_p   = c$id$orig_p,
        $resp_h   = c$id$resp_h,
        $resp_p   = c$id$resp_p,
        $is_quic  = T,
        $zero_rtt = F
    ];

    Log::write(QUIC_DETECT::LOG, rec);
}
