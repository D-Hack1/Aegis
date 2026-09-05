from dataclasses import dataclass, field, asdict
from typing import Optional
import json


@dataclass
class FeatureRow:
    # Flow identity
    flow_id: str                    # Zeek conn.log uid — primary join key
    ts: float                       # Flow start time (Unix timestamp)
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str                   # "tcp" | "udp" | "icmp"
    duration: float                 # Flow duration in seconds

    # Per-flow volume features
    packets_per_sec: float          # orig_pkts / duration
    bytes_per_sec: float            # orig_bytes / duration
    outbound_inbound_ratio: float   # orig_bytes / (resp_bytes + 1)
    orig_bytes: int                 # Total bytes sent by originator
    resp_bytes: int                 # Total bytes sent by responder
    orig_pkts: int                  # Packet count from originator
    resp_pkts: int                  # Packet count from responder

    # Per-flow fan-out / fan-in features  (computed in 60s rolling window)
    fan_out: float                  # Unique dst_ip:dst_port pairs from this src in window
    fan_in: float                   # Unique src_ips connecting to this dst in window
    unique_dst_ips: int             # Unique destination IPs from this src in window
    unique_dst_ports: int           # Unique destination ports from this src in window

    # Inter-arrival time features  (across flows from same src, sorted by ts)
    iat_mean: float                 # Mean inter-arrival time (seconds)
    iat_std: float                  # Std dev of inter-arrival time
    iat_min: float                  # Min inter-arrival time
    iat_max: float                  # Max inter-arrival time
    connection_frequency: float     # Flows per minute from this src in window

    # Per-source entropy features  (60s rolling window, group by src_ip)
    src_ip_entropy: float           # Shannon entropy of dst IP distribution — high = scanning, low = beaconing
    periodicity_score: float        # 1 / std(IAT) — high = very regular intervals = beaconing signal

    # DNS features  (from dns.log, joined on src_ip + time window)
    dns_query_entropy: float        # Shannon entropy of chars in query name
    domain_length_mean: float       # Mean domain name length from this src in window
    domain_length_max: float        # Max domain name length from this src in window
    subdomain_count: float          # Mean number of labels in FQDN
    dns_record_type_a_ratio: float  # Fraction of queries that are A records
    dns_record_type_txt_ratio: float  # Fraction of queries that are TXT (tunnelling signal)
    dns_query_count: int            # Total DNS queries from this src in window

    # TLS / JA3 features  (from ssl.log)
    ja3_hash: str                   # JA3 fingerprint hash (empty string if not TLS)
    ja3s_hash: str                  # JA3S fingerprint hash (empty string if not TLS)
    tls_version: float              # Ordinal: TLS1.0=1.0, 1.1=2.0, 1.2=3.0, 1.3=4.0, 0=not TLS
    cipher_suite_enc: int           # Frequency-encoded cipher suite (top-50, rest=0)
    is_tls: bool                    # True if this flow has a TLS session

    # JA4 features  (new — from Zeek ja4 package or post-processing)
    ja4_hash: str                   # JA4 fingerprint hash (empty string if not TLS/QUIC)

    # QUIC features  (new — from quic.log or Scapy post-processing)
    is_quic: bool                   # True if this flow is QUIC (UDP/443)
    quic_0rtt: bool                 # True if QUIC 0-RTT resumption was used
    quic_pkt_size_mean: float       # Mean QUIC packet size within this flow (0 if not QUIC)
    quic_pkt_size_std: float        # Std dev of QUIC packet sizes (0 if not QUIC)

    # Label  (None at inference time, set during training data preparation)
    label: Optional[str] = None
    # Possible values:
    #   "ddos"          — SYN flood, UDP flood
    #   "c2_beaconing"  — Botnet C2 periodic communication
    #   "dns_anomaly"   — DGA domains, DNS tunnelling
    #   "malware_tls"   — Malware inside encrypted sessions
    #   "port_scan"     — Reconnaissance / port scanning
    #   "exfiltration"  — Data exfiltration
    #   "benign"        — Normal traffic


# Ordered list of feature column names used for model input.
# The label column is excluded — add it separately when building training data.
# This is the exact column order the XGBoost model and Isolation Forest expect.
FEATURE_COLUMNS: list[str] = [
    # Flow identity (non-numeric — excluded from model input, kept for joining)
    # flow_id, ts, src_ip, dst_ip, protocol are join keys, not model features

    # Volume
    "packets_per_sec",
    "bytes_per_sec",
    "outbound_inbound_ratio",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",

    # Fan-out / fan-in
    "fan_out",
    "fan_in",
    "unique_dst_ips",
    "unique_dst_ports",

    # IAT
    "iat_mean",
    "iat_std",
    "iat_min",
    "iat_max",
    "connection_frequency",

    # Entropy / periodicity
    "src_ip_entropy",
    "periodicity_score",

    # DNS
    "dns_query_entropy",
    "domain_length_mean",
    "domain_length_max",
    "subdomain_count",
    "dns_record_type_a_ratio",
    "dns_record_type_txt_ratio",
    "dns_query_count",

    # TLS / JA3
    "tls_version",
    "cipher_suite_enc",
    "is_tls",

    # JA4
    # ja4_hash is frequency-encoded into ja4_hash_enc by the feature pipeline
    "ja4_hash_enc",

    # QUIC
    "is_quic",
    "quic_0rtt",
    "quic_pkt_size_mean",
    "quic_pkt_size_std",

    # src_port and dst_port included as numeric features
    "src_port",
    "dst_port",
    "duration",
]

# Columns that are identifiers only — never passed to the model
ID_COLUMNS: list[str] = [
    "flow_id",
    "ts",
    "src_ip",
    "dst_ip",
    "protocol",
    "ja3_hash",
    "ja3s_hash",
    "ja4_hash",   # raw hash — model uses ja4_hash_enc
]

# String/hash columns that need encoding before model input
ENCODE_COLUMNS: list[str] = [
    "ja4_hash",   # → ja4_hash_enc  (frequency encoding, top-50, rest=0)
]

# Boolean columns — ensure these are cast to int (0/1) before model input
BOOL_COLUMNS: list[str] = [
    "is_tls",
    "is_quic",
    "quic_0rtt",
]

# Numeric columns that should be filled with 0.0 if missing
# (e.g. QUIC features on non-QUIC flows, DNS features on non-DNS flows)
FILL_ZERO_COLUMNS: list[str] = [
    "dns_query_entropy",
    "domain_length_mean",
    "domain_length_max",
    "subdomain_count",
    "dns_record_type_a_ratio",
    "dns_record_type_txt_ratio",
    "dns_query_count",
    "tls_version",
    "cipher_suite_enc",
    "ja4_hash_enc",
    "quic_pkt_size_mean",
    "quic_pkt_size_std",
    "iat_std",
    "iat_min",
    "iat_max",
    "periodicity_score",
]


# Serialisation helpers

def to_dict(row: FeatureRow) -> dict:
    """Convert a FeatureRow to a plain dict for JSON serialisation (Kafka messages)."""
    return asdict(row)


def from_dict(d: dict) -> FeatureRow:
    """
    Reconstruct a FeatureRow from a dict (e.g. deserialised from Kafka).
    Missing optional fields default to safe zero values.
    """
    defaults = {
        "is_quic": False,
        "quic_0rtt": False,
        "quic_pkt_size_mean": 0.0,
        "quic_pkt_size_std": 0.0,
        "ja4_hash": "",
        "dns_query_entropy": 0.0,
        "domain_length_mean": 0.0,
        "domain_length_max": 0.0,
        "subdomain_count": 0.0,
        "dns_record_type_a_ratio": 0.0,
        "dns_record_type_txt_ratio": 0.0,
        "dns_query_count": 0,
        "iat_std": 0.0,
        "iat_min": 0.0,
        "iat_max": 0.0,
        "periodicity_score": 0.0,
        "label": None,
    }
    merged = {**defaults, **d}
    return FeatureRow(**{k: merged[k] for k in FeatureRow.__dataclass_fields__})


def to_json(row: FeatureRow) -> str:
    """Serialise a FeatureRow to a JSON string for Kafka publishing."""
    return json.dumps(to_dict(row))


def from_json(s: str) -> FeatureRow:
    """Deserialise a FeatureRow from a JSON string (Kafka consumer)."""
    return from_dict(json.loads(s))
