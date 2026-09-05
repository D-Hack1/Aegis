import argparse
import codecs
import ipaddress
import math
from collections import Counter, defaultdict, deque
from pathlib import Path

import pandas as pd

try:
    from features.schema import BOOL_COLUMNS, FEATURE_COLUMNS, FeatureRow, to_dict
except ModuleNotFoundError:  # Supports running this file directly as a script.
    from schema import BOOL_COLUMNS, FEATURE_COLUMNS, FeatureRow, to_dict


WINDOW_SECONDS = 60.0
EPSILON = 1e-9
REQUIRED_CONN_COLUMNS = (
    "uid",
    "ts",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
)
CONN_FEATURE_COLUMNS = (
    "uid", "flow_id", "ts", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "packets_per_sec",
    "bytes_per_sec", "outbound_inbound_ratio", "fan_out", "fan_in", "unique_dst_ips",
    "unique_dst_ports", "connection_frequency", "iat_mean", "iat_std", "iat_min", "iat_max",
    "src_ip_entropy", "periodicity_score",
)


def safe_float(value, default=0.0):
    """Convert Zeek values to finite floats, treating '-' as missing."""
    if value is None or (isinstance(value, str) and value.strip() in {"", "-"}):
        return default
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if math.isfinite(number) else default


def _parse_required_int(value, field):
    if value is None or (isinstance(value, str) and value.strip() in {"", "-"}):
        raise ValueError(f"feature row has an invalid required integer field: {field}")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"feature row has an invalid required integer field: {field}") from None
    if not math.isfinite(number) or not number.is_integer() or number < 0:
        raise ValueError(f"feature row has an invalid required integer field: {field}")
    return int(number)


def _parse_timestamp(value):
    if value is None or (isinstance(value, str) and value.strip() in {"", "-"}):
        raise ValueError(f"conn.log contains an invalid ts value: {value!r}")
    try:
        timestamp = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"conn.log contains an invalid ts value: {value!r}") from None
    if not math.isfinite(timestamp):
        raise ValueError(f"conn.log contains an invalid ts value: {value!r}")
    return timestamp


def safe_divide(numerator, denominator):
    """Divide without returning NaN or infinity."""
    if abs(denominator) < EPSILON:
        return 0.0
    result = numerator / denominator
    return result if math.isfinite(result) else 0.0


def read_zeek_log(path):
    """Read a Zeek TSV log while preserving its #fields column names."""
    separator = "\t"
    fields = None
    rows = []

    with Path(path).open(encoding="utf-8") as log_file:
        for raw_line in log_file:
            line = raw_line.rstrip("\r\n")
            if line.startswith("#separator"):
                encoded_separator = line[len("#separator") :].strip()
                separator = codecs.decode(encoded_separator, "unicode_escape")
            elif line.startswith("#fields"):
                fields = line.split(separator)[1:]
            elif line.startswith("#"):
                continue
            else:
                if fields is None:
                    raise ValueError("Zeek log is missing a #fields header")
                values = line.split(separator)
                if len(values) != len(fields):
                    raise ValueError("Zeek log row does not match the #fields header")
                rows.append([None if value == "-" else value for value in values])

    if fields is None:
        raise ValueError("Zeek log is missing a #fields header")
    return pd.DataFrame(rows, columns=fields)


def read_zeek_conn_log(path):
    """Read conn.log using the generic Zeek TSV reader."""
    return read_zeek_log(path)


def _clean_ip(value):
    if value is None or str(value).strip() in {"", "-"}:
        return ""
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return str(value)


def _standard_deviation(values):
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((value - mean) ** 2 for value in values) / len(values)
    return math.sqrt(variance)


def _iat_features(intervals):
    if not intervals:
        return 0.0, 0.0, 0.0, 0.0, 0.0

    iat_mean = sum(intervals) / len(intervals)
    iat_std = _standard_deviation(intervals)
    periodicity_score = 1.0 / max(iat_std, EPSILON)
    return iat_mean, iat_std, min(intervals), max(intervals), periodicity_score


def _destination_entropy(source_window):
    destination_counts = Counter(destination_ip for _, destination_ip, _ in source_window)
    total = sum(destination_counts.values())
    if total == 0:
        return 0.0

    return -sum(
        (count / total) * math.log2(count / total) for count in destination_counts.values()
    )


def _normalise_conn_log(conn_log):
    missing_columns = [column for column in REQUIRED_CONN_COLUMNS if column not in conn_log.columns]
    if missing_columns:
        raise ValueError(f"conn.log is missing required columns: {', '.join(missing_columns)}")

    columns = list(REQUIRED_CONN_COLUMNS)
    if "proto" in conn_log.columns:
        columns.append("proto")
    normalized = conn_log.loc[:, columns].copy()
    normalized["uid"] = normalized["uid"].map(lambda value: "" if value is None else str(value))
    normalized["ts"] = normalized["ts"].map(_parse_timestamp)
    normalized["id.orig_h"] = normalized["id.orig_h"].map(_clean_ip)
    normalized["id.resp_h"] = normalized["id.resp_h"].map(_clean_ip)
    if "proto" in normalized.columns:
        normalized["proto"] = normalized["proto"].map(
            lambda value: "" if value is None else str(value).strip().lower()
        )
    else:
        normalized["proto"] = ""

    for column in ("id.orig_p", "id.resp_p"):
        normalized[column] = normalized[column].map(
            lambda value: _parse_required_int(value, column)
        )
    normalized["duration"] = normalized["duration"].map(lambda value: max(safe_float(value), 0.0))
    for column in ("orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"):
        normalized[column] = normalized[column].map(
            lambda value: _parse_required_int(value, column)
        )

    return normalized.sort_values(["ts", "uid"], kind="mergesort").reset_index(drop=True)


def compute_conn_features(conn_log):
    """Compute schema-independent conn.log features in timestamp order."""
    normalized = _normalise_conn_log(conn_log)
    source_windows = defaultdict(deque)
    destination_windows = defaultdict(deque)
    source_iats = defaultdict(list)
    previous_source_timestamp = {}
    feature_rows = []

    for record in normalized.to_dict("records"):
        timestamp = record["ts"]
        source_ip = record["id.orig_h"]
        destination_ip = record["id.resp_h"]
        destination_port = record["id.resp_p"]

        source_window = source_windows[source_ip]
        while source_window and timestamp - source_window[0][0] > WINDOW_SECONDS:
            source_window.popleft()
        destination_window = destination_windows[destination_ip]
        while destination_window and timestamp - destination_window[0][0] > WINDOW_SECONDS:
            destination_window.popleft()

        if source_ip in previous_source_timestamp:
            source_iats[source_ip].append(max(0.0, timestamp - previous_source_timestamp[source_ip]))
        previous_source_timestamp[source_ip] = timestamp

        source_window.append((timestamp, destination_ip, destination_port))
        destination_window.append((timestamp, source_ip))
        iat_mean, iat_std, iat_min, iat_max, periodicity_score = _iat_features(source_iats[source_ip])

        duration = record["duration"]
        orig_bytes = record["orig_bytes"]
        resp_bytes = record["resp_bytes"]
        orig_pkts = record["orig_pkts"]
        feature_rows.append(
            {
                "uid": record["uid"],
                # Temporary internal mapping until features/schema.py defines the shared contract.
                "flow_id": record["uid"],
                "ts": timestamp,
                "src_ip": source_ip,
                "dst_ip": destination_ip,
                "src_port": record["id.orig_p"],
                "dst_port": destination_port,
                "protocol": record["proto"],
                "duration": duration,
                "orig_bytes": orig_bytes,
                "resp_bytes": resp_bytes,
                "orig_pkts": orig_pkts,
                "resp_pkts": record["resp_pkts"],
                "packets_per_sec": safe_divide(orig_pkts, duration),
                "bytes_per_sec": safe_divide(orig_bytes, duration),
                "outbound_inbound_ratio": safe_divide(orig_bytes, resp_bytes + 1.0),
                "fan_out": float(len({(ip, port) for _, ip, port in source_window})),
                "fan_in": float(len({ip for _, ip in destination_window})),
                "unique_dst_ips": float(len({ip for _, ip, _ in source_window})),
                "unique_dst_ports": float(len({port for _, _, port in source_window})),
                "connection_frequency": float(len(source_window)),
                "iat_mean": iat_mean,
                "iat_std": iat_std,
                "iat_min": iat_min,
                "iat_max": iat_max,
                "src_ip_entropy": _destination_entropy(source_window),
                "periodicity_score": periodicity_score,
            }
        )

    return pd.DataFrame(feature_rows, columns=CONN_FEATURE_COLUMNS)


def _text(value):
    if value is None or (isinstance(value, str) and value.strip() in {"", "-"}):
        return ""
    return str(value).strip()


def _resolve_columns(log_rows, aliases, required=()):
    lower_columns = {str(column).lower(): column for column in log_rows.columns}
    resolved = {}
    for semantic, names in aliases.items():
        resolved[semantic] = next(
            (lower_columns[name.lower()] for name in names if name.lower() in lower_columns), None
        )
    missing = [semantic for semantic in required if resolved.get(semantic) is None]
    if missing:
        expected = ", ".join("/".join(aliases[semantic]) for semantic in missing)
        raise ValueError(f"Zeek log is missing required field(s): {expected}")
    return resolved


def dns_query_entropy(query):
    query = _text(query)
    if not query:
        return 0.0
    counts = Counter(query)
    length = len(query)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def subdomain_count(query):
    query = _text(query).rstrip(".")
    return len([label for label in query.split(".") if label]) if query else 0


def dns_record_type_fractions(qtypes):
    """Use every DNS record with a non-empty qtype as the ratio denominator."""
    normalized = [_text(qtype).upper() for qtype in qtypes if _text(qtype)]
    if not normalized:
        return {record_type: 0.0 for record_type in ("A", "AAAA", "TXT", "MX")}
    counts = Counter(normalized)
    total = len(normalized)
    return {record_type: counts[record_type] / total for record_type in ("A", "AAAA", "TXT", "MX")}


DNS_ALIASES = {
    "uid": ("uid",),
    "src_ip": ("id.orig_h", "src_ip", "source_ip"),
    "ts": ("ts", "timestamp", "time"),
    "query": ("query", "qname"),
    "qtype": ("qtype_name", "qtype"),
}
DNS_EVENT_COLUMNS = (
    "uid",
    "src_ip",
    "ts",
    "query",
    "qtype",
)
DNS_FEATURE_COLUMNS = (
    "uid", "dns_query_entropy", "domain_length_mean", "domain_length_max", "subdomain_count",
    "dns_record_type_a_ratio", "dns_record_type_txt_ratio", "dns_query_count",
)


def compute_dns_features(dns_log):
    """Normalize DNS events for source-IP, timestamp-window enrichment."""
    resolved = _resolve_columns(dns_log, DNS_ALIASES, required=("uid", "src_ip", "ts", "query"))
    if dns_log.empty:
        return pd.DataFrame(columns=DNS_EVENT_COLUMNS)

    qtype_column = resolved["qtype"]
    rows = [
        {
            "uid": _text(record[resolved["uid"]]),
            "src_ip": _clean_ip(record[resolved["src_ip"]]),
            "ts": _parse_timestamp(record[resolved["ts"]]),
            "query": _text(record[resolved["query"]]),
            "qtype": _text(record[qtype_column]) if qtype_column else "",
        }
        for record in dns_log.to_dict("records")
    ]
    return pd.DataFrame(rows, columns=DNS_EVENT_COLUMNS).sort_values(
        ["ts", "uid"], kind="mergesort"
    ).reset_index(drop=True)


def _dns_window_features(conn_features, dns_events):
    if dns_events.empty:
        return pd.DataFrame(columns=DNS_FEATURE_COLUMNS)

    events_by_source = {
        source_ip: group.to_dict("records")
        for source_ip, group in dns_events.groupby("src_ip", sort=False)
    }
    rows = []
    for flow in conn_features.to_dict("records"):
        timestamp = flow["ts"]
        events = [
            event
            for event in events_by_source.get(flow["src_ip"], [])
            if 0.0 <= timestamp - event["ts"] <= WINDOW_SECONDS
        ]
        queries = [event["query"] for event in events if event["query"]]
        lengths = [len(query) for query in queries]
        fractions = dns_record_type_fractions(event["qtype"] for event in events)
        rows.append(
            {
                "uid": flow["uid"],
                "dns_query_entropy": (
                    sum(dns_query_entropy(query) for query in queries) / len(queries)
                    if queries
                    else 0.0
                ),
                "domain_length_mean": sum(lengths) / len(lengths) if lengths else 0.0,
                "domain_length_max": float(max(lengths)) if lengths else 0.0,
                "subdomain_count": (
                    sum(subdomain_count(query) for query in queries) / len(queries) if queries else 0.0
                ),
                "dns_record_type_a_ratio": fractions["A"],
                "dns_record_type_txt_ratio": fractions["TXT"],
                "dns_query_count": len(queries),
            }
        )
    return pd.DataFrame(rows, columns=DNS_FEATURE_COLUMNS)


def encode_tls_version(value):
    normalized = _text(value).upper().replace(" ", "").replace("_", "")
    versions = {
        "TLS1.0": 1,
        "TLSV1.0": 1,
        "TLSV10": 1,
        "TLS10": 1,
        "TLS1.1": 2,
        "TLSV1.1": 2,
        "TLSV11": 2,
        "TLS11": 2,
        "TLS1.2": 3,
        "TLSV1.2": 3,
        "TLSV12": 3,
        "TLS12": 3,
        "TLS1.3": 4,
        "TLSV1.3": 4,
        "TLSV13": 4,
        "TLS13": 4,
    }
    return versions.get(normalized, 0)


def _first_nonempty(values):
    return next((text for value in values if (text := _text(value))), "")


TLS_ALIASES = {
    "uid": ("uid",),
    "version": ("version", "tls_version"),
    "cipher": ("cipher", "cipher_suite"),
    "ja3": ("ja3", "ja3_hash"),
    "ja3s": ("ja3s", "ja3s_hash"),
    # Aadi's JA4 field can vary; aliases remain isolated here.
    "ja4": ("ja4", "ja4_hash"),
}
TLS_COLUMNS = (
    "uid",
    "ja3_hash",
    "ja3s_hash",
    "ja4_hash",
    "tls_version",
    "cipher_suite",
    "is_tls",
)


def compute_tls_features(tls_log):
    """Aggregate ssl.log fingerprints by UID without fitting model encoders."""
    resolved = _resolve_columns(tls_log, TLS_ALIASES, required=("uid",))
    if tls_log.empty:
        return pd.DataFrame(columns=TLS_COLUMNS)

    rows = []
    for uid, group in tls_log.groupby(resolved["uid"], sort=True, dropna=False):
        value = lambda semantic: _first_nonempty(group[resolved[semantic]]) if resolved[semantic] else ""
        cipher = value("cipher")
        ja4_hash = value("ja4")
        rows.append(
            {
                "uid": _text(uid),
                "ja3_hash": value("ja3"),
                "ja3s_hash": value("ja3s"),
                "ja4_hash": ja4_hash,
                "tls_version": float(encode_tls_version(value("version"))),
                "cipher_suite": cipher,
                "is_tls": True,
            }
        )
    return pd.DataFrame(rows, columns=TLS_COLUMNS)


def normalize_boolean(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and math.isfinite(value):
        return value != 0
    return _text(value).lower() in {"1", "true", "t", "yes", "y", "on"}


def quic_packet_size_stats(packet_sizes):
    sizes = [safe_float(size, -1.0) for size in packet_sizes]
    sizes = [size for size in sizes if size >= 0.0]
    if not sizes:
        return 0.0, 0.0
    return sum(sizes) / len(sizes), _standard_deviation(sizes)


def _packet_sizes(value):
    if isinstance(value, (list, tuple, set)):
        return value
    text = _text(value).strip("[]{}")
    return text.split(",") if text else []


QUIC_ALIASES = {
    "uid": ("uid",),
    "zero_rtt": ("quic_0rtt", "0rtt", "zero_rtt", "is_0rtt"),
    "packet_sizes": ("packet_sizes", "pkt_sizes", "packet_size", "pkt_size"),
}
QUIC_COLUMNS = ("uid", "is_quic", "quic_0rtt", "quic_pkt_size_mean", "quic_pkt_size_std")


def quic_defaults():
    return {
        "is_quic": False,
        "quic_0rtt": False,
        "quic_pkt_size_mean": 0.0,
        "quic_pkt_size_std": 0.0,
    }


def compute_quic_features(quic_log):
    """Aggregate available QUIC metadata by UID without assuming Aadi's final field names."""
    resolved = _resolve_columns(quic_log, QUIC_ALIASES, required=("uid",))
    if quic_log.empty:
        return pd.DataFrame(columns=QUIC_COLUMNS)

    rows = []
    for uid, group in quic_log.groupby(resolved["uid"], sort=True, dropna=False):
        packet_sizes = []
        if resolved["packet_sizes"]:
            for value in group[resolved["packet_sizes"]]:
                packet_sizes.extend(_packet_sizes(value))
        mean, std = quic_packet_size_stats(packet_sizes)
        zero_rtt = (
            any(normalize_boolean(value) for value in group[resolved["zero_rtt"]])
            if resolved["zero_rtt"]
            else False
        )
        rows.append(
            {
                "uid": _text(uid),
                "is_quic": True,
                "quic_0rtt": zero_rtt,
                "quic_pkt_size_mean": mean,
                "quic_pkt_size_std": std,
            }
        )
    return pd.DataFrame(rows, columns=QUIC_COLUMNS)


ENRICHMENT_DEFAULTS = {
    "dns_query_entropy": 0.0,
    "domain_length_mean": 0.0,
    "domain_length_max": 0.0,
    "subdomain_count": 0.0,
    "dns_record_type_a_ratio": 0.0,
    "dns_record_type_txt_ratio": 0.0,
    "dns_query_count": 0,
    "ja3_hash": "",
    "ja3s_hash": "",
    "ja4_hash": "",
    "cipher_suite": "",
    "tls_version": 0.0,
    "is_tls": False,
    **quic_defaults(),
}


def _merge_enrichment(features, enrichment, name):
    if enrichment is None or enrichment.empty:
        return features
    if "uid" not in enrichment.columns:
        raise ValueError(f"{name} enrichment is missing uid")
    if enrichment["uid"].duplicated().any():
        raise ValueError(f"{name} enrichment contains duplicate uid rows")
    return features.merge(enrichment, on="uid", how="left", validate="one_to_one")


def enrich_conn_features(conn_features, dns_features=None, tls_features=None, quic_features=None):
    """Left-join optional metadata while retaining exactly one row per conn.log UID."""
    if "uid" not in conn_features.columns:
        raise ValueError("conn feature rows are missing uid")
    if conn_features["uid"].duplicated().any():
        raise ValueError("conn feature rows must contain exactly one row per uid")

    enriched = conn_features.copy()
    if dns_features is not None:
        enriched = _merge_enrichment(
            enriched, _dns_window_features(enriched, dns_features), "DNS"
        )
    enriched = _merge_enrichment(enriched, tls_features, "TLS")
    enriched = _merge_enrichment(enriched, quic_features, "QUIC")
    for column, default in ENRICHMENT_DEFAULTS.items():
        if column not in enriched.columns:
            enriched[column] = default
        else:
            enriched[column] = enriched[column].map(
                lambda value: default if pd.isna(value) else value
            )
    return enriched


SCHEMA_COLUMNS = tuple(FeatureRow.__dataclass_fields__)
SCHEMA_DEFAULTS = {**ENRICHMENT_DEFAULTS, "cipher_suite_enc": 0, "ja4_hash_enc": 0, "label": None}
STRING_SCHEMA_FIELDS = {"flow_id", "src_ip", "dst_ip", "protocol", "ja3_hash", "ja3s_hash", "ja4_hash"}
INT_SCHEMA_FIELDS = {
    "src_port",
    "dst_port",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
    "unique_dst_ips",
    "unique_dst_ports",
    "dns_query_count",
    "cipher_suite_enc",
}
BOOL_SCHEMA_FIELDS = {"is_tls", "is_quic", "quic_0rtt"}


def _required_schema_value(record, field):
    value = record.get(field, SCHEMA_DEFAULTS.get(field))
    if value is None and field not in SCHEMA_DEFAULTS:
        raise ValueError(f"feature row is missing required schema field: {field}")
    return value


def apply_categorical_encoders(feature_rows, ja4_mapping=None, cipher_mapping=None):
    """Apply persisted training-time mappings without fitting from the current batch."""
    encoded = feature_rows.copy()
    for raw_column, encoded_column, mapping in (
        ("ja4_hash", "ja4_hash_enc", ja4_mapping),
        ("cipher_suite", "cipher_suite_enc", cipher_mapping),
    ):
        if raw_column not in encoded.columns:
            if encoded_column not in encoded.columns:
                encoded[encoded_column] = 0
            continue
        values = encoded[raw_column]
        encoded[encoded_column] = [
            _parse_required_int(mapping.get(_text(value), 0), encoded_column) if mapping else 0
            for value in values
        ]
    return encoded


def normalize_to_schema(enriched_features, ja4_mapping=None, cipher_mapping=None):
    """Construct raw FeatureRow-compatible rows using optional persisted encoders."""
    if "uid" not in enriched_features.columns:
        raise ValueError("feature rows are missing uid")
    enriched_features = apply_categorical_encoders(
        enriched_features, ja4_mapping=ja4_mapping, cipher_mapping=cipher_mapping
    )
    rows = []
    for record in enriched_features.to_dict("records"):
        uid = _text(record.get("uid"))
        if not uid:
            raise ValueError("feature row has an invalid required uid")
        record["flow_id"] = uid
        for field in ("flow_id", "src_ip", "dst_ip", "protocol"):
            if not _text(record.get(field)):
                raise ValueError(f"feature row has an invalid required schema field: {field}")
        if record["protocol"] not in {"tcp", "udp", "icmp"}:
            raise ValueError("feature row has an invalid required schema field: protocol")

        schema_row = {}
        for field in SCHEMA_COLUMNS:
            value = _required_schema_value(record, field)
            if field in STRING_SCHEMA_FIELDS:
                schema_row[field] = _text(value)
            elif field in BOOL_SCHEMA_FIELDS:
                schema_row[field] = normalize_boolean(value)
            elif field in INT_SCHEMA_FIELDS:
                schema_row[field] = _parse_required_int(value, field)
            elif field == "label":
                schema_row[field] = None if value is None else _text(value)
            else:
                number = safe_float(value, None)
                if number is None:
                    raise ValueError(f"feature row has an invalid numeric schema field: {field}")
                schema_row[field] = number

        # FeatureRow construction is the schema contract check before serialisation.
        validated = to_dict(FeatureRow(**schema_row))
        rows.append(validated)

    return pd.DataFrame(rows, columns=SCHEMA_COLUMNS)


def prepare_model_input(feature_rows, ja4_mapping=None, cipher_mapping=None):
    """Build model columns with persisted mappings; absent mappings encode categories as 0 only."""
    encoded = apply_categorical_encoders(
        feature_rows, ja4_mapping=ja4_mapping, cipher_mapping=cipher_mapping
    )
    missing_columns = [column for column in FEATURE_COLUMNS if column not in encoded.columns]
    if missing_columns:
        raise ValueError(f"model input is missing required columns: {', '.join(missing_columns)}")

    model_input = encoded.loc[:, FEATURE_COLUMNS].copy()
    for column in BOOL_COLUMNS:
        model_input[column] = model_input[column].map(lambda value: int(normalize_boolean(value)))
    for column in model_input.columns:
        if column not in BOOL_COLUMNS:
            model_input[column] = model_input[column].map(lambda value: safe_float(value, None))
            if model_input[column].isna().any():
                raise ValueError(f"model input has an invalid numeric value: {column}")
    return model_input


def write_parquet(feature_rows, scenario_name, output_dir="data/features"):
    if not _text(scenario_name):
        raise ValueError("--scenario-name must not be empty when writing Parquet")
    output_path = Path(output_dir) / f"{scenario_name}.parquet"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    feature_rows.loc[:, list(SCHEMA_COLUMNS)].to_parquet(output_path, index=False)
    return output_path


def main():
    parser = argparse.ArgumentParser(description="Compute schema-compatible Zeek feature rows.")
    parser.add_argument("--zeek-dir", required=True, help="Directory containing conn.log")
    parser.add_argument("--scenario-name", help="Scenario name used when writing Parquet")
    parser.add_argument("--output-dir", default="data/features", help="Parquet output directory")
    args = parser.parse_args()

    zeek_dir = Path(args.zeek_dir)
    conn_features = compute_conn_features(read_zeek_conn_log(zeek_dir / "conn.log"))
    dns_path = zeek_dir / "dns.log"
    tls_path = zeek_dir / "ssl.log"
    quic_path = zeek_dir / "quic.log"
    dns_features = compute_dns_features(read_zeek_log(dns_path)) if dns_path.exists() else None
    tls_features = compute_tls_features(read_zeek_log(tls_path)) if tls_path.exists() else None
    quic_features = compute_quic_features(read_zeek_log(quic_path)) if quic_path.exists() else None
    feature_rows = normalize_to_schema(
        enrich_conn_features(conn_features, dns_features, tls_features, quic_features)
    )

    if args.scenario_name:
        output_path = write_parquet(feature_rows, args.scenario_name, args.output_dir)
        print(f"Wrote {len(feature_rows)} feature rows to {output_path}.")
    else:
        print(f"Computed {len(feature_rows)} schema-compatible feature rows. No output file was written.")


if __name__ == "__main__":
    main()
