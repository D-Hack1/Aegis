import argparse
import codecs
import ipaddress
import math
from collections import Counter, defaultdict, deque
from pathlib import Path

import pandas as pd


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


def safe_float(value, default=0.0):
    """Convert Zeek values to finite floats, treating '-' as missing."""
    if value is None or (isinstance(value, str) and value.strip() in {"", "-"}):
        return default
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if math.isfinite(number) else default


def safe_int(value, default=0):
    """Convert Zeek integer values to ints, treating '-' as missing."""
    return int(safe_float(value, default))


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


def read_zeek_conn_log(path):
    """Read a Zeek TSV conn.log while preserving its #fields column names."""
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
                    raise ValueError("Zeek conn.log is missing a #fields header")
                values = line.split(separator)
                if len(values) != len(fields):
                    raise ValueError("Zeek conn.log row does not match the #fields header")
                rows.append([None if value == "-" else value for value in values])

    if fields is None:
        raise ValueError("Zeek conn.log is missing a #fields header")
    return pd.DataFrame(rows, columns=fields)


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

    normalized = conn_log.loc[:, REQUIRED_CONN_COLUMNS].copy()
    normalized["uid"] = normalized["uid"].map(lambda value: "" if value is None else str(value))
    normalized["ts"] = normalized["ts"].map(_parse_timestamp)
    normalized["id.orig_h"] = normalized["id.orig_h"].map(_clean_ip)
    normalized["id.resp_h"] = normalized["id.resp_h"].map(_clean_ip)

    for column in ("id.orig_p", "id.resp_p"):
        normalized[column] = normalized[column].map(safe_int)
    for column in ("duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"):
        normalized[column] = normalized[column].map(lambda value: max(safe_float(value), 0.0))

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

    # Integration boundary: Ebin's features/schema.py will validate and convert these rows later.
    return pd.DataFrame(feature_rows)


def main():
    parser = argparse.ArgumentParser(description="Compute in-memory conn.log feature rows.")
    parser.add_argument("--zeek-dir", required=True, help="Directory containing conn.log")
    args = parser.parse_args()

    conn_log = read_zeek_conn_log(Path(args.zeek_dir) / "conn.log")
    feature_rows = compute_conn_features(conn_log)
    print(f"Computed {len(feature_rows)} conn.log feature rows. No output file was written.")


if __name__ == "__main__":
    main()
