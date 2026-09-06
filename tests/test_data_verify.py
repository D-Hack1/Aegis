import math

import pandas as pd

from data.verify import DURABLE_LABEL_VALUES, main, validate_dataframe, validate_file
from features.pipeline import SCHEMA_COLUMNS


def _valid_frame(label="ddos"):
    row = {
        "flow_id": "C1",
        "ts": 1.0,
        "src_ip": "10.10.0.2",
        "dst_ip": "10.10.0.3",
        "src_port": 12345,
        "dst_port": 443,
        "protocol": "tcp",
        "duration": 1.0,
        "packets_per_sec": 2.0,
        "bytes_per_sec": 128.0,
        "outbound_inbound_ratio": 1.0,
        "orig_bytes": 64,
        "resp_bytes": 64,
        "orig_pkts": 1,
        "resp_pkts": 1,
        "fan_out": 1.0,
        "fan_in": 1.0,
        "unique_dst_ips": 1,
        "unique_dst_ports": 1,
        "iat_mean": 0.0,
        "iat_std": 0.0,
        "iat_min": 0.0,
        "iat_max": 0.0,
        "connection_frequency": 1.0,
        "src_ip_entropy": 0.0,
        "periodicity_score": 0.0,
        "dns_query_entropy": 0.0,
        "domain_length_mean": 0.0,
        "domain_length_max": 0.0,
        "subdomain_count": 0.0,
        "dns_record_type_a_ratio": 0.0,
        "dns_record_type_txt_ratio": 0.0,
        "dns_query_count": 0,
        "ja3_hash": "",
        "ja3s_hash": "",
        "tls_version": 0.0,
        "cipher_suite_enc": 0,
        "is_tls": False,
        "ja4_hash": "RAW_JA4",
        "is_quic": False,
        "quic_0rtt": False,
        "quic_pkt_size_mean": 0.0,
        "quic_pkt_size_std": 0.0,
        "label": label,
    }
    return pd.DataFrame([row], columns=SCHEMA_COLUMNS)


def _write(frame, path):
    frame.to_parquet(path, index=False)
    return path


def test_valid_labeled_dataset_passes(tmp_path):
    path = _write(_valid_frame("ddos"), tmp_path / "valid.parquet")

    result = validate_file(path, require_label=True)

    assert result.passed
    assert result.label_counts["ddos"] == 1


def test_empty_parquet_fails(tmp_path):
    result = validate_file(_write(_valid_frame().iloc[0:0], tmp_path / "empty.parquet"))

    assert not result.passed
    assert "dataframe is empty" in result.errors


def test_missing_required_column_fails(tmp_path):
    frame = _valid_frame().drop(columns=["bytes_per_sec"])

    result = validate_file(_write(frame, tmp_path / "missing.parquet"))

    assert not result.passed
    assert any("missing required columns: bytes_per_sec" in error for error in result.errors)


def test_duplicate_flow_ids_fail(tmp_path):
    frame = pd.concat([_valid_frame(), _valid_frame()], ignore_index=True)

    result = validate_file(_write(frame, tmp_path / "duplicate-flow.parquet"))

    assert not result.passed
    assert any("duplicate flow_id values" in error for error in result.errors)


def test_non_finite_and_negative_numeric_values_fail(tmp_path):
    frame = _valid_frame()
    frame.loc[0, "bytes_per_sec"] = math.inf
    frame.loc[0, "orig_bytes"] = -1

    result = validate_file(_write(frame, tmp_path / "invalid-numeric.parquet"))

    assert not result.passed
    assert any("non-finite bytes_per_sec" in error for error in result.errors)
    assert any("invalid non-negative integer orig_bytes" in error for error in result.errors)


def test_invalid_and_valid_labels(tmp_path):
    invalid = _valid_frame("not-a-label")
    valid = _valid_frame("benign")

    invalid_result = validate_file(_write(invalid, tmp_path / "invalid-label.parquet"), require_label=True)
    valid_result = validate_file(_write(valid, tmp_path / "valid-label.parquet"), require_label=True)

    assert not invalid_result.passed
    assert any("invalid labels: not-a-label" in error for error in invalid_result.errors)
    assert valid_result.passed
    assert "ddos" in DURABLE_LABEL_VALUES


def test_ja4_contract_accepts_raw_and_rejects_encoded(tmp_path):
    raw_result = validate_file(_write(_valid_frame(), tmp_path / "raw-ja4.parquet"))
    encoded = _valid_frame()
    encoded["ja4_hash_enc"] = 7
    encoded_result = validate_file(_write(encoded, tmp_path / "encoded-ja4.parquet"))

    assert raw_result.passed
    assert not encoded_result.passed
    assert "unexpected model-only column: ja4_hash_enc" in encoded_result.errors


def test_duplicate_column_names_fail():
    frame = _valid_frame()
    frame.columns = ["flow_id", "flow_id", *frame.columns[2:]]

    result = validate_dataframe(frame)

    assert not result.passed
    assert "duplicate column names: flow_id" in result.errors


def test_cli_exit_codes(tmp_path):
    valid_path = _write(_valid_frame(), tmp_path / "valid-cli.parquet")
    invalid_path = _write(_valid_frame().drop(columns=["flow_id"]), tmp_path / "invalid-cli.parquet")

    assert main([str(valid_path)]) == 0
    assert main([str(invalid_path)]) != 0
