import pandas as pd
import pytest

from features.pipeline import SCHEMA_COLUMNS, normalize_to_schema, prepare_model_input, write_parquet
from features.schema import FEATURE_COLUMNS, FeatureRow


def _raw_row(ja4_hash, uid="C1"):
    return {
        "uid": uid,
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
        "ja4_hash": ja4_hash,
        # Normalization must discard model-only input fields from durable output.
        "ja4_hash_enc": 999,
    }


def _normalized_rows(*ja4_hashes):
    return normalize_to_schema(
        pd.DataFrame([_raw_row(ja4_hash, uid=f"C{index}") for index, ja4_hash in enumerate(ja4_hashes)])
    )


def test_raw_ja4_is_durable_and_encoded_ja4_is_model_only():
    normalized = _normalized_rows("KNOWN_HASH")

    assert "ja4_hash" in FeatureRow.__dataclass_fields__
    assert "ja4_hash_enc" not in FeatureRow.__dataclass_fields__
    assert "ja4_hash" in SCHEMA_COLUMNS
    assert "ja4_hash_enc" not in SCHEMA_COLUMNS
    assert normalized.loc[0, "ja4_hash"] == "KNOWN_HASH"
    assert "ja4_hash_enc" not in normalized.columns


def test_parquet_round_trip_preserves_raw_ja4_only(tmp_path):
    pytest.importorskip("pyarrow", reason="Parquet round-trip requires the project Parquet engine")
    normalized = _normalized_rows("KNOWN_HASH")

    output_path = write_parquet(normalized, "ja4_contract", tmp_path)
    stored = pd.read_parquet(output_path)

    assert stored.loc[0, "ja4_hash"] == "KNOWN_HASH"
    assert "ja4_hash_enc" not in stored.columns


def test_model_preparation_uses_only_supplied_ja4_mapping():
    normalized = _normalized_rows("KNOWN_HASH", "UNKNOWN_HASH", "", None)

    model_input = prepare_model_input(normalized, ja4_mapping={"KNOWN_HASH": 7})

    assert list(model_input.columns) == FEATURE_COLUMNS
    assert "ja4_hash_enc" in model_input.columns
    assert "ja4_hash" not in model_input.columns
    assert model_input["ja4_hash_enc"].tolist() == [7.0, 0.0, 0.0, 0.0]


def test_model_preparation_never_fits_ja4_mapping_from_batch():
    normalized = _normalized_rows("UNMAPPED_A", "UNMAPPED_B")
    normalized["cipher_suite"] = ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"]

    model_input = prepare_model_input(
        normalized,
        ja4_mapping={"KNOWN_HASH": 7},
        cipher_mapping={"TLS_AES_128_GCM_SHA256": 3},
    )

    assert model_input["ja4_hash_enc"].tolist() == [0.0, 0.0]
    assert model_input["cipher_suite_enc"].tolist() == [3.0, 0.0]
