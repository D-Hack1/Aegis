import pytest

from features.pipeline import _parse_required_int, compute_conn_features, read_zeek_conn_log


def _write_conn_log(tmp_path, orig_bytes, resp_bytes="64", orig_pkts="2", resp_pkts="1"):
    conn_log_path = tmp_path / "conn.log"
    conn_log_path.write_text(
        "#separator \\x09\n"
        "#fields\tuid\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\t"
        "orig_bytes\tresp_bytes\tconn_state\torig_pkts\tresp_pkts\n"
        f"CSYN\t1710000000.0\t192.0.2.10\t53124\t198.51.100.25\t443\ttcp\t0.0\t"
        f"{orig_bytes}\t{resp_bytes}\tS0\t{orig_pkts}\t{resp_pkts}\n",
        encoding="utf-8",
    )
    return conn_log_path


def test_parse_required_int_accepts_zeek_missing_sentinel():
    assert _parse_required_int("-", "orig_bytes") == 0


def test_parse_required_int_preserves_valid_and_malformed_value_handling():
    assert _parse_required_int("42", "orig_bytes") == 42
    assert _parse_required_int(42, "orig_bytes") == 42

    with pytest.raises(ValueError, match="invalid required integer field: orig_bytes"):
        _parse_required_int("12x", "orig_bytes")


def test_incomplete_zeek_conn_flow_with_missing_numeric_values_is_normalized(tmp_path):
    conn_log = read_zeek_conn_log(_write_conn_log(tmp_path, "-", "-", "-", "-"))
    assert conn_log.loc[0, ["orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]].tolist() == [
        "-", "-", "-", "-",
    ]

    features = compute_conn_features(conn_log)

    row = features.iloc[0]
    assert row["orig_bytes"] == 0
    assert row["resp_bytes"] == 0
    assert row["orig_pkts"] == 0
    assert row["resp_pkts"] == 0


def test_blank_required_conn_integer_is_not_converted_to_zeek_sentinel(tmp_path):
    conn_log = read_zeek_conn_log(_write_conn_log(tmp_path, ""))

    assert conn_log.loc[0, "orig_bytes"] == ""
    with pytest.raises(ValueError, match="invalid required integer field: orig_bytes"):
        compute_conn_features(conn_log)


def test_numeric_conn_values_remain_unchanged(tmp_path):
    features = compute_conn_features(read_zeek_conn_log(_write_conn_log(tmp_path, "128")))

    row = features.iloc[0]
    assert row["orig_bytes"] == 128
    assert row["resp_bytes"] == 64
    assert row["orig_pkts"] == 2
    assert row["resp_pkts"] == 1


def test_malformed_required_conn_integer_is_rejected(tmp_path):
    conn_log = read_zeek_conn_log(_write_conn_log(tmp_path, "12x"))

    with pytest.raises(ValueError, match="invalid required integer field: orig_bytes"):
        compute_conn_features(conn_log)
