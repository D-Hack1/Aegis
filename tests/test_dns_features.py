import pandas as pd
import pytest

from features.pipeline import compute_dns_features, enrich_conn_features


DNS_QUERIES = (
    "yrbncq.tunnel.lab",
    "vaaaakavuke.tunnel.lab",
    "lademw4j322uhxehobwwd205sey3liuq.tunnel.lab",
    "ianct.tunnel.lab",
)


def _conn_feature(uid="C1", timestamp=100.0):
    return pd.DataFrame([{"uid": uid, "src_ip": "10.10.0.3", "ts": timestamp}])


def _dns_events(events, qtype_column="qtype_name"):
    return compute_dns_features(
        pd.DataFrame(
            [
                {
                    "uid": uid,
                    "id.orig_h": "10.10.0.3",
                    "ts": timestamp,
                    "query": query,
                    qtype_column: qtypes[0] if qtypes else "NULL",
                }
                for uid, timestamp, query, *qtypes in events
            ]
        )
    )


def _dns_values(conn_features, dns_events):
    return enrich_conn_features(conn_features, dns_features=dns_events).iloc[0]


def _assert_record_type_ratios(row, a, aaaa, txt, mx):
    assert row["dns_record_type_a_ratio"] == pytest.approx(a)
    assert row["dns_record_type_aaaa_ratio"] == pytest.approx(aaaa)
    assert row["dns_record_type_txt_ratio"] == pytest.approx(txt)
    assert row["dns_record_type_mx_ratio"] == pytest.approx(mx)


def test_same_uid_dns_events_after_flow_start_are_all_aggregated():
    row = _dns_values(
        _conn_feature(),
        _dns_events([("C1", 100.0 + index, query) for index, query in enumerate(DNS_QUERIES)]),
    )

    assert row["dns_query_count"] == 4
    assert row["domain_length_mean"] == pytest.approx(24.5)
    assert row["domain_length_max"] == 43.0
    assert row["dns_query_entropy"] == pytest.approx(3.543144, abs=1e-6)


def test_same_source_dns_events_with_a_different_uid_are_excluded():
    row = _dns_values(
        _conn_feature(),
        _dns_events(
            [
                ("C1", 100.0, DNS_QUERIES[0]),
                ("C2", 99.0, DNS_QUERIES[2]),
            ]
        ),
    )

    assert row["dns_query_count"] == 1
    assert row["domain_length_mean"] == len(DNS_QUERIES[0])


def test_missing_uid_uses_existing_backward_source_window_fallback():
    row = _dns_values(
        _conn_feature(uid="", timestamp=100.0),
        _dns_events(
            [
                ("C2", 99.0, DNS_QUERIES[0]),
                ("C3", 101.0, DNS_QUERIES[2]),
            ]
        ),
    )

    assert row["dns_query_count"] == 1
    assert row["domain_length_mean"] == len(DNS_QUERIES[0])


def test_dns_aggregation_is_independent_of_event_order():
    events = [("C1", 100.0 + index, query) for index, query in enumerate(DNS_QUERIES)]
    forward = _dns_values(_conn_feature(), _dns_events(events))
    reverse = _dns_values(_conn_feature(), _dns_events(list(reversed(events))))

    for column in (
        "dns_query_entropy",
        "domain_length_mean",
        "domain_length_max",
        "subdomain_count",
        "dns_record_type_a_ratio",
        "dns_record_type_aaaa_ratio",
        "dns_record_type_txt_ratio",
        "dns_record_type_mx_ratio",
        "dns_query_count",
    ):
        assert forward[column] == pytest.approx(reverse[column])


def test_aaaa_only_queries_have_only_an_aaaa_ratio():
    row = _dns_values(_conn_feature(), _dns_events([("C1", 100.0, DNS_QUERIES[0], "AAAA")]))

    _assert_record_type_ratios(row, 0.0, 1.0, 0.0, 0.0)


def test_mx_only_queries_have_only_an_mx_ratio():
    row = _dns_values(_conn_feature(), _dns_events([("C1", 100.0, DNS_QUERIES[0], "MX")]))

    _assert_record_type_ratios(row, 0.0, 0.0, 0.0, 1.0)


def test_mixed_textual_qtypes_have_equal_ratios():
    row = _dns_values(
        _conn_feature(),
        _dns_events(
            [
                ("C1", 100.0, DNS_QUERIES[0], "A"),
                ("C1", 101.0, DNS_QUERIES[1], "AAAA"),
                ("C1", 102.0, DNS_QUERIES[2], "TXT"),
                ("C1", 103.0, DNS_QUERIES[3], "MX"),
            ]
        ),
    )

    _assert_record_type_ratios(row, 0.25, 0.25, 0.25, 0.25)


def test_numeric_qtypes_have_equal_ratios():
    row = _dns_values(
        _conn_feature(),
        _dns_events(
            [
                ("C1", 100.0, DNS_QUERIES[0], 1),
                ("C1", 101.0, DNS_QUERIES[1], 28),
                ("C1", 102.0, DNS_QUERIES[2], 16),
                ("C1", 103.0, DNS_QUERIES[3], 15),
            ],
            qtype_column="qtype",
        ),
    )

    _assert_record_type_ratios(row, 0.25, 0.25, 0.25, 0.25)


def test_unknown_qtype_contributes_only_to_the_denominator():
    row = _dns_values(
        _conn_feature(),
        _dns_events(
            [
                ("C1", 100.0, DNS_QUERIES[0], "A"),
                ("C1", 101.0, DNS_QUERIES[1], "NULL"),
            ]
        ),
    )

    _assert_record_type_ratios(row, 0.5, 0.0, 0.0, 0.0)


def test_missing_qtype_contributes_only_to_the_denominator():
    row = _dns_values(
        _conn_feature(),
        _dns_events(
            [
                ("C1", 100.0, DNS_QUERIES[0], "A"),
                ("C1", 101.0, DNS_QUERIES[1], None),
            ]
        ),
    )

    _assert_record_type_ratios(row, 0.5, 0.0, 0.0, 0.0)


def test_zero_dns_query_events_have_zero_ratios():
    dns_events = compute_dns_features(
        pd.DataFrame(columns=["uid", "id.orig_h", "ts", "query", "qtype_name"])
    )
    row = _dns_values(_conn_feature(), dns_events)

    _assert_record_type_ratios(row, 0.0, 0.0, 0.0, 0.0)
    assert row["dns_query_count"] == 0


def test_same_uid_mixed_qtypes_are_aggregated():
    row = _dns_values(
        _conn_feature(),
        _dns_events(
            [
                ("C1", 100.0, DNS_QUERIES[0], "A"),
                ("C1", 101.0, DNS_QUERIES[1], "AAAA"),
                ("C1", 102.0, DNS_QUERIES[2], "TXT"),
                ("C1", 103.0, DNS_QUERIES[3], "MX"),
            ]
        ),
    )

    _assert_record_type_ratios(row, 0.25, 0.25, 0.25, 0.25)
    assert row["dns_query_count"] == 4
