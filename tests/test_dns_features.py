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


def _dns_events(events):
    return compute_dns_features(
        pd.DataFrame(
            [
                {
                    "uid": uid,
                    "id.orig_h": "10.10.0.3",
                    "ts": timestamp,
                    "query": query,
                    "qtype_name": "NULL",
                }
                for uid, timestamp, query in events
            ]
        )
    )


def _dns_values(conn_features, dns_events):
    return enrich_conn_features(conn_features, dns_features=dns_events).iloc[0]


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
        "dns_record_type_txt_ratio",
        "dns_query_count",
    ):
        assert forward[column] == pytest.approx(reverse[column])
