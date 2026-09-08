"""
Pipeline contract test for ja3.zeek and quic.zeek outputs.
Validates that features/pipeline.py correctly parses synthetic Zeek logs
that match exactly what our Zeek scripts will produce.

Run from Aegis/:
    python _test_pipeline_contract.py
"""
import sys
import pathlib
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from features.pipeline import (
    read_zeek_conn_log,
    read_zeek_log,
    compute_conn_features,
    compute_tls_features,
    compute_quic_features,
    enrich_conn_features,
    normalize_to_schema,
)

def make_logs():
    tmp = pathlib.Path(tempfile.mkdtemp())

    # conn.log — one TCP/443 flow (TLS) and one UDP/443 flow (QUIC-like)
    # Zeek TSV format: #separator line contains the LITERAL text \x09 (not a tab).
    # The pipeline's read_zeek_log() decodes it with codecs.decode("unicode_escape").
    SEP_LINE = "#separator \\x09\n"
    (tmp / "conn.log").write_text(
        SEP_LINE
        + "#set_separator ,\n"
        + "#empty_field (empty)\n"
        + "#unset_field -\n"
        + "#path conn\n"
        + "#fields uid\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\n"
        + "#types string\ttime\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tcount\tcount\n"
        + "CaBC001\t1700000000.0\t10.10.0.2\t54321\t10.10.0.3\t443\ttcp\tssl\t1.0\t1000\t2000\t10\t8\n"
        + "CaBC002\t1700000001.0\t10.10.0.4\t12345\t10.10.0.3\t443\tudp\t-\t0.5\t100\t0\t5\t0\n"
    )

    # ssl.log — what ja3.zeek produces: adds ja3 and ja3s columns to native ssl.log
    (tmp / "ssl.log").write_text(
        SEP_LINE
        + "#set_separator ,\n"
        + "#empty_field (empty)\n"
        + "#unset_field -\n"
        + "#path ssl\n"
        + "#fields uid\tts\tversion\tcipher\tja3\tja3s\n"
        + "#types string\ttime\tstring\tstring\tstring\tstring\n"
        + "CaBC001\t1700000000.1\tTLSv12\tTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\tabc123def456abc123def456abc12345\t987654321098765432109876543210ab\n"
    )

    # quic.log — what quic.zeek produces: uid, ts, addr/port fields, is_quic=T, zero_rtt=F
    (tmp / "quic.log").write_text(
        SEP_LINE
        + "#set_separator ,\n"
        + "#empty_field (empty)\n"
        + "#unset_field -\n"
        + "#path quic\n"
        + "#fields uid\tts\torig_h\torig_p\tresp_h\tresp_p\tis_quic\tzero_rtt\n"
        + "#types string\ttime\taddr\tport\taddr\tport\tbool\tbool\n"
        + "CaBC002\t1700000001.0\t10.10.0.4\t12345\t10.10.0.3\t443\tT\tF\n"
    )

    return tmp


def run():
    print("=== Pipeline Contract Test: ja3.zeek + quic.zeek outputs ===\n")

    tmp = make_logs()
    print(f"Synthetic logs: {tmp}\n")

    # Parse
    conn_features = compute_conn_features(read_zeek_conn_log(tmp / "conn.log"))
    tls_features  = compute_tls_features(read_zeek_log(tmp / "ssl.log"))
    quic_features = compute_quic_features(read_zeek_log(tmp / "quic.log"))

    print(f"conn rows : {len(conn_features)}")
    print(f"tls rows  : {len(tls_features)}")
    print(f"quic rows : {len(quic_features)}")
    print(f"\nTLS columns  : {list(tls_features.columns)}")
    print(f"QUIC columns : {list(quic_features.columns)}\n")

    # Enrich and normalise to schema
    enriched    = enrich_conn_features(conn_features, tls_features=tls_features, quic_features=quic_features)
    schema_rows = normalize_to_schema(enriched)
    print(f"Schema rows  : {len(schema_rows)}\n")

    tcp_row = schema_rows[schema_rows["flow_id"] == "CaBC001"].iloc[0]
    udp_row = schema_rows[schema_rows["flow_id"] == "CaBC002"].iloc[0]

    # --- Assertions ---
    failures = []

    def check(name, got, expected):
        if got != expected:
            failures.append(f"  FAIL {name}: expected {expected!r}, got {got!r}")
        else:
            print(f"  PASS {name}: {got!r}")

    print("TLS flow (CaBC001):")
    check("ja3_hash",  tcp_row["ja3_hash"],  "abc123def456abc123def456abc12345")
    check("ja3s_hash", tcp_row["ja3s_hash"], "987654321098765432109876543210ab")
    check("is_tls",    tcp_row["is_tls"],    True)
    check("is_quic",   tcp_row["is_quic"],   False)

    print("\nQUIC-like flow (CaBC002):")
    check("is_quic",           udp_row["is_quic"],           True)
    check("quic_0rtt",         udp_row["quic_0rtt"],         False)
    check("quic_pkt_size_mean",udp_row["quic_pkt_size_mean"],0.0)
    check("quic_pkt_size_std", udp_row["quic_pkt_size_std"], 0.0)
    check("is_tls",            udp_row["is_tls"],            False)
    check("ja3_hash",          udp_row["ja3_hash"],          "")

    print()
    if failures:
        print("FAILURES:")
        for f in failures:
            print(f)
        sys.exit(1)
    else:
        print("All assertions passed. Pipeline contract satisfied.")


if __name__ == "__main__":
    run()
