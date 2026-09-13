import random

import pytest
from scapy.all import IP, UDP

from attacker.scripts import udp_flood


def _spoof_pool(size):
    return [
        (f"198.51.{index // 254}.{index % 254 + 1}", 1024 + index)
        for index in range(size)
    ]


def test_default_cli_uses_fifteen_hundred_spoofed_flow_identities():
    args = udp_flood.parse_args([])

    assert args.spoof_pool_size == 1500
    assert args.pps == 150
    assert args.target == "10.10.0.3"
    assert args.port == 53
    assert args.duration == 10
    assert args.target_ports == (53,)


def test_profile_applies_profile_values():
    args = udp_flood.parse_args(["--profile", "low_steady"])

    assert args.pps == 50
    assert args.duration == 20.0
    assert args.payload_size == 256
    assert args.payload_variation == 64
    assert args.spoof_pool_size == 1000
    assert args.target_ports == (53,)


def test_explicit_values_override_udp_profile_values():
    args = udp_flood.parse_args(
        [
            "--profile",
            "bursty",
            "--pps",
            "42",
            "--duration",
            "1.5",
            "--target-ports",
            "53,443",
            "--payload-size",
            "600",
            "--payload-variation",
            "100",
            "--jitter",
            "0.01",
            "--burst-size",
            "2",
            "--burst-gap",
            "0.05",
            "--seed",
            "7",
        ]
    )

    assert args.pps == 42
    assert args.duration == 1.5
    assert args.target_ports == (53, 443)
    assert args.payload_size == 600
    assert args.payload_variation == 100
    assert args.jitter == 0.01
    assert args.burst_size == 2
    assert args.burst_gap == 0.05
    assert args.seed == 7
    assert args.spoof_pool_size == 1600


def test_invalid_spoof_pool_size_is_rejected():
    with pytest.raises(SystemExit):
        udp_flood.parse_args(["--spoof-pool-size", "0"])


def test_spoof_pool_rejects_duplicate_identity_pairs(monkeypatch):
    source_ips = iter(["198.51.100.1", "198.51.100.1", "198.51.100.2"])
    source_ports = iter([5000, 5000, 5001])
    monkeypatch.setattr(udp_flood, "random_source_ip", lambda victim_ip: next(source_ips))
    monkeypatch.setattr(udp_flood.random, "randint", lambda lower, upper: next(source_ports))

    pool = udp_flood.build_spoof_pool("10.10.0.3", 2)

    assert pool == [("198.51.100.1", 5000), ("198.51.100.2", 5001)]


def test_packets_cycle_stable_spoofed_flows_without_changing_destination():
    pool = _spoof_pool(1500)
    packets = udp_flood.build_packets("10.10.0.3", 53, 1500, 1, b"x", pool)
    identities = {(packet[IP].src, packet[UDP].sport) for packet in packets}
    tuples = {
        (packet[IP].src, packet[UDP].sport, packet[IP].dst, packet[UDP].dport, "udp")
        for packet in packets
    }

    assert len(identities) == 1500
    assert len(tuples) == 1500
    assert all(packet[IP].dst == "10.10.0.3" for packet in packets)
    assert all(packet[UDP].dport == 53 for packet in packets)
    assert all(packet[IP].src != "10.10.0.3" for packet in packets)
    assert len(packets) == 1500


def test_profile_is_seeded_and_varies_payloads_and_ports():
    args = udp_flood.parse_args(["--profile", "multi_port", "--seed", "7"])
    first_pool = udp_flood.build_spoof_pool("10.10.0.3", 12, random.Random(args.seed))
    second_pool = udp_flood.build_spoof_pool("10.10.0.3", 12, random.Random(args.seed))
    packets = udp_flood.build_packets(
        args.target,
        args.port,
        args.pps,
        1,
        b"A" * args.payload_size,
        first_pool,
        target_ports=args.target_ports,
        payload_variation=args.payload_variation,
        rng=random.Random(args.seed),
    )

    assert first_pool == second_pool
    assert {packet[UDP].dport for packet in packets} == set(args.target_ports)
    assert len({len(bytes(packet[UDP].payload)) for packet in packets}) > 1


def test_payload_variation_must_preserve_positive_payloads():
    with pytest.raises(SystemExit):
        udp_flood.parse_args(["--payload-variation", "1200"])
