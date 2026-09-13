import random

import pytest
from scapy.all import IP, Raw, TCP

from attacker.scripts import syn_flood


def _spoof_pool(size):
    return [
        (f"198.51.{index // 254}.{index % 254 + 1}", 1024 + index)
        for index in range(size)
    ]


def test_default_cli_uses_fifteen_hundred_spoofed_flow_identities():
    args = syn_flood.parse_args([])

    assert args.spoof_pool_size == 1500
    assert args.pps == 150
    assert args.duration == 10
    assert args.target_ports == (80,)


def test_profile_applies_profile_values():
    args = syn_flood.parse_args(["--profile", "low_steady"])

    assert args.pps == 50
    assert args.duration == 20.0
    assert args.spoof_pool_size == 1000
    assert args.target_ports == (80,)


def test_explicit_values_override_syn_profile_values():
    args = syn_flood.parse_args(
        [
            "--profile",
            "bursty",
            "--pps",
            "42",
            "--duration",
            "1.5",
            "--target-ports",
            "22,443",
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
    assert args.target_ports == (22, 443)
    assert args.jitter == 0.01
    assert args.burst_size == 2
    assert args.burst_gap == 0.05
    assert args.seed == 7
    assert args.spoof_pool_size == 1500


def test_packets_cycle_unique_syn_flows_without_changing_destination():
    packets = syn_flood.build_packets("10.10.0.3", 80, 1500, 1, _spoof_pool(1500))
    identities = {(packet[IP].src, packet[TCP].sport) for packet in packets}
    tuples = {
        (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport, "tcp")
        for packet in packets
    }

    assert len(packets) == 1500
    assert len(identities) == 1500
    assert len(tuples) == 1500
    assert all(packet[IP].dst == "10.10.0.3" for packet in packets)
    assert all(packet[TCP].dport == 80 for packet in packets)
    assert all(packet[TCP].flags == "S" for packet in packets)
    assert all(not packet.haslayer(Raw) for packet in packets)


def test_profile_is_seeded_and_preserves_syn_semantics():
    args = syn_flood.parse_args(["--profile", "multi_port", "--seed", "7"])
    first_pool = syn_flood.build_spoof_pool("10.10.0.3", 12, random.Random(args.seed))
    second_pool = syn_flood.build_spoof_pool("10.10.0.3", 12, random.Random(args.seed))
    packets = syn_flood.build_packets(
        args.target, args.port, args.pps, 1, first_pool, target_ports=args.target_ports, rng=random.Random(args.seed)
    )

    assert first_pool == second_pool
    assert {packet[TCP].dport for packet in packets} == set(args.target_ports)
    assert all(packet[TCP].flags == "S" for packet in packets)


def test_negative_jitter_is_rejected():
    with pytest.raises(SystemExit):
        syn_flood.parse_args(["--jitter", "-0.1"])
