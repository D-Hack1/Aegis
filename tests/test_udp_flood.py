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
