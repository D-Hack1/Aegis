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
