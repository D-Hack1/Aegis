from scapy.all import IP, TCP, Raw

from attacker.scripts import port_scan


def test_target_flow_scan_preserves_port_coverage_with_unique_syn_tuples():
    packets = port_scan.build_packets("10.10.0.3", 1, 1024, 1500, "10.10.0.2")
    tuples = {
        (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport, "tcp")
        for packet in packets
    }
    destination_ports = {packet[TCP].dport for packet in packets}

    assert len(packets) == 1500
    assert len(tuples) == 1500
    assert destination_ports == set(range(1, 1025))
    assert all(packet[IP].dst == "10.10.0.3" for packet in packets)
    assert all(packet[TCP].flags == "S" for packet in packets)
    assert all(not packet.haslayer(Raw) for packet in packets)


def test_target_flows_must_cover_every_destination_port():
    try:
        port_scan.parse_args(["--target-flows", "1023"])
    except SystemExit:
        pass
    else:
        raise AssertionError("--target-flows smaller than the port range must be rejected")
