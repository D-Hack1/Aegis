import random
import sys

from scapy.all import IP, TCP, Raw

from attacker.scripts import port_scan


def run_scan_main(monkeypatch, arguments):
    sleeps = []
    monkeypatch.setattr(sys, "argv", ["port_scan.py", *arguments])
    monkeypatch.setattr(port_scan.conf.route, "route", lambda target: ("", "10.10.0.2", ""))
    monkeypatch.setattr(port_scan, "send", lambda packet, verbose=False: None)
    monkeypatch.setattr(port_scan, "wrpcap", lambda output, packets: None)
    monkeypatch.setattr(port_scan.time, "sleep", sleeps.append)
    port_scan.main()
    return sleeps


def test_default_cli_preserves_scan_defaults():
    args = port_scan.parse_args([])

    assert args.start_port == 1
    assert args.end_port == 1024
    assert args.delay == 0.01
    assert args.scan_order == "sequential"
    assert args.source_port_mode == "sequential"


def test_profile_applies_profile_values():
    args = port_scan.parse_args(["--profile", "slow_random"])

    assert args.start_port == 1
    assert args.end_port == 512
    assert args.target_flows is None
    assert args.delay == 0.03
    assert args.jitter == 0.01
    assert args.scan_order == "random"
    assert args.source_port_mode == "random"


def test_explicit_values_override_port_scan_profile_values():
    args = port_scan.parse_args(
        [
            "--profile",
            "broad_sparse",
            "--start-port",
            "100",
            "--end-port",
            "110",
            "--ports",
            "80,443,8080",
            "--port-count",
            "2",
            "--jitter",
            "0.001",
            "--scan-order",
            "sequential",
            "--source-port-mode",
            "sequential",
            "--seed",
            "7",
        ]
    )

    assert args.start_port == 100
    assert args.end_port == 110
    assert args.port_count == 2
    assert args.selected_ports == (80, 443)
    assert args.jitter == 0.001
    assert args.scan_order == "sequential"
    assert args.source_port_mode == "sequential"
    assert args.seed == 7
    assert args.target_flows is None
    assert args.delay == 0.015


def test_explicit_port_count_with_a_profile_controls_default_flow_count():
    args = port_scan.parse_args(
        ["--profile", "slow_sequential", "--port-count", "40"]
    )
    packets = port_scan.build_packets(
        args.target,
        args.start_port,
        args.end_port,
        args.target_flows or len(args.selected_ports),
        "10.10.0.2",
        ports=args.selected_ports,
    )

    assert len(args.selected_ports) == 40
    assert args.target_flows is None
    assert len(packets) == 40
    assert args.delay == 0.05


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


def test_random_profile_is_seeded_and_covers_requested_ports():
    args = port_scan.parse_args(["--profile", "slow_random", "--seed", "7"])
    first = port_scan.build_packets(
        args.target, args.start_port, args.end_port, args.target_flows or len(args.selected_ports), "10.10.0.2",
        ports=args.selected_ports, scan_order=args.scan_order, source_port_mode=args.source_port_mode,
        jitter=args.jitter, timing_delay=args.delay, rng=random.Random(args.seed),
    )
    second = port_scan.build_packets(
        args.target, args.start_port, args.end_port, args.target_flows or len(args.selected_ports), "10.10.0.2",
        ports=args.selected_ports, scan_order=args.scan_order, source_port_mode=args.source_port_mode,
        jitter=args.jitter, timing_delay=args.delay, rng=random.Random(args.seed),
    )

    assert [bytes(packet) for packet in first] == [bytes(packet) for packet in second]
    assert {packet[TCP].dport for packet in first} == set(args.selected_ports)
    assert len({packet[TCP].sport for packet in first}) == len(first)


def test_port_count_must_be_positive():
    try:
        port_scan.parse_args(["--port-count", "0"])
    except SystemExit:
        pass
    else:
        raise AssertionError("--port-count zero must be rejected")


def test_standalone_jitter_changes_send_timing(monkeypatch):
    sleeps = run_scan_main(
        monkeypatch,
        [
            "--start-port", "1", "--end-port", "3", "--delay", "0.2",
            "--jitter", "0.05", "--seed", "7",
        ],
    )

    assert len(sleeps) == 2
    assert any(abs(sleep - 0.2) > 1e-9 for sleep in sleeps)


def test_explicit_jitter_overrides_profile_timing(monkeypatch):
    sleeps = run_scan_main(
        monkeypatch,
        [
            "--profile", "slow_random", "--start-port", "1", "--end-port", "3",
            "--jitter", "0.001", "--seed", "7",
        ],
    )

    assert len(sleeps) == 2
    assert all(0.029 <= sleep <= 0.031 for sleep in sleeps)
    assert any(abs(sleep - 0.03) > 1e-9 for sleep in sleeps)


def test_zero_jitter_preserves_fixed_delay_timing(monkeypatch):
    sleeps = run_scan_main(
        monkeypatch,
        [
            "--start-port", "1", "--end-port", "3", "--delay", "0.2",
            "--jitter", "0", "--seed", "7",
        ],
    )

    assert sleeps == [0.2, 0.2]
