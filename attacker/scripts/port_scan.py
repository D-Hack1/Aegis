import argparse
import ipaddress
import random
import subprocess
import time

from scapy.all import IP, TCP, conf, send, wrpcap


COMMON_PORTS = (21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443)
PROFILES = {
    "fast_sequential": {"start_port": 1, "end_port": 1024, "delay": 0.001},
    "slow_sequential": {"start_port": 1, "end_port": 256, "delay": 0.05},
    "fast_random": {"start_port": 1, "end_port": 1024, "delay": 0.001, "scan_order": "random", "source_port_mode": "random"},
    "slow_random": {"start_port": 1, "end_port": 512, "delay": 0.03, "jitter": 0.01, "scan_order": "random", "source_port_mode": "random"},
    "common_ports": {"ports": COMMON_PORTS, "delay": 0.1},
    "broad_sparse": {"start_port": 1, "end_port": 4096, "port_count": 512, "delay": 0.015, "jitter": 0.005, "scan_order": "random", "source_port_mode": "random"},
}
DEFAULTS = {
    "target": "10.10.0.3",
    "start_port": 1,
    "end_port": 1024,
    "ports": None,
    "port_count": None,
    "target_flows": None,
    "delay": None,
    "jitter": 0.0,
    "scan_order": "sequential",
    "source_port_mode": "sequential",
    "seed": None,
    "profile": None,
    "output": None,
    "mode": "scapy",
}


def parse_ports(value):
    try:
        ports = tuple(int(port) for port in value.split(",") if port)
    except ValueError as error:
        raise argparse.ArgumentTypeError("--ports must be comma-separated integers") from error
    if not ports or any(not 1 <= port <= 65535 for port in ports):
        raise argparse.ArgumentTypeError("--ports must contain ports between 1 and 65535")
    return tuple(dict.fromkeys(ports))


def apply_profile(args):
    profile = getattr(args, "profile", None)
    values = DEFAULTS | (PROFILES[profile] if profile else {}) | vars(args)
    for name, value in values.items():
        setattr(args, name, value)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Run a TCP SYN port scan using Scapy or nmap.",
        argument_default=argparse.SUPPRESS,
    )
    parser.add_argument("--target", help="Target IPv4 address")
    parser.add_argument("--start-port", type=int, help="First destination port")
    parser.add_argument("--end-port", type=int, help="Last destination port")
    parser.add_argument("--ports", type=parse_ports, help="Comma-separated destination ports")
    parser.add_argument("--port-count", type=int, help="Number of ports selected from the range")
    parser.add_argument("--target-flows", type=int, help="Scapy TCP SYN flow count")
    parser.add_argument("--delay", type=float, help="Delay between packets in seconds")
    parser.add_argument("--jitter", type=float, help="Maximum delay jitter in seconds")
    parser.add_argument("--scan-order", choices=("sequential", "random"), help="Destination-port order")
    parser.add_argument("--source-port-mode", choices=("sequential", "random"), help="Source-port selection")
    parser.add_argument("--seed", type=int, help="Seed for reproducible port selection and timing")
    parser.add_argument("--profile", choices=tuple(PROFILES), help="Bounded port-scan traffic profile")
    parser.add_argument("--output", help="Scapy output PCAP file")
    parser.add_argument("--mode", choices=("scapy", "nmap"), help="Scan backend")
    args = parser.parse_args(argv)
    apply_profile(args)
    delay = 0.01 if args.delay is None else args.delay

    try:
        ipaddress.IPv4Address(args.target)
    except ipaddress.AddressValueError:
        parser.error("--target must be a valid IPv4 address")
    if not 1 <= args.start_port <= 65535 or not 1 <= args.end_port <= 65535:
        parser.error("port values must be between 1 and 65535")
    if args.start_port > args.end_port:
        parser.error("--start-port must not be greater than --end-port")
    if args.port_count is not None and args.port_count <= 0:
        parser.error("--port-count must be greater than zero")
    if args.target_flows is not None and args.target_flows <= 0:
        parser.error("--target-flows must be greater than zero")
    if args.target_flows is not None and args.target_flows > 64512:
        parser.error("--target-flows must not exceed 64512")
    if delay < 0:
        parser.error("--delay must be zero or greater")
    if args.jitter < 0:
        parser.error("--jitter must be zero or greater")
    if args.mode == "nmap" and any((args.ports, args.port_count, args.profile, args.jitter, args.scan_order != "sequential", args.source_port_mode != "sequential", args.seed is not None)):
        parser.error("profile and packet-shape options are only supported with --mode scapy")
    if args.mode == "nmap" and args.target_flows is not None:
        parser.error("--target-flows is only supported with --mode scapy")
    if args.mode == "nmap" and args.delay is not None:
        parser.error("--delay is only supported with --mode scapy")
    if args.mode == "nmap" and args.output is not None:
        parser.error("--output is only supported with --mode scapy; capture nmap traffic externally")

    ports = list(args.ports or range(args.start_port, args.end_port + 1))
    if args.port_count is not None:
        if args.port_count > len(ports):
            parser.error("--port-count must not exceed available ports")
        rng = random.Random(args.seed)
        ports = rng.sample(ports, args.port_count) if args.scan_order == "random" else ports[:args.port_count]
    if args.target_flows is not None and args.target_flows < len(ports):
        parser.error("--target-flows must cover every requested destination port")
    args.delay = delay
    args.selected_ports = tuple(ports)
    return args


def build_packets(target, start_port, end_port, target_flows, source_ip, ports=None, scan_order="sequential", source_port_mode="sequential", jitter=0.0, timing_delay=None, rng=None):
    randomizer = rng or random
    selected_ports = list(ports or range(start_port, end_port + 1))
    if scan_order == "random":
        randomizer.shuffle(selected_ports)
    if source_port_mode == "random":
        source_ports = randomizer.sample(range(1024, 65536), target_flows)
    else:
        source_ports = [1024 + index for index in range(target_flows)]
    packets = []
    timestamp = 0.0
    for index in range(target_flows):
        packet = IP(src=source_ip, dst=target) / TCP(
            sport=source_ports[index], dport=selected_ports[index % len(selected_ports)], flags="S"
        )
        if timing_delay is not None:
            packet.time = timestamp
            timestamp += max(0.000001, timing_delay + randomizer.uniform(-jitter, jitter)) if jitter else timing_delay
        packets.append(packet)
    return packets


def main():
    args = parse_args()
    output = args.output or "/pcaps/port_scan_candidate.pcap"

    if args.mode == "nmap":
        command = ["nmap", "-sS", "-p", f"{args.start_port}-{args.end_port}", args.target]
        print(f"Starting nmap SYN scan of {args.target} on ports {args.start_port}-{args.end_port}.")
        try:
            subprocess.run(command, check=True)
        except FileNotFoundError:
            parser.error("nmap is unavailable; install nmap and ensure it is on PATH")
        except subprocess.CalledProcessError as error:
            parser.exit(error.returncode, f"nmap exited with status {error.returncode}.\n")
        return

    target_flows = args.target_flows or len(args.selected_ports)
    source_ip = conf.route.route(args.target)[1]
    rng = random.Random(args.seed) if args.seed is not None else None
    packets = build_packets(
        args.target,
        args.start_port,
        args.end_port,
        target_flows,
        source_ip,
        ports=args.selected_ports,
        scan_order=args.scan_order,
        source_port_mode=args.source_port_mode,
        jitter=args.jitter,
        timing_delay=args.delay if args.profile or args.jitter else None,
        rng=rng,
    )
    print(f"Starting SYN scan of {args.target} across {len(args.selected_ports)} ports.")
    for index, packet in enumerate(packets):
        send(packet, verbose=False)
        if index + 1 < len(packets):
            if args.profile or args.jitter:
                pause = max(0.0, float(packets[index + 1].time) - float(packet.time))
                if pause:
                    time.sleep(pause)
            elif args.delay:
                time.sleep(args.delay)
    wrpcap(output, packets)
    print(f"Completed SYN scan of {args.target}. Wrote {len(packets)} packets to {output}.")


if __name__ == "__main__":
    main()
