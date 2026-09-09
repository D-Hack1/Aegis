import argparse
import ipaddress
import subprocess
import time

from scapy.all import IP, TCP, conf, send, wrpcap


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Run a TCP SYN port scan using Scapy or nmap.")
    parser.add_argument("--target", default="10.10.0.3", help="Target IPv4 address")
    parser.add_argument("--start-port", type=int, default=1, help="First destination port")
    parser.add_argument("--end-port", type=int, default=1024, help="Last destination port")
    parser.add_argument("--target-flows", type=int, help="Scapy TCP SYN flow count (default: one per destination port)")
    parser.add_argument("--delay", type=float, help="Scapy delay between packets in seconds (default: 0.01)")
    parser.add_argument("--output", help="Scapy output PCAP file (default: data/raw/port_scan_candidate.pcap)")
    parser.add_argument("--mode", choices=("scapy", "nmap"), default="scapy", help="Scan backend (default: scapy)")
    args = parser.parse_args(argv)
    delay = 0.01 if args.delay is None else args.delay

    try:
        ipaddress.IPv4Address(args.target)
    except ipaddress.AddressValueError:
        parser.error("--target must be a valid IPv4 address")

    if not 1 <= args.start_port <= 65535 or not 1 <= args.end_port <= 65535:
        parser.error("port values must be between 1 and 65535")
    if args.start_port > args.end_port:
        parser.error("--start-port must not be greater than --end-port")
    if args.target_flows is not None and args.target_flows <= 0:
        parser.error("--target-flows must be greater than zero")
    if args.target_flows is not None and args.target_flows < args.end_port - args.start_port + 1:
        parser.error("--target-flows must cover every requested destination port")
    if args.target_flows is not None and args.target_flows > 64512:
        parser.error("--target-flows must not exceed 64512")
    if delay < 0:
        parser.error("--delay must be zero or greater")
    if args.mode == "nmap" and args.target_flows is not None:
        parser.error("--target-flows is only supported with --mode scapy")
    if args.mode == "nmap" and args.delay is not None:
        parser.error("--delay is only supported with --mode scapy")
    if args.mode == "nmap" and args.output is not None:
        parser.error("--output is only supported with --mode scapy; capture nmap traffic externally")
    return args


def build_packets(target, start_port, end_port, target_flows, source_ip):
    ports = range(start_port, end_port + 1)
    return [
        IP(src=source_ip, dst=target) / TCP(
            sport=1024 + index, dport=start_port + index % len(ports), flags="S"
        )
        for index in range(target_flows)
    ]


def main():
    args = parse_args()
    delay = 0.01 if args.delay is None else args.delay
    output = args.output or "data/raw/port_scan_candidate.pcap"

    if args.mode == "nmap":
        command = ["nmap", "-sS", "-p", f"{args.start_port}-{args.end_port}", args.target]
        print(f"Starting nmap SYN scan of {args.target} on ports {args.start_port}-{args.end_port}.")
        print("nmap mode does not write a PCAP; capture traffic externally.")
        try:
            subprocess.run(command, check=True)
        except FileNotFoundError:
            parser.error("nmap is unavailable; install nmap and ensure it is on PATH")
        except subprocess.CalledProcessError as error:
            parser.exit(error.returncode, f"nmap exited with status {error.returncode}.\n")
        return

    print(f"Starting SYN scan of {args.target} on ports {args.start_port}-{args.end_port}.")
    target_flows = args.target_flows or args.end_port - args.start_port + 1
    source_ip = conf.route.route(args.target)[1]
    packets = build_packets(args.target, args.start_port, args.end_port, target_flows, source_ip)
    for packet in packets:
        send(packet, verbose=False)
        if delay:
            time.sleep(delay)
    wrpcap(output, packets)
    print(f"Completed SYN scan of {args.target} on ports {args.start_port}-{args.end_port}. Wrote {len(packets)} packets to {output}.")


if __name__ == "__main__":
    main()
