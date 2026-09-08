import argparse
import ipaddress
import subprocess
import time

from scapy.all import IP, TCP, send, wrpcap


def main():
    parser = argparse.ArgumentParser(description="Run a TCP SYN port scan using Scapy or nmap.")
    parser.add_argument("--target", default="10.10.0.3", help="Target IPv4 address")
    parser.add_argument("--start-port", type=int, default=1, help="First destination port")
    parser.add_argument("--end-port", type=int, default=1024, help="Last destination port")
    parser.add_argument("--delay", type=float, help="Scapy delay between packets in seconds (default: 0.01)")
    parser.add_argument("--output", help="Scapy output PCAP file (default: data/raw/port_scan_candidate.pcap)")
    parser.add_argument("--mode", choices=("scapy", "nmap"), default="scapy", help="Scan backend (default: scapy)")
    args = parser.parse_args()
    delay = 0.01 if args.delay is None else args.delay
    output = args.output or "data/raw/port_scan_candidate.pcap"

    try:
        ipaddress.IPv4Address(args.target)
    except ipaddress.AddressValueError:
        parser.error("--target must be a valid IPv4 address")

    if not 1 <= args.start_port <= 65535 or not 1 <= args.end_port <= 65535:
        parser.error("port values must be between 1 and 65535")
    if args.start_port > args.end_port:
        parser.error("--start-port must not be greater than --end-port")
    if delay < 0:
        parser.error("--delay must be zero or greater")

    if args.mode == "nmap":
        if args.delay is not None:
            parser.error("--delay is only supported with --mode scapy")
        if args.output is not None:
            parser.error("--output is only supported with --mode scapy; capture nmap traffic externally")
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
    packets = []
    for port in range(args.start_port, args.end_port + 1):
        packet = IP(dst=args.target) / TCP(dport=port, flags="S")
        packets.append(packet)
        send(packet, verbose=False)
        if delay:
            time.sleep(delay)
    wrpcap(output, packets)
    print(f"Completed SYN scan of {args.target} on ports {args.start_port}-{args.end_port}. Wrote {len(packets)} packets to {output}.")


if __name__ == "__main__":
    main()
