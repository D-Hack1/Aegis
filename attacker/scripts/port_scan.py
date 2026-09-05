import argparse
import ipaddress
import time

from scapy.all import IP, TCP, send


def main():
    parser = argparse.ArgumentParser(description="Send a sequential TCP SYN port scan.")
    parser.add_argument("--target", default="10.10.0.3", help="Target IPv4 address")
    parser.add_argument("--start-port", type=int, default=1, help="First destination port")
    parser.add_argument("--end-port", type=int, default=1024, help="Last destination port")
    parser.add_argument("--delay", type=float, default=0.01, help="Delay between packets in seconds")
    args = parser.parse_args()

    try:
        ipaddress.IPv4Address(args.target)
    except ipaddress.AddressValueError:
        parser.error("--target must be a valid IPv4 address")

    if not 1 <= args.start_port <= 65535 or not 1 <= args.end_port <= 65535:
        parser.error("port values must be between 1 and 65535")
    if args.start_port > args.end_port:
        parser.error("--start-port must not be greater than --end-port")
    if args.delay < 0:
        parser.error("--delay must be zero or greater")

    print(f"Starting SYN scan of {args.target} on ports {args.start_port}-{args.end_port}.")
    for port in range(args.start_port, args.end_port + 1):
        send(IP(dst=args.target) / TCP(dport=port, flags="S"), verbose=False)
        if args.delay:
            time.sleep(args.delay)
    print(f"Completed SYN scan of {args.target} on ports {args.start_port}-{args.end_port}.")


if __name__ == "__main__":
    main()
