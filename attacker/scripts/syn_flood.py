import argparse
import ipaddress
import random
import time

from scapy.all import IP, TCP, wrpcap


def random_source_ip(victim_ip):
    while True:
        source_ip = ipaddress.IPv4Address(random.getrandbits(32))
        if source_ip.is_global and source_ip != victim_ip:
            return str(source_ip)


def build_spoof_pool(victim_ip, pool_size):
    pool = []
    for _ in range(pool_size):
        src_ip = random_source_ip(victim_ip)
        src_port = random.randint(1024, 65535)
        pool.append((src_ip, src_port))
    return pool


def main():
    parser = argparse.ArgumentParser(description="Generate a TCP SYN flood PCAP with spoofed source addresses.")
    parser.add_argument("--target", default="10.10.0.3", help="Target IPv4 address")
    parser.add_argument("--port", type=int, default=80, help="Target TCP port")
    parser.add_argument("--pps", type=int, default=100, help="Packets per second")
    parser.add_argument("--duration", type=float, default=10, help="Flood duration in seconds")
    parser.add_argument("--spoof-pool-size", type=int, default=50, help="Number of spoofed source identities (IP:port pairs) to rotate through")
    parser.add_argument("--output", default="data/raw/syn_flood_candidate.pcap", help="Output PCAP file")
    args = parser.parse_args()

    try:
        victim_ip = ipaddress.IPv4Address(args.target)
    except ipaddress.AddressValueError:
        parser.error("--target must be a valid IPv4 address")

    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if args.pps <= 0:
        parser.error("--pps must be greater than zero")
    if args.duration <= 0:
        parser.error("--duration must be greater than zero")
    if args.spoof_pool_size <= 0:
        parser.error("--spoof-pool-size must be greater than zero")

    spoof_pool = build_spoof_pool(victim_ip, args.spoof_pool_size)

    print(f"Generating SYN flood to {args.target}:{args.port} at {args.pps} PPS for {args.duration:g} seconds "
          f"(spoof pool: {args.spoof_pool_size} identities).")
    interval = 1 / args.pps
    packets = []
    current_time = 0.0
    sent = 0

    while current_time < args.duration:
        src_ip, src_port = random.choice(spoof_pool)
        packet = IP(src=src_ip, dst=args.target) / TCP(
            sport=src_port, dport=args.port, flags="S"
        )
        packet.time = current_time
        packets.append(packet)
        sent += 1
        current_time += interval

    wrpcap(args.output, packets)
    print(f"Completed SYN flood generation. Wrote {sent} packets across {len(spoof_pool)} spoofed flows to {args.output}.")


if __name__ == "__main__":
    main()
