import argparse
import ipaddress
import math
import random

from scapy.all import IP, TCP, wrpcap


def random_source_ip(victim_ip):
    while True:
        source_ip = ipaddress.IPv4Address(random.getrandbits(32))
        if source_ip.is_global and source_ip != victim_ip:
            return str(source_ip)


def build_spoof_pool(victim_ip, pool_size):
    pool = []
    identities = set()
    while len(pool) < pool_size:
        src_ip = random_source_ip(victim_ip)
        src_port = random.randint(1024, 65535)
        identity = (src_ip, src_port)
        if identity not in identities:
            identities.add(identity)
            pool.append(identity)
    return pool


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Generate a TCP SYN flood PCAP with spoofed source addresses.")
    parser.add_argument("--target", default="10.10.0.3", help="Target IPv4 address")
    parser.add_argument("--port", type=int, default=80, help="Target TCP port")
    parser.add_argument("--pps", type=int, default=150, help="Packets per second")
    parser.add_argument("--duration", type=float, default=10, help="Flood duration in seconds")
    parser.add_argument("--spoof-pool-size", type=int, default=1500, help="Number of spoofed source identities (IP:port pairs) to rotate through")
    parser.add_argument("--output", default="data/raw/syn_flood_candidate.pcap", help="Output PCAP file")
    args = parser.parse_args(argv)

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
    return args


def build_packets(target, port, pps, duration, spoof_pool):
    packet_count = math.ceil(pps * duration)
    interval = 1 / pps
    packets = []
    for sent in range(packet_count):
        src_ip, src_port = spoof_pool[sent % len(spoof_pool)]
        packet = IP(src=src_ip, dst=target) / TCP(
            sport=src_port, dport=port, flags="S"
        )
        packet.time = sent * interval
        packets.append(packet)
    return packets


def main():
    args = parse_args()
    victim_ip = ipaddress.IPv4Address(args.target)

    spoof_pool = build_spoof_pool(victim_ip, args.spoof_pool_size)

    print(f"Generating SYN flood to {args.target}:{args.port} at {args.pps} PPS for {args.duration:g} seconds "
          f"(spoof pool: {args.spoof_pool_size} identities).")
    packets = build_packets(args.target, args.port, args.pps, args.duration, spoof_pool)

    wrpcap(args.output, packets)
    print(f"Completed SYN flood generation. Wrote {len(packets)} packets across {len(spoof_pool)} spoofed flows to {args.output}.")


if __name__ == "__main__":
    main()
