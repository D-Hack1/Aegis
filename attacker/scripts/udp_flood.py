import argparse
import ipaddress
import math
import random

from scapy.all import IP, UDP, Raw, wrpcap


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
    parser = argparse.ArgumentParser(description="Generate a UDP flood PCAP with spoofed source addresses.")
    parser.add_argument("--target", default="10.10.0.3", help="Target IPv4 address")
    parser.add_argument("--port", type=int, default=53, help="Target UDP port (53 or 80)")
    parser.add_argument("--pps", type=int, default=150, help="Packets per second")
    parser.add_argument("--duration", type=float, default=10, help="Flood duration in seconds")
    parser.add_argument("--payload-size", type=int, default=1200, help="UDP payload size in bytes")
    parser.add_argument("--spoof-pool-size", type=int, default=1500, help="Number of spoofed source identities (IP:port pairs) to rotate through")
    parser.add_argument("--output", default="data/raw/udp_flood_candidate.pcap", help="Output PCAP file")
    args = parser.parse_args(argv)

    try:
        victim_ip = ipaddress.IPv4Address(args.target)
    except ipaddress.AddressValueError:
        parser.error("--target must be a valid IPv4 address")

    if args.port not in (53, 80):
        parser.error("--port must be 53 or 80")
    if args.pps <= 0:
        parser.error("--pps must be greater than zero")
    if args.duration <= 0:
        parser.error("--duration must be greater than zero")
    if not 1 <= args.payload_size <= 65507:
        parser.error("--payload-size must be between 1 and 65507 bytes")
    if args.spoof_pool_size <= 0:
        parser.error("--spoof-pool-size must be greater than zero")
    return args


def build_packets(target, port, pps, duration, payload, spoof_pool):
    interval = 1 / pps
    packets = []
    for sent in range(math.ceil(pps * duration)):
        src_ip, src_port = spoof_pool[sent % len(spoof_pool)]
        packet = IP(src=src_ip, dst=target) / UDP(
            sport=src_port, dport=port
        ) / Raw(load=payload)
        packet.time = sent * interval
        packets.append(packet)
    return packets


def main():
    args = parse_args()
    victim_ip = ipaddress.IPv4Address(args.target)

    spoof_pool = build_spoof_pool(victim_ip, args.spoof_pool_size)

    print(
        f"Generating UDP flood to {args.target}:{args.port} at {args.pps} PPS "
        f"for {args.duration:g} seconds (spoof pool: {args.spoof_pool_size} identities)."
    )
    payload = b"A" * args.payload_size
    packets = build_packets(
        args.target, args.port, args.pps, args.duration, payload, spoof_pool
    )

    wrpcap(args.output, packets)
    print(f"Completed UDP flood generation. Wrote {len(packets)} packets across {len(spoof_pool)} spoofed flows to {args.output}.")


if __name__ == "__main__":
    main()
