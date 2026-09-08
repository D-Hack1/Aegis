import argparse
import random

from scapy.all import IP, UDP, Raw, wrpcap


def main():
    parser = argparse.ArgumentParser(
        description="Generate data exfiltration traffic."
    )

    parser.add_argument(
        "--dst",
        required=True,
        help="Destination IPv4 address",
    )

    parser.add_argument(
        "--port",
        type=int,
        required=True,
        help="Destination UDP port",
    )

    parser.add_argument(
        "--burst-duration",
        type=float,
        default=5.0,
        help="Duration of each burst in seconds",
    )

    parser.add_argument(
        "--idle-gap",
        type=float,
        default=10.0,
        help="Idle gap between bursts in seconds",
    )

    parser.add_argument(
        "--duration",
        type=int,
        default=3600,
        help="Total duration in seconds",
    )

    parser.add_argument(
        "--count",
        type=int,
        default=None,
        help="Exact number of UDP packets to generate",
    )

    parser.add_argument(
        "--output",
        default="data/raw/exfiltration_candidate.pcap",
        help="Output PCAP file",
    )

    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    if args.burst_duration <= 0:
        parser.error("--burst-duration must be greater than zero")

    if args.idle_gap < 0:
        parser.error("--idle-gap must be zero or greater")

    if args.duration <= 0:
        parser.error("--duration must be greater than zero")

    if args.count is not None and args.count <= 0:
        parser.error("--count must be greater than zero")

    packets = []
    total_packets = 0
    burst_number = 0
    current_time = 0.0

    # One unique source port per packet.
    source_ports = list(range(1024, 65536))
    random.shuffle(source_ports)

    print(
        f"Generating exfiltration traffic to "
        f"{args.dst}:{args.port}."
    )

    while True:
        if args.count is not None:
            if total_packets >= args.count:
                break
        elif current_time >= args.duration:
            break

        burst_number += 1
        burst_start = current_time
        burst_end = min(
            current_time + args.burst_duration,
            args.duration,
        )

        packets_in_burst = 0

        print(
            f"Starting burst #{burst_number} "
            f"for {args.burst_duration:g}s..."
        )

        while current_time < burst_end:
            if args.count is not None and total_packets >= args.count:
                break

            payload_size = random.randint(1200, 1450)

            packet = (
                IP(dst=args.dst)
                / UDP(
                    sport=source_ports[total_packets],
                    dport=args.port,
                )
                / Raw(load=b"X" * payload_size)
            )

            packet.time = current_time
            packets.append(packet)

            total_packets += 1
            packets_in_burst += 1

            # 100 packets/sec.
            current_time += 0.01

        print(
            f"Burst #{burst_number} complete. "
            f"Generated {packets_in_burst} packets."
        )

        if args.count is not None and total_packets >= args.count:
            break

        current_time += args.idle_gap

    wrpcap(args.output, packets)

    print(
        f"Completed exfiltration traffic generation. "
        f"Wrote {total_packets} packets across "
        f"{burst_number} bursts to {args.output}."
    )


if __name__ == "__main__":
    main()