import argparse
import random

from scapy.all import IP, UDP, Raw, wrpcap


def main():
    parser = argparse.ArgumentParser(
        description="Data Exfiltration Traffic Generator"
    )

    parser.add_argument(
        "--dst",
        required=True,
        help="Destination IP address",
    )

    parser.add_argument(
        "--port",
        type=int,
        required=True,
        help="Starting destination UDP port",
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
        help="Total duration to generate in seconds",
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

    packets = []
    burst_number = 0
    total_packets = 0
    current_time = 0.0

    print(
        f"Generating exfiltration traffic to {args.dst} "
        f"for {args.duration}s."
    )

    while current_time < args.duration:
        burst_number += 1

        # Give every burst its own destination port.
        burst_port = args.port + burst_number - 1

        if burst_port > 65535:
            burst_port = args.port + (
                (burst_number - 1) % (65535 - args.port + 1)
            )

        burst_end = min(
            current_time + args.burst_duration,
            args.duration,
        )

        packets_sent = 0

        print(
            f"Starting burst #{burst_number} "
            f"to {args.dst}:{burst_port} "
            f"for {args.burst_duration:g}s..."
        )

        while current_time < burst_end:
            payload_size = random.randint(1200, 1450)
            payload = b"X" * payload_size

            packet = (
                IP(dst=args.dst)
                / UDP(dport=burst_port)
                / Raw(load=payload)
            )

            packet.time = current_time
            packets.append(packet)

            packets_sent += 1
            total_packets += 1

            # Preserve the original 10 ms packet spacing.
            current_time += 0.01

        print(
            f"Burst #{burst_number} complete. "
            f"Generated {packets_sent} packets. "
            f"Idling for {args.idle_gap:g}s..."
        )

        current_time += args.idle_gap

    wrpcap(args.output, packets)

    print(
        f"Completed exfiltration traffic generation. "
        f"Wrote {total_packets} packets across "
        f"{burst_number} bursts to {args.output}."
    )


if __name__ == "__main__":
    main()