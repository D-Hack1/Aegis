import argparse
import random
import time

from scapy.all import IP, UDP, Raw, send


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
        help="Total duration to run in seconds",
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

    start_time = time.monotonic()
    end_time = start_time + args.duration

    burst_number = 0
    total_packets = 0

    print(
        f"Starting exfiltration traffic to {args.dst} "
        f"for {args.duration}s."
    )

    while time.monotonic() < end_time:
        burst_number += 1

        # Give every burst its own destination port.
        # This creates a different UDP 5-tuple for each burst.
        burst_port = args.port + burst_number - 1

        if burst_port > 65535:
            burst_port = args.port + ((burst_number - 1) % (65535 - args.port + 1))

        burst_start = time.monotonic()
        packets_sent = 0

        print(
            f"Starting burst #{burst_number} "
            f"to {args.dst}:{burst_port} "
            f"for {args.burst_duration:g}s..."
        )

        while time.monotonic() - burst_start < args.burst_duration:
            if time.monotonic() >= end_time:
                break

            payload_size = random.randint(1200, 1450)
            payload = b"X" * payload_size

            packet = (
                IP(dst=args.dst)
                / UDP(dport=burst_port)
                / Raw(load=payload)
            )

            send(packet, verbose=False)

            packets_sent += 1
            total_packets += 1

            # Prevent excessive packet generation/interface buffering.
            time.sleep(0.01)

        print(
            f"Burst #{burst_number} complete. "
            f"Sent {packets_sent} packets. "
            f"Idling for {args.idle_gap:g}s..."
        )

        remaining = end_time - time.monotonic()

        if remaining <= 0:
            break

        sleep_time = min(args.idle_gap, remaining)

        if sleep_time > 0:
            time.sleep(sleep_time)

    print(
        f"Completed exfiltration traffic. "
        f"Sent {total_packets} packets across "
        f"{burst_number} bursts."
    )


if __name__ == "__main__":
    main()