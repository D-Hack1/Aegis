import argparse
import random
import time

from scapy.all import IP, TCP, Raw, wrpcap


def main():
    parser = argparse.ArgumentParser(
        description="Generate C2 beaconing traffic with jitter."
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
        help="Destination TCP port",
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=60,
        help="Base interval between beacons in seconds (default: 60)",
    )

    parser.add_argument(
        "--duration",
        type=float,
        default=3600,
        help="Total duration in seconds (default: 3600)",
    )

    parser.add_argument(
        "--jitter",
        type=float,
        default=5,
        help="Maximum positive/negative jitter in seconds (default: 5)",
    )

    parser.add_argument(
        "--output",
        default="data/raw/c2_beacon_candidate.pcap",
        help="Output PCAP file",
    )

    args = parser.parse_args()

    # Validate arguments
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    if args.interval <= 0:
        parser.error("--interval must be greater than zero")

    if args.duration <= 0:
        parser.error("--duration must be greater than zero")

    if args.jitter < 0 or args.jitter > args.interval:
        parser.error("--jitter must be >= 0 and <= --interval")

    start_time = time.monotonic()
    end_time = start_time + args.duration

    packets = []
    sent = 0
    current_time = 0.0

    print(
        f"Generating C2 beaconing to {args.dst}:{args.port} "
        f"every ~{args.interval:g}s ±{args.jitter:g}s "
        f"for {args.duration:g}s."
    )

    while current_time < args.duration:
        # Use a different source port for every beacon.
        src_port = random.randint(1024, 65535)

        # Slightly vary the payload size.
        payload_size = random.randint(10, 50)
        payload = b"A" * payload_size

        packet = (
            IP(dst=args.dst)
            / TCP(
                sport=src_port,
                dport=args.port,
                flags="S",
            )
            / Raw(load=payload)
        )

        # Timestamp packet relative to the beginning of the capture.
        packet.time = current_time
        packets.append(packet)

        sent += 1

        print(
            f"Beacon #{sent}: "
            f"{args.dst}:{args.port} "
            f"(src port {src_port}, payload {payload_size} bytes)"
        )

        # Randomized beacon interval.
        sleep_time = args.interval + random.uniform(
            -args.jitter,
            args.jitter,
        )

        current_time += sleep_time

    wrpcap(args.output, packets)

    print(
        f"Completed C2 beaconing generation. "
        f"Wrote {sent} beacons to {args.output}."
    )


if __name__ == "__main__":
    main()