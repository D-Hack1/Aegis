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
        "--count",
        type=int,
        default=None,
        help="Number of beacons to generate (overrides duration if specified)",
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

    if args.count is not None and args.count <= 0:
        parser.error("--count must be greater than zero")

    # We need enough source ports for unique flows.
    # Ports 1024-65535 give us 64512 possible source ports.
    if args.count is not None and args.count > 64512:
        parser.error("--count cannot exceed 64512")

    # Create unique source ports and shuffle them so the sequence
    # isn't simply 1024, 1025, 1026, ...
    if args.count is not None:
        source_ports = list(range(1024, 1024 + args.count))
        random.shuffle(source_ports)
    else:
        source_ports = None

    packets = []
    sent = 0
    current_time = 0.0

    if args.count is not None:
        print(
            f"Generating {args.count} C2 beacons to "
            f"{args.dst}:{args.port} with "
            f"~{args.interval:g}s ±{args.jitter:g}s jitter."
        )
    else:
        print(
            f"Generating C2 beaconing to {args.dst}:{args.port} "
            f"every ~{args.interval:g}s ±{args.jitter:g}s "
            f"for {args.duration:g}s."
        )

    while True:
        # Duration mode
        if args.count is None and current_time >= args.duration:
            break

        # Count mode
        if args.count is not None and sent >= args.count:
            break

        # Every beacon gets a unique source port.
        if source_ports is not None:
            src_port = source_ports[sent]
        else:
            # Duration mode also avoids source-port reuse.
            # The maximum practical number of beacons is 64512.
            if sent >= 64512:
                print(
                    "Reached the maximum number of unique source ports."
                )
                break

            src_port = 1024 + sent

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

        # Timestamp relative to the beginning of the PCAP.
        packet.time = current_time

        packets.append(packet)
        sent += 1

        print(
            f"Beacon #{sent}: "
            f"{args.dst}:{args.port} "
            f"(src port {src_port}, "
            f"payload {payload_size} bytes, "
            f"timestamp {current_time:.2f}s)"
        )

        # Don't add an unnecessary delay after the final beacon.
        if args.count is not None and sent >= args.count:
            break

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