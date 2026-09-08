import argparse
import random
import time

from scapy.all import IP, TCP, Raw, send


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

    sent = 0

    print(
        f"Starting C2 beaconing to {args.dst}:{args.port} "
        f"every ~{args.interval:g}s ±{args.jitter:g}s "
        f"for {args.duration:g}s."
    )

    while time.monotonic() < end_time:
        # Use a different source port for every beacon.
        # This makes each beacon a distinct TCP 5-tuple/flow.
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

        send(packet, verbose=False)

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

        # Don't sleep beyond the requested duration.
        remaining = end_time - time.monotonic()

        if remaining <= 0:
            break

        sleep_time = min(sleep_time, remaining)

        if sleep_time > 0:
            time.sleep(sleep_time)

    print(f"Completed C2 beaconing. Sent {sent} beacons.")


if __name__ == "__main__":
    main()