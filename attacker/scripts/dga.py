import argparse
import random
import string

from scapy.all import DNS, DNSQR, IP, UDP, wrpcap


def generate_dga_domain(rng, length=12):
    tlds = [".com", ".net", ".org", ".info", ".biz"]

    domain = "".join(
        rng.choices(
            string.ascii_lowercase + string.digits,
            k=length,
        )
    )

    tld = rng.choice(tlds)

    return domain + tld


def main():
    parser = argparse.ArgumentParser(
        description="DGA Traffic Generator"
    )

    parser.add_argument(
        "--dns-server",
        required=True,
        help="DNS server IP address",
    )

    parser.add_argument(
        "--duration",
        type=int,
        default=3600,
        help="Total duration to run in seconds",
    )

    parser.add_argument(
        "--queries-per-min",
        type=int,
        default=30,
        help="Number of DNS queries per minute (20-50)",
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Seed for reproducible DGA generation",
    )

    parser.add_argument(
        "--output",
        default="data/raw/dga_candidate.pcap",
        help="Output PCAP file",
    )

    args = parser.parse_args()

    if args.duration <= 0:
        parser.error("--duration must be greater than zero")

    if not 20 <= args.queries_per_min <= 50:
        parser.error("--queries-per-min must be between 20 and 50")

    rng = random.Random(args.seed)

    query_interval = 60.0 / args.queries_per_min

    packets = []
    sent = 0
    current_time = 0.0

    print(
        f"Generating DGA traffic to DNS server {args.dns_server}:53 "
        f"at approximately {args.queries_per_min} queries/min "
        f"for {args.duration} seconds."
    )

    while current_time < args.duration:
        domain = generate_dga_domain(rng)

        packet = (
            IP(dst=args.dns_server)
            / UDP(dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(
                    qname=domain,
                    qtype="A",
                ),
            )
        )

        packet.time = current_time
        packets.append(packet)

        sent += 1

        print(
            f"Query #{sent}: {domain} A -> "
            f"{args.dns_server}:53"
        )

        jitter = rng.uniform(
            -0.1 * query_interval,
            0.1 * query_interval,
        )

        current_time += query_interval + jitter

    wrpcap(args.output, packets)

    print(
        f"Completed DGA traffic generation. "
        f"Wrote {sent} DNS queries to {args.output}."
    )


if __name__ == "__main__":
    main()