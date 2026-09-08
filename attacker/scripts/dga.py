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

    return domain + rng.choice(tlds)


def main():
    parser = argparse.ArgumentParser(
        description="Generate DGA DNS traffic."
    )

    parser.add_argument(
        "--dns-server",
        required=True,
        help="DNS server IPv4 address",
    )

    parser.add_argument(
        "--duration",
        type=int,
        default=3600,
        help="Total duration in seconds",
    )

    parser.add_argument(
        "--queries-per-min",
        type=int,
        default=30,
        help="DNS queries per minute (20-50)",
    )

    parser.add_argument(
        "--count",
        type=int,
        default=None,
        help="Exact number of DNS queries to generate",
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

    if args.count is not None and args.count <= 0:
        parser.error("--count must be greater than zero")

    rng = random.Random(args.seed)

    query_interval = 60.0 / args.queries_per_min

    packets = []
    sent = 0
    current_time = 0.0

    # Use unique source ports so each DNS query has a
    # different 5-tuple and can become a separate Zeek flow.
    source_ports = list(range(1024, 1024 + 64512))
    rng.shuffle(source_ports)

    print(
        f"Generating DGA traffic to {args.dns_server}:53 "
        f"at approximately {args.queries_per_min} queries/min."
    )

    while True:
        if args.count is not None:
            if sent >= args.count:
                break
        elif current_time >= args.duration:
            break

        domain = generate_dga_domain(rng)

        src_port = source_ports[sent]

        packet = (
            IP(dst=args.dns_server)
            / UDP(
                sport=src_port,
                dport=53,
            )
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
            f"{args.dns_server}:53 "
            f"(source port {src_port})"
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