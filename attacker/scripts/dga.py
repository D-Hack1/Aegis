#!/usr/bin/env python3
"""
Aegis — Synthetic DGA / DNS Anomaly PCAP Generator

Purpose:
    Generate synthetic DNS traffic containing a mixture of:
      - Mild DGA domains
      - Extreme DGA domains
      - DNS tunneling-like domains
      - High-entropy benign domains
      - Long benign domains
      - Normal benign domains

The generator is OFFLINE:
    It writes packets to a PCAP instead of sending DNS traffic onto
    a real network.

Default dataset target:
    1500 DNS transactions
    -> approximately 1500 UDP flows
    -> approximately 3000 packets (query + response)

Example:
    python3 /scripts/dga.py \
        --dns-server 10.10.0.5 \
        --queries 1500 \
        --seed 42 \
        --output /pcaps/dga.pcap
"""

from __future__ import annotations

import argparse
import math
import random
import string
from collections import Counter
from pathlib import Path

from scapy.all import (
    DNS,
    DNSQR,
    DNSRR,
    IP,
    UDP,
    wrpcap,
)


# ============================================================================
# Constants
# ============================================================================

DEFAULT_DNS_SERVER = "10.10.0.5"
DEFAULT_CLIENT_IP = "10.10.0.2"
DEFAULT_QUERY_COUNT = 1500
DEFAULT_SEED = 42

DNS_PORT = 53

ALPHANUMERIC = string.ascii_lowercase + string.digits
LETTERS = string.ascii_lowercase

TLD_LIST = [
    "com",
    "net",
    "org",
    "info",
    "biz",
    "xyz",
    "top",
    "site",
]

BENIGN_DOMAINS = [
    "google.com",
    "microsoft.com",
    "github.com",
    "stackoverflow.com",
    "wikipedia.org",
    "amazon.com",
    "apple.com",
    "cloudflare.com",
    "python.org",
    "ubuntu.com",
    "mozilla.org",
    "example.com",
]

BENIGN_SUBDOMAINS = [
    "www",
    "mail",
    "api",
    "cdn",
    "static",
    "assets",
    "images",
    "login",
    "portal",
    "app",
    "download",
    "update",
]


# ============================================================================
# Utility functions
# ============================================================================

def calculate_entropy(value: str) -> float:
    """
    Calculate Shannon entropy for a string.
    """

    if not value:
        return 0.0

    counts = Counter(value)

    length = len(value)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def random_label(
    rng: random.Random,
    minimum: int,
    maximum: int,
) -> str:
    """
    Generate a random lowercase alphanumeric DNS label.
    """

    length = rng.randint(minimum, maximum)

    return "".join(
        rng.choice(ALPHANUMERIC)
        for _ in range(length)
    )


def random_alpha_label(
    rng: random.Random,
    minimum: int,
    maximum: int,
) -> str:
    """
    Generate a random alphabetic DNS label.
    """

    length = rng.randint(minimum, maximum)

    return "".join(
        rng.choice(LETTERS)
        for _ in range(length)
    )


def random_hex_label(
    rng: random.Random,
    minimum: int,
    maximum: int,
) -> str:
    """
    Generate a hexadecimal-looking label.

    Useful for tunneling-like traffic.
    """

    length = rng.randint(minimum, maximum)

    return "".join(
        rng.choice("0123456789abcdef")
        for _ in range(length)
    )


# ============================================================================
# Domain generators
# ============================================================================

def generate_mild_dga_domain(
    rng: random.Random,
) -> str:
    """
    Generate a relatively mild DGA-style domain.

    Characteristics:
        - One random-looking label
        - Moderate length
        - Lower entropy than extreme DGA
        - Common TLD
    """

    label = random_label(
        rng,
        8,
        16,
    )

    tld = rng.choice(
        [
            "com",
            "net",
            "org",
            "info",
            "biz",
        ]
    )

    return f"{label}.{tld}"


def generate_extreme_dga_domain(
    rng: random.Random,
) -> str:
    """
    Generate a high-entropy multi-label DGA-style domain.
    """

    label_count = rng.randint(2, 4)

    labels = []

    for _ in range(label_count):
        labels.append(
            random_label(
                rng,
                12,
                32,
            )
        )

    tld = rng.choice(
        [
            "xyz",
            "top",
            "site",
            "biz",
            "info",
        ]
    )

    return ".".join(labels) + "." + tld


def generate_tunneling_domain(
    rng: random.Random,
) -> str:
    """
    Generate a DNS-tunneling-like domain.

    The first label is intentionally long and encoded-looking.
    """

    prefix_type = rng.choice(
        [
            "hex",
            "alphanumeric",
            "base32ish",
        ]
    )

    if prefix_type == "hex":
        first_label = random_hex_label(
            rng,
            35,
            55,
        )

    elif prefix_type == "alphanumeric":
        first_label = random_label(
            rng,
            35,
            55,
        )

    else:
        first_label = "".join(
            rng.choice(
                string.ascii_lowercase
                + string.digits
            )
            for _ in range(
                rng.randint(35, 55)
            )
        )

    second_label = random_label(
        rng,
        8,
        18,
    )

    tld = rng.choice(
        [
            "com",
            "net",
            "org",
        ]
    )

    return (
        f"{first_label}."
        f"{second_label}."
        f"{tld}"
    )


def generate_benign_entropy_domain(
    rng: random.Random,
) -> str:
    """
    Generate a benign-looking domain that nevertheless has
    relatively high entropy.

    This provides hard negatives for an anomaly detector.
    """

    prefix = random_label(
        rng,
        12,
        22,
    )

    base = rng.choice(
        [
            "cdn.example.com",
            "assets.example.com",
            "static.example.com",
            "content.example.com",
            "cache.example.com",
        ]
    )

    return f"{prefix}.{base}"


def generate_benign_long_domain(
    rng: random.Random,
) -> str:
    """
    Generate a long but syntactically benign domain.
    """

    label_one = rng.choice(
        [
            "api",
            "static",
            "download",
            "images",
            "resources",
            "content",
            "services",
        ]
    )

    label_two = random_alpha_label(
        rng,
        15,
        30,
    )

    base = rng.choice(
        [
            "example.com",
            "example.net",
            "example.org",
        ]
    )

    return (
        f"{label_one}."
        f"{label_two}."
        f"{base}"
    )


def generate_benign_normal_domain(
    rng: random.Random,
) -> str:
    """
    Generate ordinary benign DNS names.
    """

    base = rng.choice(BENIGN_DOMAINS)

    # Sometimes use the base domain directly.
    if rng.random() < 0.40:
        return base

    subdomain = rng.choice(
        BENIGN_SUBDOMAINS
    )

    return f"{subdomain}.{base}"


# ============================================================================
# Profile selection
# ============================================================================

PROFILES = [
    ("mild_dga", 0.35),
    ("extreme_dga", 0.20),
    ("tunneling", 0.10),
    ("benign_entropy", 0.15),
    ("benign_long", 0.10),
    ("benign_normal", 0.10),
]


def choose_profile(
    rng: random.Random,
) -> str:
    """
    Weighted profile selection.
    """

    names = [
        profile[0]
        for profile in PROFILES
    ]

    weights = [
        profile[1]
        for profile in PROFILES
    ]

    return rng.choices(
        names,
        weights=weights,
        k=1,
    )[0]


def generate_domain(
    rng: random.Random,
    profile: str,
) -> str:
    """
    Generate a domain according to the selected profile.
    """

    if profile == "mild_dga":
        return generate_mild_dga_domain(rng)

    if profile == "extreme_dga":
        return generate_extreme_dga_domain(rng)

    if profile == "tunneling":
        return generate_tunneling_domain(rng)

    if profile == "benign_entropy":
        return generate_benign_entropy_domain(rng)

    if profile == "benign_long":
        return generate_benign_long_domain(rng)

    if profile == "benign_normal":
        return generate_benign_normal_domain(rng)

    raise ValueError(
        f"Unknown profile: {profile}"
    )


# ============================================================================
# DNS record selection
# ============================================================================

def choose_query_type(
    rng: random.Random,
    profile: str,
) -> str:
    """
    Select DNS query type.

    Tunneling traffic receives a higher probability of TXT queries.
    """

    if profile == "tunneling":
        return rng.choices(
            [
                "A",
                "AAAA",
                "TXT",
                "CNAME",
            ],
            weights=[
                20,
                15,
                50,
                15,
            ],
            k=1,
        )[0]

    if profile in {
        "mild_dga",
        "extreme_dga",
    }:
        return rng.choices(
            [
                "A",
                "AAAA",
                "TXT",
                "CNAME",
            ],
            weights=[
                55,
                25,
                10,
                10,
            ],
            k=1,
        )[0]

    return rng.choices(
        [
            "A",
            "AAAA",
            "TXT",
            "CNAME",
            "MX",
        ],
        weights=[
            55,
            20,
            5,
            10,
            10,
        ],
        k=1,
    )[0]


# ============================================================================
# DNS response construction
# ============================================================================

def build_dns_response(
    query_name: str,
    query_type: str,
    dns_id: int,
    rng: random.Random,
) -> DNSRR | None:
    """
    Construct a DNS answer.

    IMPORTANT:
        The MX response uses `rdata` instead of the Scapy field
        `preference`, because Scapy versions differ in how MX
        record fields are exposed.
    """

    if query_type == "A":
        return DNSRR(
            rrname=query_name,
            type="A",
            rclass="IN",
            ttl=rng.randint(30, 300),
            rdata=rng.choice(
                [
                    "93.184.216.34",
                    "142.250.72.14",
                    "151.101.1.69",
                    "104.16.132.229",
                    "172.217.16.14",
                ]
            ),
        )

    if query_type == "AAAA":
        return DNSRR(
            rrname=query_name,
            type="AAAA",
            rclass="IN",
            ttl=rng.randint(30, 300),
            rdata=rng.choice(
                [
                    "2606:4700::6810:84e5",
                    "2606:4700::6810:85e5",
                    "2001:4860:4860::8888",
                    "2607:f8b0:4005:805::200e",
                ]
            ),
        )

    if query_type == "CNAME":
        cname = rng.choice(
            [
                "cdn.example.com.",
                "edge.example.net.",
                "proxy.example.org.",
                "www.example.com.",
            ]
        )

        return DNSRR(
            rrname=query_name,
            type="CNAME",
            rclass="IN",
            ttl=rng.randint(30, 300),
            rdata=cname,
        )

    if query_type == "MX":
        # Do NOT use:
        #
        #     preference=10
        #
        # because that raises:
        #
        #     AttributeError: preference
        #
        # with some Scapy versions.
        #
        # Scapy accepts the complete MX RDATA here.
        return DNSRR(
            rrname=query_name,
            type="MX",
            rclass="IN",
            ttl=rng.randint(30, 300),
            rdata="10 mail.example.com.",
        )

    if query_type == "TXT":
        txt_choices = [
            "v=spf1 -all",
            "verification=abcdef",
            "service=api",
            "status=ok",
            "cache-control=max-age=300",
        ]

        return DNSRR(
            rrname=query_name,
            type="TXT",
            rclass="IN",
            ttl=rng.randint(30, 300),
            rdata=rng.choice(txt_choices),
        )

    return None


# ============================================================================
# DNS transaction generation
# ============================================================================

def generate_dns_transaction(
    rng: random.Random,
    client_ip: str,
    dns_server: str,
    transaction_id: int,
    profile: str,
) -> tuple[list, dict]:
    """
    Generate one DNS query + response transaction.

    Each transaction uses a fresh UDP source port.

    Returns:
        packets, metadata
    """

    query_name = generate_domain(
        rng,
        profile,
    )

    query_type = choose_query_type(
        rng,
        profile,
    )

    entropy = calculate_entropy(
        query_name.replace(".", "")
    )

    # Keep source ports in the ephemeral range.
    source_port = rng.randint(
        32768,
        60999,
    )

    dns_id = transaction_id & 0xFFFF

    # ------------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------------

    query = (
        IP(
            src=client_ip,
            dst=dns_server,
        )
        /
        UDP(
            sport=source_port,
            dport=DNS_PORT,
        )
        /
        DNS(
            id=dns_id,
            qr=0,
            rd=1,
            qd=DNSQR(
                qname=query_name + ".",
                qtype=query_type,
            ),
        )
    )

    # ------------------------------------------------------------------------
    # Response
    # ------------------------------------------------------------------------

    answer = build_dns_response(
        query_name=query_name + ".",
        query_type=query_type,
        dns_id=dns_id,
        rng=rng,
    )

    if answer is not None:
        response = (
            IP(
                src=dns_server,
                dst=client_ip,
            )
            /
            UDP(
                sport=DNS_PORT,
                dport=source_port,
            )
            /
            DNS(
                id=dns_id,
                qr=1,
                aa=1,
                rd=1,
                ra=1,
                qd=DNSQR(
                    qname=query_name + ".",
                    qtype=query_type,
                ),
                ancount=1,
                ar=answer,
            )
        )

    else:
        response = (
            IP(
                src=dns_server,
                dst=client_ip,
            )
            /
            UDP(
                sport=DNS_PORT,
                dport=source_port,
            )
            /
            DNS(
                id=dns_id,
                qr=1,
                aa=1,
                rd=1,
                ra=1,
                qd=DNSQR(
                    qname=query_name + ".",
                    qtype=query_type,
                ),
                ancount=0,
            )
        )

    metadata = {
        "profile": profile,
        "domain": query_name,
        "query_type": query_type,
        "entropy": entropy,
        "source_port": source_port,
        "dns_id": dns_id,
    }

    return [query, response], metadata


# ============================================================================
# Argument parsing
# ============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate synthetic DGA/DNS anomaly traffic "
            "as an offline PCAP."
        )
    )

    parser.add_argument(
        "--dns-server",
        default=DEFAULT_DNS_SERVER,
        help=(
            "Destination DNS server IP. "
            f"Default: {DEFAULT_DNS_SERVER}"
        ),
    )

    parser.add_argument(
        "--client-ip",
        default=DEFAULT_CLIENT_IP,
        help=(
            "Synthetic DNS client IP. "
            f"Default: {DEFAULT_CLIENT_IP}"
        ),
    )

    parser.add_argument(
        "--queries",
        type=int,
        default=DEFAULT_QUERY_COUNT,
        help=(
            "Number of DNS transactions to generate. "
            f"Default: {DEFAULT_QUERY_COUNT}"
        ),
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help=(
            "Random seed for reproducible generation. "
            f"Default: {DEFAULT_SEED}"
        ),
    )

    parser.add_argument(
        "--output",
        default="dga.pcap",
        help=(
            "Output PCAP path. "
            "Default: dga.pcap"
        ),
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print every generated transaction.",
    )

    return parser.parse_args()


# ============================================================================
# Main
# ============================================================================

def main() -> None:
    args = parse_args()

    if args.queries <= 0:
        raise ValueError(
            "--queries must be greater than zero"
        )

    rng = random.Random(
        args.seed
    )

    packets = []

    profile_counts = Counter()
    type_counts = Counter()

    print("=" * 72)
    print("Aegis — Synthetic DGA PCAP Generator")
    print("=" * 72)
    print(f"Client IP       : {args.client_ip}")
    print(f"DNS server      : {args.dns_server}")
    print(f"Transactions    : {args.queries}")
    print(f"Random seed     : {args.seed}")
    print(f"Output          : {args.output}")
    print("=" * 72)

    # ------------------------------------------------------------------------
    # Generate transactions
    # ------------------------------------------------------------------------

    for index in range(args.queries):
        profile = choose_profile(
            rng
        )

        transaction_packets, metadata = (
            generate_dns_transaction(
                rng=rng,
                client_ip=args.client_ip,
                dns_server=args.dns_server,
                transaction_id=index + 1,
                profile=profile,
            )
        )

        packets.extend(
            transaction_packets
        )

        profile_counts[
            metadata["profile"]
        ] += 1

        type_counts[
            metadata["query_type"]
        ] += 1

        if (
            args.verbose
            or index == 0
            or (index + 1) % 100 == 0
            or index + 1 == args.queries
        ):
            print(
                f"Generated "
                f"{index + 1}/{args.queries} "
                f"| {metadata['profile']:16s} "
                f"| {metadata['query_type']:5s} "
                f"| entropy="
                f"{metadata['entropy']:.2f} "
                f"| {metadata['domain']}"
            )

    # ------------------------------------------------------------------------
    # Sort by timestamp naturally through packet list order.
    #
    # Scapy will assign packet timestamps when the packets are written if
    # timestamps aren't explicitly supplied. For offline dataset generation,
    # packet ordering is sufficient for Zeek to observe the transactions.
    # ------------------------------------------------------------------------

    output_path = Path(
        args.output
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    wrpcap(
        str(output_path),
        packets,
    )

    # ------------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------------

    print()
    print("=" * 72)
    print("Generation complete")
    print("=" * 72)

    print(
        f"DNS transactions : {args.queries}"
    )

    print(
        f"Packets written  : {len(packets)}"
    )

    print(
        f"Expected packets : {args.queries * 2}"
    )

    print()
    print("Profiles:")

    for profile, count in sorted(
        profile_counts.items()
    ):
        percentage = (
            count / args.queries
        ) * 100

        print(
            f"  {profile:18s} "
            f"{count:5d} "
            f"({percentage:5.1f}%)"
        )

    print()
    print("DNS record types:")

    for record_type, count in sorted(
        type_counts.items()
    ):
        percentage = (
            count / args.queries
        ) * 100

        print(
            f"  {record_type:5s} "
            f"{count:5d} "
            f"({percentage:5.1f}%)"
        )

    print()
    print(
        f"PCAP saved to: {output_path}"
    )

    print("=" * 72)


if __name__ == "__main__":
    main()