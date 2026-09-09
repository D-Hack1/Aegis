"""
benign_traffic.py — Generate a realistic benign traffic PCAP for Aegis lab.

Works the same way as the new syn_flood.py:
  - Builds packets in memory using Scapy
  - Writes them directly to a PCAP file with wrpcap()
  - No Docker, no live network needed
  - Zeek replays the PCAP to produce conn.log / dns.log / ssl.log
  - features/pipeline.py then reads those logs → benign.parquet

Traffic mix (to produce ~1500+ flows):
  - HTTP TCP connections  (SYN→data→FIN, short flows)
  - DNS queries           (UDP port 53, realistic domain names)
  - HTTPS TCP connections (SYN→data→FIN to port 443)
  - SSH TCP connections   (SYN→data→FIN to port 22)
  - Large TCP transfers   (iperf3-style, high byte volume both directions)

Why this mix matters for the model:
  - HTTP/HTTPS gives normal TLS and non-TLS flows
  - DNS gives normal low-entropy queries (contrast with DGA high-entropy)
  - Large transfers give balanced orig_bytes/resp_bytes (contrast with exfiltration)
  - Varied destinations give moderate fan_out (contrast with port_scan)
  - Irregular timing gives high iat_std (contrast with c2_beaconing)

Usage:
    python3 benign_traffic.py --output data/raw/benign.pcap --flows 1500
    python3 benign_traffic.py --output data/raw/benign.pcap --flows 2000 --seed 42
"""

from __future__ import annotations

import argparse
import ipaddress
import math
import random
import string
from pathlib import Path

from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap

# ---------------------------------------------------------------------------
# Lab network constants — must match docker-compose.yml
# ---------------------------------------------------------------------------
BENIGN_IP  = "10.10.0.4"   # source (benign container)
VICTIM_IP  = "10.10.0.3"   # destination (victim container)
DNS_SERVER = "10.10.0.3"   # victim also acts as DNS in lab

# Real-looking domain names — low entropy, structured labels
# Contrast with DGA domains which are random character strings
BENIGN_DOMAINS = [
    "github.com", "google.com", "stackoverflow.com", "wikipedia.org",
    "npmjs.com", "pypi.org", "microsoft.com", "amazon.com",
    "cloudflare.com", "ubuntu.com", "debian.org", "docs.python.org",
    "api.github.com", "mail.google.com", "cdn.jsdelivr.net",
    "fonts.googleapis.com", "accounts.google.com", "s3.amazonaws.com",
    "login.microsoftonline.com", "registry.npmjs.org",
]

# Destination ports for different traffic types
HTTP_PORT  = 80
HTTPS_PORT = 443
SSH_PORT   = 22
DNS_PORT   = 53


# ---------------------------------------------------------------------------
# Packet builders — each returns a list of Scapy packets for one flow
# ---------------------------------------------------------------------------

def _tcp_flow(src_ip, dst_ip, src_port, dst_port, payload_size, timestamp):
    """
    Build a minimal TCP flow: SYN → SYN-ACK → ACK → data → FIN.
    Each call = one complete connection = one Zeek conn.log row.
    """
    payload = b"X" * payload_size
    pkts = [
        IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S"),
        IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="SA"),
        IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="A"),
        IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="PA") / Raw(load=payload),
        # Response from server — gives resp_bytes > 0 (contrast with SYN flood)
        IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="PA") / Raw(load=b"Y" * (payload_size // 2)),
        IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="FA"),
        IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="FA"),
    ]
    for i, pkt in enumerate(pkts):
        pkt.time = timestamp + i * 0.001
    return pkts


def _dns_query(src_ip, dns_server, src_port, domain, timestamp):
    """
    Build a DNS query + response pair.
    One query = one Zeek dns.log row with low-entropy domain name.
    """
    pkts = [
        IP(src=src_ip, dst=dns_server) / UDP(sport=src_port, dport=DNS_PORT) /
        DNS(rd=1, qd=DNSQR(qname=domain)),
        # Fake A-record response
        IP(src=dns_server, dst=src_ip) / UDP(sport=DNS_PORT, dport=src_port) /
        DNS(qr=1, rd=1, ra=1, qd=DNSQR(qname=domain)),
    ]
    pkts[0].time = timestamp
    pkts[1].time = timestamp + 0.002
    return pkts


def _large_transfer(src_ip, dst_ip, src_port, dst_port, orig_bytes, resp_bytes, timestamp):
    """
    Simulate an iperf3-style bulk transfer.
    High bytes in BOTH directions — balanced outbound_inbound_ratio ≈ 1.
    Contrast with exfiltration which has resp_bytes ≈ 0.
    """
    chunk = 1400  # MTU-ish
    pkts = []
    t = timestamp

    # Handshake
    pkts.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S"))
    pkts[-1].time = t; t += 0.001
    pkts.append(IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="SA"))
    pkts[-1].time = t; t += 0.001

    # Outbound data
    for _ in range(math.ceil(orig_bytes / chunk)):
        pkts.append(
            IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="PA") /
            Raw(load=b"O" * min(chunk, orig_bytes))
        )
        pkts[-1].time = t; t += 0.0005

    # Inbound response — meaningful volume
    for _ in range(math.ceil(resp_bytes / chunk)):
        pkts.append(
            IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="PA") /
            Raw(load=b"I" * min(chunk, resp_bytes))
        )
        pkts[-1].time = t; t += 0.0005

    # Teardown
    pkts.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="FA"))
    pkts[-1].time = t
    return pkts


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def generate_benign_pcap(
    n_flows:   int  = 1500,
    seed:      int  = 42,
    output:    str  = "data/raw/benign.pcap",
    src_ip:    str  = BENIGN_IP,
    dst_ip:    str  = VICTIM_IP,
):
    """
    Generate a PCAP with n_flows benign flows.

    Flow type distribution (approximate):
        40%  HTTP  flows  (TCP port 80,  small payload)
        25%  HTTPS flows  (TCP port 443, small payload)
        20%  DNS   flows  (UDP port 53,  real-looking domains)
        10%  Large TCP transfers (iperf3-style, balanced bytes)
         5%  SSH   flows  (TCP port 22)

    Timing: flows are spread across a 600-second window with random
    inter-arrival times, matching realistic background traffic patterns.
    IAT is irregular (iat_std is high) — contrast with c2_beaconing.
    """
    rng = random.Random(seed)
    all_packets = []

    # Spread flows across 600 seconds with jittered IAT
    # Mean IAT ≈ 0.4s, std ≈ 0.3s — irregular, realistic
    current_time = 0.0
    src_port_counter = 1024

    def next_port():
        nonlocal src_port_counter
        p = src_port_counter
        src_port_counter = (src_port_counter % 64511) + 1024
        return p

    # Assign flow types
    flow_types = rng.choices(
        ["http", "https", "dns", "transfer", "ssh"],
        weights=[40, 25, 20, 10, 5],
        k=n_flows,
    )

    for flow_type in flow_types:
        # Irregular inter-arrival time — high iat_std is the benign signal
        iat = max(0.05, rng.gauss(0.4, 0.3))
        current_time += iat

        sport = next_port()

        if flow_type == "http":
            payload = rng.randint(200, 8000)
            pkts = _tcp_flow(src_ip, dst_ip, sport, HTTP_PORT, payload, current_time)

        elif flow_type == "https":
            payload = rng.randint(500, 15000)
            pkts = _tcp_flow(src_ip, dst_ip, sport, HTTPS_PORT, payload, current_time)

        elif flow_type == "dns":
            domain = rng.choice(BENIGN_DOMAINS)
            # Occasionally add www. prefix — realistic subdomain pattern
            if rng.random() < 0.3:
                prefix = rng.choice(["www", "api", "cdn", "static"])
                domain = f"{prefix}.{domain}"
            pkts = _dns_query(src_ip, dst_ip, sport, domain, current_time)

        elif flow_type == "transfer":
            orig_b = rng.randint(50000, 500000)
            resp_b = rng.randint(40000, 400000)   # balanced both directions
            pkts = _large_transfer(src_ip, dst_ip, sport, HTTP_PORT, orig_b, resp_b, current_time)
            current_time += 2.0   # transfers take longer

        else:  # ssh
            payload = rng.randint(100, 2000)
            pkts = _tcp_flow(src_ip, dst_ip, sport, SSH_PORT, payload, current_time)

        all_packets.extend(pkts)

    # Sort by timestamp before writing — Zeek requires chronological order
    all_packets.sort(key=lambda p: float(p.time))

    Path(output).parent.mkdir(parents=True, exist_ok=True)
    wrpcap(output, all_packets)
    print(f"Wrote {len(all_packets)} packets ({n_flows} flows) to {output}")
    return output


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate a realistic benign traffic PCAP for Aegis lab."
    )
    parser.add_argument(
        "--output",
        default="data/raw/benign.pcap",
        help="Output PCAP path (default: data/raw/benign.pcap)",
    )
    parser.add_argument(
        "--flows",
        type=int,
        default=1500,
        help="Number of flows to generate (default: 1500)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42)",
    )
    parser.add_argument(
        "--src-ip",
        default=BENIGN_IP,
        help=f"Source IP (default: {BENIGN_IP})",
    )
    parser.add_argument(
        "--dst-ip",
        default=VICTIM_IP,
        help=f"Destination IP (default: {VICTIM_IP})",
    )
    args = parser.parse_args()

    if args.flows <= 0:
        parser.error("--flows must be greater than zero")

    generate_benign_pcap(
        n_flows=args.flows,
        seed=args.seed,
        output=args.output,
        src_ip=args.src_ip,
        dst_ip=args.dst_ip,
    )


if __name__ == "__main__":
    main()
