"""
Aegis — Diverse benign traffic PCAP generator (Zeek Extraction Optimized).

Purpose:
Generate difficult, heterogeneous BENIGN traffic with strict TCP sequence
accounting and valid application-layer headers (HTTP/SSH) so Zeek correctly
extracts states (SF) and byte counts, without relying on ML "shortcuts."
"""

from __future__ import annotations

import argparse
import math
import random
import time
from pathlib import Path

from scapy.all import IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, send, wrpcap

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BENIGN_IP = "10.10.0.4"
VICTIM_IP = "10.10.0.3"
DNS_SERVER = "10.10.0.3"

HTTP_PORT = 80
HTTPS_PORT = 443
SSH_PORT = 22
DNS_PORT = 53
NTP_PORT = 123

BENIGN_DOMAINS = [
    "github.com", "google.com", "stackoverflow.com", "wikipedia.org",
    "npmjs.com", "pypi.org", "microsoft.com", "amazon.com",
    "cloudflare.com", "ubuntu.com", "debian.org", "docs.python.org",
    "api.openai.com",
]
BENIGN_LABELS = [
    "api", "www", "cdn", "static", "assets", "download", "update",
    "packages", "registry", "login", "auth", "mail", "docs", "support",
]

# Genuine protocol headers for the application layer
HTTP_REQ_TEMPLATE = b"GET /%b HTTP/1.1\r\nHost: %b\r\nAccept: */*\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n"
HTTP_RES_HEADER = b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nConnection: keep-alive\r\n\r\n"
SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _random_payload_size(rng: random.Random, minimum: int, maximum: int) -> int:
    if rng.random() < 0.78:
        value = int(math.exp(rng.uniform(math.log(max(1, minimum)), math.log(max(2, maximum)))))
    else:
        value = rng.randint(minimum, maximum)
    return max(minimum, min(maximum, value))

def _next_port_factory(rng):
    current = rng.randint(1024, 60000)

    def next_port():
        nonlocal current
        port = current
        current += rng.randint(1, 37)
        if current > 64511:
            current = rng.randint(1024, 50000)
        return port

    return next_port


# ---------------------------------------------------------------------------
# Strict TCP State Machine Builder
# ---------------------------------------------------------------------------

def _tcp_request_response(
    src_ip, dst_ip, src_port, dst_port,
    request_bytes, response_bytes, timestamp, rng,
    duration_profile="short", protocol=None
):
    """
    Builds a TCP connection strictly adhering to sequence/ack numbers so
    Zeek reports state 'SF' and exact orig_bytes / resp_bytes.
    """
    packets = []
    t = timestamp

    # Initialize random Initial Sequence Numbers (ISNs)
    seq_a = rng.randint(1000, 4000000000)
    seq_b = rng.randint(1000, 4000000000)

    # 1. SYN
    packets.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S", seq=seq_a))
    packets[-1].time = t
    seq_a += 1
    t += rng.uniform(0.0005, 0.004)

    # 2. SYN-ACK
    packets.append(IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="SA", seq=seq_b, ack=seq_a))
    packets[-1].time = t
    seq_b += 1
    t += rng.uniform(0.0005, 0.004)

    # 3. ACK
    packets.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="A", seq=seq_a, ack=seq_b))
    packets[-1].time = t

    def emit_direction(src, dst, sport, dport, total_bytes, is_req):
        nonlocal t, seq_a, seq_b
        remaining = max(0, int(total_bytes))
        if remaining == 0:
            return

        first_packet = True

        while remaining > 0:
            chunk_size = min(remaining, rng.choice([rng.randint(200, 900), rng.randint(900, 1400), rng.randint(1200, 1460)]))
            
            # Application-layer formatting.
            # HTTP/SSH use recognizable application headers.
            # HTTPS is intentionally opaque TCP/443 traffic; no fake TLS handshake.
            payload = b""

            if first_packet:
                if protocol == "http":
                    if is_req:
                        path = rng.choice([
                            b"index.html", b"api/data", b"docs/",
                            b"search?q=network", b"download/package.tar.gz",
                            b"login", b"status"
                        ])
                        host = rng.choice(BENIGN_DOMAINS).encode()
                        header = HTTP_REQ_TEMPLATE % (path, host)
                    else:
                        header = HTTP_RES_HEADER

                    if len(header) > chunk_size:
                        chunk_size = min(1460, len(header))
                    payload = header + b"A" * (chunk_size - len(header))

                elif protocol == "ssh":
                    if len(SSH_BANNER) > chunk_size:
                        chunk_size = min(1460, len(SSH_BANNER))
                    payload = SSH_BANNER + rng.randbytes(chunk_size - len(SSH_BANNER))

                else:
                    payload = rng.randbytes(chunk_size)

                first_packet = False

            else:
                if protocol == "http":
                    payload = (
                        b"A" * chunk_size
                        if rng.random() < 0.75
                        else rng.randbytes(chunk_size)
                    )
                else:
                    payload = rng.randbytes(chunk_size)

            # Ensure payload doesn't exceed requested chunk
            payload = payload[:chunk_size]

            # Set correct Seq/Ack based on direction
            if is_req:  # src -> dst
                pkt_seq, pkt_ack = seq_a, seq_b
                seq_a += len(payload)
            else:       # dst -> src
                pkt_seq, pkt_ack = seq_b, seq_a
                seq_b += len(payload)

            packets.append(
                IP(src=src, dst=dst) /
                TCP(sport=sport, dport=dport, flags="PA", seq=pkt_seq, ack=pkt_ack) /
                Raw(load=payload)
            )
            packets[-1].time = t
            remaining -= len(payload)

            # Timing jitter
            if duration_profile == "interactive": t += rng.uniform(0.0003, 0.025)
            elif duration_profile == "background": t += rng.uniform(0.005, 0.15)
            elif duration_profile == "bulk": t += rng.uniform(0.0001, 0.003)
            else: t += rng.uniform(0.0005, 0.04)

            if rng.random() < 0.025: t += rng.uniform(0.05, 1.5)

    # 4. Data Transfer
    emit_direction(src_ip, dst_ip, src_port, dst_port, request_bytes, is_req=True)
    if response_bytes > 0:
        t += rng.uniform(0.002, 0.12)
        emit_direction(dst_ip, src_ip, dst_port, src_port, response_bytes, is_req=False)

    # 5. Teardown (FIN/ACK sequence)
    t += rng.uniform(0.0005, 0.01)
    packets.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="FA", seq=seq_a, ack=seq_b))
    packets[-1].time = t
    seq_a += 1

    t += rng.uniform(0.0005, 0.002)
    packets.append(IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="FA", seq=seq_b, ack=seq_a))
    packets[-1].time = t
    seq_b += 1

    t += rng.uniform(0.0005, 0.002)
    packets.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="A", seq=seq_a, ack=seq_b))
    packets[-1].time = t

    return packets


# ---------------------------------------------------------------------------
# Specific Flow Builders
# ---------------------------------------------------------------------------

def _ssh_flow(src_ip, dst_ip, src_port, timestamp, rng):
    return _tcp_request_response(src_ip, dst_ip, src_port, SSH_PORT,
                                 _random_payload_size(rng, 100, 5000), _random_payload_size(rng, 200, 8000),
                                 timestamp, rng, "interactive", "ssh")

def _web_flow(src_ip, dst_ip, src_port, dst_port, timestamp, rng, protocol):
    request = _random_payload_size(rng, 80, 5000)
    if rng.random() < 0.12:
        response, profile = _random_payload_size(rng, 200_000, 2_000_000), "bulk"
    elif rng.random() < 0.30:
        response, profile = _random_payload_size(rng, 20_000, 300_000), "background"
    else:
        response, profile = _random_payload_size(rng, 500, 40_000), "interactive"

    return _tcp_request_response(src_ip, dst_ip, src_port, dst_port, request, response, timestamp, rng, profile, protocol)

def _bulk_transfer(src_ip, dst_ip, src_port, dst_port, timestamp, rng, protocol):
    mode = rng.choice(["download", "upload", "balanced", "backup"])
    if mode == "download":   orig, resp = _random_payload_size(rng, 500, 80_000), _random_payload_size(rng, 100_000, 3_000_000)
    elif mode == "upload":   orig, resp = _random_payload_size(rng, 100_000, 3_000_000), _random_payload_size(rng, 500, 100_000)
    else:                    orig, resp = _random_payload_size(rng, 50_000, 1_500_000), _random_payload_size(rng, 30_000, 1_500_000)
    
    return _tcp_request_response(src_ip, dst_ip, src_port, dst_port, orig, resp, timestamp, rng, "bulk", protocol)


# ---------------------------------------------------------------------------
# DNS & UDP builders
# ---------------------------------------------------------------------------

def _dns_query(src_ip, dns_server, src_port, timestamp, rng):
    base = rng.choice(BENIGN_DOMAINS)
    domain = base if rng.random() < 0.3 else f"{rng.choice(BENIGN_LABELS)}.{base}"

    packets = []
    qtype_str = rng.choices(
        ["A", "AAAA", "CNAME"],
        weights=[70, 20, 10],
        k=1
    )[0]

    query = (
        IP(src=src_ip, dst=dns_server)
        / UDP(sport=src_port, dport=DNS_PORT)
        / DNS(rd=1, qd=DNSQR(qname=domain, qtype=qtype_str))
    )
    query.time = timestamp
    packets.append(query)

    if qtype_str == "A":
        rdata = VICTIM_IP
    elif qtype_str == "AAAA":
        rdata = "2001:db8::3"
    else:
        rdata = f"www.{base}."

    answer = DNSRR(
        rrname=domain,
        type=qtype_str,
        ttl=rng.choice([60, 300, 3600]),
        rdata=rdata
    )

    response = (
        IP(src=dns_server, dst=src_ip)
        / UDP(sport=DNS_PORT, dport=src_port)
        / DNS(
            qr=1, rd=1, ra=1, aa=0, rcode=0,
            qd=DNSQR(qname=domain, qtype=qtype_str),
            an=answer
        )
    )
    response.time = timestamp + rng.uniform(0.005, 0.08)
    packets.append(response)

    return packets


def _ntp_like(src_ip, dst_ip, src_port, timestamp, rng):
    packets = []
    for direction in range(2):
        src, dst, sport, dport = (src_ip, dst_ip, src_port, NTP_PORT) if direction == 0 else (dst_ip, src_ip, NTP_PORT, src_port)
        pkt = IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(load=rng.randbytes(rng.randint(48, 120)))
        pkt.time = timestamp + direction * rng.uniform(0.002, 0.02)
        packets.append(pkt)
    return packets


# ---------------------------------------------------------------------------
# Behavioral profiles
# ---------------------------------------------------------------------------

PROFILES = {
    "web_user": {"weights": {"web_http": 25, "web_https": 40, "dns": 20, "bulk": 8, "ssh": 2, "ntp": 5}, "iat_mean": 0.35, "iat_jitter": 0.45},
    "developer": {"weights": {"web_http": 12, "web_https": 28, "dns": 22, "bulk": 15, "ssh": 15, "ntp": 8}, "iat_mean": 0.65, "iat_jitter": 0.70},
    "backup": {"weights": {"web_http": 8, "web_https": 15, "dns": 12, "bulk": 50, "ssh": 5, "ntp": 10}, "iat_mean": 0.9, "iat_jitter": 0.9},
    "dns_heavy": {"weights": {"web_http": 15, "web_https": 25, "dns": 45, "bulk": 5, "ssh": 2, "ntp": 8}, "iat_mean": 0.25, "iat_jitter": 0.35},
    "enterprise_mix": {"weights": {"web_http": 18, "web_https": 32, "dns": 22, "bulk": 18, "ssh": 5, "ntp": 5}, "iat_mean": 0.55, "iat_jitter": 0.65},
    "idle_bursty": {"weights": {"web_http": 22, "web_https": 28, "dns": 30, "bulk": 8, "ssh": 4, "ntp": 8}, "iat_mean": 1.20, "iat_jitter": 1.30},
    "high_throughput": {"weights": {"web_http": 10, "web_https": 25, "dns": 10, "bulk": 50, "ssh": 2, "ntp": 3}, "iat_mean": 0.08, "iat_jitter": 0.10},
}


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def generate_benign_pcap(n_flows=1500, seed=42, output="data/raw/benign.pcap", src_ip=BENIGN_IP, dst_ip=VICTIM_IP, send_live=False):
    rng = random.Random(seed)
    all_packets = []
    next_port = _next_port_factory(rng)
    profile_names = list(PROFILES.keys())
    primary_profile = rng.choice(profile_names)
    secondary_profiles = rng.sample(profile_names, k=min(2, len(profile_names) - 1))
    profile_pool = [primary_profile] * 6 + secondary_profiles
    current_time = 0.0

    print(f"Generating {n_flows} flows (Primary profile: {primary_profile}) -> {output}")

    for _ in range(n_flows):
        profile = PROFILES[rng.choice(profile_pool)]
        
        # Inter-arrival time logic
        if rng.random() < 0.08: iat = rng.uniform(2.0, 15.0)
        elif rng.random() < 0.20: iat = rng.uniform(0.005, 0.08)
        else: iat = max(0.002, rng.gauss(profile["iat_mean"], profile["iat_jitter"]))
        
        current_time += iat
        flow_type = rng.choices(list(profile["weights"].keys()), weights=list(profile["weights"].values()), k=1)[0]
        sport = next_port()

        if flow_type == "web_http":
            all_packets.extend(_web_flow(src_ip, dst_ip, sport, HTTP_PORT, current_time, rng, protocol="http"))
        elif flow_type == "web_https":
            all_packets.extend(_web_flow(src_ip, dst_ip, sport, HTTPS_PORT, current_time, rng, protocol="tls"))
        elif flow_type == "dns":
            all_packets.extend(_dns_query(src_ip, DNS_SERVER, sport, current_time, rng))
        elif flow_type == "bulk":
            dst_port, proto = rng.choice([(HTTP_PORT, "http"), (HTTPS_PORT, "tls")])
            all_packets.extend(_bulk_transfer(src_ip, dst_ip, sport, dst_port, current_time, rng, protocol=proto))
        elif flow_type == "ssh":
            all_packets.extend(_ssh_flow(src_ip, dst_ip, sport, current_time, rng))
        else:
            all_packets.extend(_ntp_like(src_ip, dst_ip, sport, current_time, rng))

    all_packets.sort(key=lambda p: float(p.time))

    if send_live:
        # Half of all_packets are synthetic "replies" crafted with
        # src=dst_ip (the victim) so a single script can produce a
        # complete two-sided conversation offline. Sending those live
        # would mean addressing a real packet to our OWN IP — scapy has
        # no real ARP entry for that, so it hangs resolving each one
        # (falls back to broadcast after a ~1-2s timeout, per packet,
        # which is what "taking forever" was). Only the genuine outbound
        # half (src == our real address) can actually go out on the
        # wire; the full bidirectional set is still written to the pcap
        # below for offline/dataset use.
        outbound = [p for p in all_packets if p[IP].src == src_ip]
        for index, packet in enumerate(outbound):
            send(packet, verbose=False)
            if index + 1 < len(outbound):
                pause = max(0.0, float(outbound[index + 1].time) - float(packet.time))
                if pause:
                    time.sleep(pause)

    Path(output).parent.mkdir(parents=True, exist_ok=True)
    wrpcap(output, all_packets)
    if send_live:
        print(f"Sent {len(outbound)} outbound packets live (of {len(all_packets)} total in the archived pcap) to {output}.")
    else:
        print(f"Successfully wrote {len(all_packets)} packets to {output}.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="data/raw/benign.pcap")
    parser.add_argument("--flows", type=int, default=1500)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--src-ip", default=BENIGN_IP)
    parser.add_argument("--dst-ip", default=VICTIM_IP)
    parser.add_argument(
        "--send-live", action="store_true",
        help="Actually transmit the generated packets in real time (for the live lab demo), "
             "instead of only writing a PCAP for offline/dataset use.",
    )
    args = parser.parse_args()
    generate_benign_pcap(args.flows, args.seed, args.output, args.src_ip, args.dst_ip, args.send_live)
