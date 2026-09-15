"""
Aegis — Synthetic C2 Beaconing PCAP Generator.

Purpose:
Generate offline, synthetic C2-like TCP beaconing traffic for the Aegis
Zeek -> feature pipeline.

Important:
    - Nothing is transmitted to a real network.
    - The output is a PCAP containing synthetic TCP connections.
    - Each generated C2 connection is intended to produce one Zeek
      conn.log UID and therefore one feature row in pipeline.py.

Dataset target:
    --flows 1800
        -> approximately/exactly 1800 C2 conn.log rows
        -> approximately/exactly 1800 c2_beacon.parquet rows

Traffic characteristics:
    - Proper TCP three-way handshakes
    - Established request/response exchanges
    - Clean TCP connection teardown
    - Small heartbeat traffic
    - Occasional larger tasking/burst traffic
    - Jittered beacon intervals
    - Variable payload sizes
    - Variable connection duration
    - Multiple synthetic C2 destinations/ports
    - Mostly stable destination behavior characteristic of beaconing
    - No benign background flows mixed into the C2 dataset
    - No real commands, credentials, files, or exfiltrated information

Example:

    python3 /scripts/c2_beacon.py \
        --dst 10.10.0.3 \
        --port 443 \
        --flows 1800 \
        --interval 2 \
        --jitter 5

Output:
    c2_beacon.pcap
"""

from __future__ import annotations

import argparse
import random

from scapy.all import IP, TCP, Raw, wrpcap


# ============================================================================
# Synthetic source
# ============================================================================

SOURCE_IP = "10.0.0.10"


# ============================================================================
# Optional synthetic destinations
#
# Most C2 connections stay on the requested destination. A small minority
# use alternate synthetic endpoints so that the source does not have a
# completely identical destination distribution.
# ============================================================================

EXTRA_DESTINATIONS = [
    "10.0.0.20",
    "10.0.0.21",
    "10.0.0.22",
    "10.0.0.23",
]


HTTPS_PORTS = [
    443,
    8443,
    9443,
]


# ============================================================================
# TCP helpers
# ============================================================================

def random_seq() -> int:
    """Generate a synthetic TCP initial sequence number."""
    return random.randint(1_000_000, 4_000_000_000)


def random_source_port() -> int:
    """Generate an ephemeral source port."""
    return random.randint(1024, 65535)


def build_handshake(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    client_seq: int,
):
    """
    Create a synthetic TCP three-way handshake.

    Returns:
        packets,
        next_client_seq,
        next_server_seq
    """

    server_seq = random_seq()

    syn = (
        IP(src=src_ip, dst=dst_ip)
        / TCP(
            sport=src_port,
            dport=dst_port,
            flags="S",
            seq=client_seq,
        )
    )

    synack = (
        IP(src=dst_ip, dst=src_ip)
        / TCP(
            sport=dst_port,
            dport=src_port,
            flags="SA",
            seq=server_seq,
            ack=client_seq + 1,
        )
    )

    ack = (
        IP(src=src_ip, dst=dst_ip)
        / TCP(
            sport=src_port,
            dport=dst_port,
            flags="A",
            seq=client_seq + 1,
            ack=server_seq + 1,
        )
    )

    return [
        syn,
        synack,
        ack,
    ], client_seq + 1, server_seq + 1


def build_tcp_exchange(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    client_seq: int,
    server_seq: int,
    request_size: int,
    response_size: int,
):
    """
    Create one synthetic application request/response exchange.

    Payloads contain only repeated synthetic bytes.

    No real application commands, credentials, files, or extracted data
    are included.
    """

    packets = []

    # ------------------------------------------------------------------
    # Client request
    # ------------------------------------------------------------------

    request = (
        IP(src=src_ip, dst=dst_ip)
        / TCP(
            sport=src_port,
            dport=dst_port,
            flags="PA",
            seq=client_seq,
            ack=server_seq,
        )
        / Raw(load=b"R" * request_size)
    )

    packets.append(request)

    client_seq += request_size

    # ------------------------------------------------------------------
    # Server ACK
    # ------------------------------------------------------------------

    client_ack = (
        IP(src=dst_ip, dst=src_ip)
        / TCP(
            sport=dst_port,
            dport=src_port,
            flags="A",
            seq=server_seq,
            ack=client_seq,
        )
    )

    packets.append(client_ack)

    # ------------------------------------------------------------------
    # Server response
    # ------------------------------------------------------------------

    response = (
        IP(src=dst_ip, dst=src_ip)
        / TCP(
            sport=dst_port,
            dport=src_port,
            flags="PA",
            seq=server_seq,
            ack=client_seq,
        )
        / Raw(load=b"S" * response_size)
    )

    packets.append(response)

    server_seq += response_size

    # ------------------------------------------------------------------
    # Client ACK
    # ------------------------------------------------------------------

    server_ack = (
        IP(src=src_ip, dst=dst_ip)
        / TCP(
            sport=src_port,
            dport=dst_port,
            flags="A",
            seq=client_seq,
            ack=server_seq,
        )
    )

    packets.append(server_ack)

    return packets, client_seq, server_seq


def build_close(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    client_seq: int,
    server_seq: int,
):
    """
    Create a clean TCP FIN/ACK teardown.
    """

    packets = []

    # ------------------------------------------------------------------
    # Client FIN
    # ------------------------------------------------------------------

    fin = (
        IP(src=src_ip, dst=dst_ip)
        / TCP(
            sport=src_port,
            dport=dst_port,
            flags="FA",
            seq=client_seq,
            ack=server_seq,
        )
    )

    packets.append(fin)

    # ------------------------------------------------------------------
    # Server ACK
    # ------------------------------------------------------------------

    ack = (
        IP(src=dst_ip, dst=src_ip)
        / TCP(
            sport=dst_port,
            dport=src_port,
            flags="A",
            seq=server_seq,
            ack=client_seq + 1,
        )
    )

    packets.append(ack)

    # ------------------------------------------------------------------
    # Server FIN
    # ------------------------------------------------------------------

    server_fin = (
        IP(src=dst_ip, dst=src_ip)
        / TCP(
            sport=dst_port,
            dport=src_port,
            flags="FA",
            seq=server_seq,
            ack=client_seq + 1,
        )
    )

    packets.append(server_fin)

    # ------------------------------------------------------------------
    # Final ACK
    # ------------------------------------------------------------------

    final_ack = (
        IP(src=src_ip, dst=dst_ip)
        / TCP(
            sport=src_port,
            dport=dst_port,
            flags="A",
            seq=client_seq + 1,
            ack=server_seq + 1,
        )
    )

    packets.append(final_ack)

    return packets


# ============================================================================
# C2 beacon generation
# ============================================================================

def choose_destination(requested_dst: str, requested_port: int):
    """
    Choose a synthetic destination.

    Most traffic remains directed at the requested C2 endpoint.

    A small fraction uses an alternate synthetic endpoint to provide some
    destination diversity without turning the dataset into scanning traffic.
    """

    # 90% of connections use the primary destination.
    if random.random() < 0.90:
        return requested_dst, requested_port

    # 10% use one of the synthetic alternate endpoints.
    dst_ip = random.choice(EXTRA_DESTINATIONS)

    # Mostly HTTPS-like ports.
    if random.random() < 0.85:
        dst_port = random.choice(HTTPS_PORTS)
    else:
        dst_port = requested_port

    return dst_ip, dst_port


def choose_beacon_profile():
    """
    Select a synthetic C2 traffic profile.

    The majority are heartbeat-style connections.
    A smaller portion are tasking/burst-style connections.

    Returns:
        profile name
    """

    value = random.random()

    if value < 0.72:
        return "heartbeat"

    if value < 0.90:
        return "heartbeat_large"

    if value < 0.97:
        return "tasking"

    return "burst"


def choose_payload_sizes(profile: str):
    """
    Choose request/response sizes for a beacon profile.
    """

    if profile == "heartbeat":
        request_size = random.randint(12, 55)
        response_size = random.randint(12, 110)

    elif profile == "heartbeat_large":
        request_size = random.randint(30, 90)
        response_size = random.randint(80, 250)

    elif profile == "tasking":
        request_size = random.randint(80, 300)
        response_size = random.randint(300, 1400)

    else:
        # Larger synthetic operator-tasking/burst exchange.
        request_size = random.randint(100, 500)
        response_size = random.randint(800, 3000)

    return request_size, response_size


def choose_connection_gap(
    base_interval: float,
    jitter_percent: float,
):
    """
    Generate the time until the next beacon.

    --jitter 5 means approximately +/-5% around the requested interval.

    A small fraction of intervals receive a larger deviation so that the
    dataset isn't mathematically perfect periodic traffic.
    """

    jitter_fraction = jitter_percent / 100.0

    lower = max(
        0.01,
        1.0 - jitter_fraction,
    )

    upper = 1.0 + jitter_fraction

    gap = base_interval * random.uniform(
        lower,
        upper,
    )

    # Occasional larger timing deviation.
    if random.random() < 0.08:
        gap *= random.uniform(0.50, 1.50)

    return max(gap, 0.01)


def generate_beacon(
    dst_ip: str,
    dst_port: int,
    current_time: float,
):
    """
    Generate one complete synthetic C2 connection.

    Returns:
        packets
        metadata dictionary
    """

    src_port = random_source_port()

    client_seq = random_seq()

    profile = choose_beacon_profile()

    request_size, response_size = choose_payload_sizes(profile)

    # ------------------------------------------------------------------
    # TCP handshake
    # ------------------------------------------------------------------

    packets, client_seq, server_seq = build_handshake(
        SOURCE_IP,
        dst_ip,
        src_port,
        dst_port,
        client_seq,
    )

    # ------------------------------------------------------------------
    # Application exchange
    # ------------------------------------------------------------------

    exchange, client_seq, server_seq = build_tcp_exchange(
        SOURCE_IP,
        dst_ip,
        src_port,
        dst_port,
        client_seq,
        server_seq,
        request_size,
        response_size,
    )

    packets.extend(exchange)

    # ------------------------------------------------------------------
    # TCP teardown
    # ------------------------------------------------------------------

    packets.extend(
        build_close(
            SOURCE_IP,
            dst_ip,
            src_port,
            dst_port,
            client_seq,
            server_seq,
        )
    )

    # ------------------------------------------------------------------
    # Synthetic packet timing
    #
    # Keep the individual connection short relative to the beacon interval.
    # ------------------------------------------------------------------

    if profile == "heartbeat":
        packet_gap = random.uniform(0.003, 0.015)

    elif profile == "heartbeat_large":
        packet_gap = random.uniform(0.004, 0.020)

    elif profile == "tasking":
        packet_gap = random.uniform(0.005, 0.030)

    else:
        packet_gap = random.uniform(0.005, 0.040)

    for index, packet in enumerate(packets):
        packet.time = current_time + index * packet_gap

    metadata = {
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "request_size": request_size,
        "response_size": response_size,
        "profile": profile,
        "connection_duration": (len(packets) - 1) * packet_gap,
    }

    return packets, metadata


# ============================================================================
# Argument parsing
# ============================================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Generate an offline synthetic C2 beaconing PCAP "
            "with a controlled number of TCP flows."
        )
    )

    parser.add_argument(
        "--dst",
        required=True,
        help="Primary synthetic destination IPv4 address",
    )

    parser.add_argument(
        "--port",
        type=int,
        required=True,
        help="Primary destination TCP port",
    )

    parser.add_argument(
        "--flows",
        type=int,
        default=1800,
        help=(
            "Number of C2 TCP flows to generate "
            "(default: 1800)"
        ),
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help=(
            "Base time between beacon connections in seconds "
            "(default: 2)"
        ),
    )

    parser.add_argument(
        "--duration",
        type=float,
        default=None,
        help=(
            "Optional maximum PCAP duration in seconds. "
            "If omitted, --flows controls the dataset size."
        ),
    )

    parser.add_argument(
        "--jitter",
        type=float,
        default=5.0,
        help=(
            "Jitter percentage around --interval. "
            "For example, 5 means approximately +/-5%% "
            "(default: 5)"
        ),
    )

    parser.add_argument(
        "--output",
        default="c2_beacon.pcap",
        help="Output PCAP path (default: c2_beacon.pcap)",
    )

    return parser.parse_args()


# ============================================================================
# Validation
# ============================================================================

def validate_args(args):
    if not 1 <= args.port <= 65535:
        raise ValueError(
            "--port must be between 1 and 65535"
        )

    if args.flows <= 0:
        raise ValueError(
            "--flows must be greater than zero"
        )

    if args.interval <= 0:
        raise ValueError(
            "--interval must be greater than zero"
        )

    if args.jitter < 0 or args.jitter > 100:
        raise ValueError(
            "--jitter must be between 0 and 100 percent"
        )

    if args.duration is not None and args.duration <= 0:
        raise ValueError(
            "--duration must be greater than zero"
        )


# ============================================================================
# Main
# ============================================================================

def main():
    args = parse_args()

    try:
        validate_args(args)
    except ValueError as exc:
        raise SystemExit(f"Error: {exc}")

    packets = []

    current_time = 0.0

    generated = 0

    profile_counts = {
        "heartbeat": 0,
        "heartbeat_large": 0,
        "tasking": 0,
        "burst": 0,
    }

    print()
    print("=" * 72)
    print("Aegis Synthetic C2 Beacon Generator")
    print("=" * 72)
    print(f"Source       : {SOURCE_IP}")
    print(f"Destination  : {args.dst}:{args.port}")
    print(f"Target flows : {args.flows}")
    print(f"Interval     : ~{args.interval:g}s")
    print(f"Jitter       : ±{args.jitter:g}%")
    print(f"Output       : {args.output}")
    print("=" * 72)
    print()

    # ------------------------------------------------------------------
    # Generate exactly the requested number of C2 connections.
    #
    # There are intentionally NO background connections here because
    # pipeline.py produces one feature row per conn.log UID.
    # ------------------------------------------------------------------

    for flow_number in range(1, args.flows + 1):

        # Select synthetic endpoint.
        dst_ip, dst_port = choose_destination(
            args.dst,
            args.port,
        )

        # Generate one complete C2 connection.
        beacon_packets, metadata = generate_beacon(
            dst_ip,
            dst_port,
            current_time,
        )

        # --------------------------------------------------------------
        # Optional duration guard.
        #
        # By default --flows is authoritative.
        # If --duration is explicitly provided, don't allow the generated
        # timestamps to exceed it.
        # --------------------------------------------------------------

        if args.duration is not None:

            valid_packets = [
                packet
                for packet in beacon_packets
                if float(packet.time) <= args.duration
            ]

            # If the flow cannot fit inside the requested duration,
            # move its starting point so that it does.
            if len(valid_packets) != len(beacon_packets):

                connection_duration = metadata["connection_duration"]

                if connection_duration >= args.duration:
                    current_time = 0.0

                else:
                    current_time = max(
                        0.0,
                        args.duration - connection_duration - 0.001,
                    )

                beacon_packets, metadata = generate_beacon(
                    dst_ip,
                    dst_port,
                    current_time,
                )

                valid_packets = [
                    packet
                    for packet in beacon_packets
                    if float(packet.time) <= args.duration
                ]

                beacon_packets = valid_packets

        packets.extend(beacon_packets)

        generated += 1

        profile = metadata["profile"]

        profile_counts[profile] += 1

        # --------------------------------------------------------------
        # Advance to next beacon.
        # --------------------------------------------------------------

        gap = choose_connection_gap(
            args.interval,
            args.jitter,
        )

        current_time += gap

        # --------------------------------------------------------------
        # Progress output.
        #
        # Printing every flow would create a massive console output for
        # 1,800 flows, so print every 100 flows plus the final flow.
        # --------------------------------------------------------------

        if (
            flow_number == 1
            or flow_number % 100 == 0
            or flow_number == args.flows
        ):
            print(
                f"Generated {flow_number:4d}/{args.flows} "
                f"flows | "
                f"last={profile:<16} "
                f"payload="
                f"{metadata['request_size'] + metadata['response_size']:>5} B"
            )

    # ------------------------------------------------------------------
    # Sort chronologically.
    # ------------------------------------------------------------------

    packets.sort(
        key=lambda packet: float(packet.time)
    )

    # ------------------------------------------------------------------
    # Apply final duration limit if requested.
    # ------------------------------------------------------------------

    if args.duration is not None:
        packets = [
            packet
            for packet in packets
            if float(packet.time) <= args.duration
        ]

    # ------------------------------------------------------------------
    # Write PCAP.
    # ------------------------------------------------------------------

    wrpcap(
        args.output,
        packets,
    )

    # ------------------------------------------------------------------
    # Summary.
    # ------------------------------------------------------------------

    print()
    print("=" * 72)
    print("Generation complete")
    print("=" * 72)
    print(f"C2 flows generated : {generated}")
    print(f"Total packets      : {len(packets)}")
    print()
    print("Traffic profiles:")
    print(
        f"  heartbeat        : {profile_counts['heartbeat']}"
    )
    print(
        f"  heartbeat_large  : {profile_counts['heartbeat_large']}"
    )
    print(
        f"  tasking          : {profile_counts['tasking']}"
    )
    print(
        f"  burst            : {profile_counts['burst']}"
    )
    print()
    print(f"PCAP written to    : {args.output}")
    print("=" * 72)
    print()


if __name__ == "__main__":
    main()