
#!/usr/bin/env python3

"""
Aegis — Synthetic Exfiltration PCAP Generator

Generates synthetic TCP-based exfiltration traffic for ML/Zeek
feature extraction.

IMPORTANT:
    - Exactly --flows network flows are generated.
    - ALL generated flows are exfiltration.
    - No benign traffic is generated.
    - Payloads are synthetic random bytes only.
    - No real files, credentials, documents, databases, or system data
      are accessed.

Traffic characteristics:
    - TCP only
    - Client -> server carries the majority of the data
    - Server -> client sends small response payloads
    - High outbound/inbound byte ratio
    - resp_bytes > 0
    - Long-lived connections
    - Variable transfer rates
    - Bursty and irregular timing
    - Multiple exfiltration profiles

Profiles:
    - slow_exfil
    - low_volume_exfil
    - medium_burst
    - high_burst
    - irregular_exfil

Default:
    1500 flows

Example:

    python3 /scripts/exfiltration.py \
        --dst 10.10.0.3 \
        --src 10.10.0.2 \
        --port 443 \
        --flows 1500 \
        --seed 42 \
        --output /pcaps/exfiltration.pcap
"""

from __future__ import annotations

import argparse
import random
from collections import Counter
from pathlib import Path

from scapy.all import IP, TCP, Raw, wrpcap


# ============================================================================
# CONSTANTS
# ============================================================================

DEFAULT_SOURCE_IP = "10.10.0.2"
DEFAULT_DESTINATION_IP = "10.10.0.3"

DEFAULT_DESTINATION_PORT = 443
DEFAULT_FLOW_COUNT = 1500
DEFAULT_SEED = 42

PROTO_TCP = "tcp"


# ============================================================================
# EXFILTRATION PROFILES
# ============================================================================

PROFILES = [
    "slow_exfil",
    "low_volume_exfil",
    "medium_burst",
    "high_burst",
    "irregular_exfil",
]

PROFILE_WEIGHTS = [
    0.20,
    0.20,
    0.20,
    0.20,
    0.20,
]


# ============================================================================
# TCP HANDSHAKE
# ============================================================================

def tcp_handshake(
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    client_seq: int,
    server_seq: int,
) -> list:

    packets = []

    syn = (
        IP(
            src=source_ip,
            dst=destination_ip,
        )
        /
        TCP(
            sport=source_port,
            dport=destination_port,
            flags="S",
            seq=client_seq,
        )
    )

    syn_ack = (
        IP(
            src=destination_ip,
            dst=source_ip,
        )
        /
        TCP(
            sport=destination_port,
            dport=source_port,
            flags="SA",
            seq=server_seq,
            ack=client_seq + 1,
        )
    )

    ack = (
        IP(
            src=source_ip,
            dst=destination_ip,
        )
        /
        TCP(
            sport=source_port,
            dport=destination_port,
            flags="A",
            seq=client_seq + 1,
            ack=server_seq + 1,
        )
    )

    packets.extend(
        [
            syn,
            syn_ack,
            ack,
        ]
    )

    return packets


# ============================================================================
# TCP TEARDOWN
# ============================================================================

def tcp_teardown(
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    client_seq: int,
    server_seq: int,
) -> list:

    packets = []

    fin = (
        IP(
            src=source_ip,
            dst=destination_ip,
        )
        /
        TCP(
            sport=source_port,
            dport=destination_port,
            flags="FA",
            seq=client_seq,
            ack=server_seq,
        )
    )

    ack = (
        IP(
            src=destination_ip,
            dst=source_ip,
        )
        /
        TCP(
            sport=destination_port,
            dport=source_port,
            flags="A",
            seq=server_seq,
            ack=client_seq + 1,
        )
    )

    server_fin = (
        IP(
            src=destination_ip,
            dst=source_ip,
        )
        /
        TCP(
            sport=destination_port,
            dport=source_port,
            flags="FA",
            seq=server_seq,
            ack=client_seq + 1,
        )
    )

    final_ack = (
        IP(
            src=source_ip,
            dst=destination_ip,
        )
        /
        TCP(
            sport=source_port,
            dport=destination_port,
            flags="A",
            seq=client_seq + 1,
            ack=server_seq + 1,
        )
    )

    packets.extend(
        [
            fin,
            ack,
            server_fin,
            final_ack,
        ]
    )

    return packets


# ============================================================================
# PROFILE SELECTION
# ============================================================================

def choose_profile(
    rng: random.Random,
) -> str:

    return rng.choices(
        PROFILES,
        weights=PROFILE_WEIGHTS,
        k=1,
    )[0]


# ============================================================================
# PROFILE PARAMETERS
# ============================================================================

def profile_parameters(
    rng: random.Random,
    profile: str,
) -> dict:

    # ------------------------------------------------------------------------
    # SLOW EXFILTRATION
    # ------------------------------------------------------------------------

    if profile == "slow_exfil":

        return {
            "protocol": PROTO_TCP,
            "packet_count": rng.randint(100, 180),

            # Slow sustained transfer.
            "packet_interval": rng.uniform(
                0.20,
                0.60,
            ),

            "min_size": 500,
            "max_size": 1200,

            # Probability of compressed/bursty timing.
            "burstiness": rng.uniform(
                0.05,
                0.20,
            ),

            # Server response payload size.
            "response_min_size": 20,
            "response_max_size": 100,
        }


    # ------------------------------------------------------------------------
    # LOW-VOLUME EXFILTRATION
    # ------------------------------------------------------------------------

    if profile == "low_volume_exfil":

        return {
            "protocol": PROTO_TCP,
            "packet_count": rng.randint(
                120,
                220,
            ),

            "packet_interval": rng.uniform(
                0.08,
                0.25,
            ),

            "min_size": 300,
            "max_size": 900,

            "burstiness": rng.uniform(
                0.10,
                0.30,
            ),

            "response_min_size": 20,
            "response_max_size": 80,
        }


    # ------------------------------------------------------------------------
    # MEDIUM BURST EXFILTRATION
    # ------------------------------------------------------------------------

    if profile == "medium_burst":

        return {
            "protocol": PROTO_TCP,

            "packet_count": rng.randint(
                150,
                350,
            ),

            "packet_interval": rng.uniform(
                0.02,
                0.08,
            ),

            "min_size": 500,
            "max_size": 1400,

            "burstiness": rng.uniform(
                0.25,
                0.60,
            ),

            "response_min_size": 30,
            "response_max_size": 120,
        }


    # ------------------------------------------------------------------------
    # HIGH-VOLUME BURST EXFILTRATION
    # ------------------------------------------------------------------------

    if profile == "high_burst":

        return {
            "protocol": PROTO_TCP,

            "packet_count": rng.randint(
                200,
                450,
            ),

            "packet_interval": rng.uniform(
                0.005,
                0.035,
            ),

            "min_size": 700,
            "max_size": 1450,

            "burstiness": rng.uniform(
                0.45,
                0.85,
            ),

            "response_min_size": 30,
            "response_max_size": 150,
        }


    # ------------------------------------------------------------------------
    # IRREGULAR EXFILTRATION
    # ------------------------------------------------------------------------

    return {
        "protocol": PROTO_TCP,

        "packet_count": rng.randint(
            100,
            300,
        ),

        "packet_interval": rng.uniform(
            0.03,
            0.30,
        ),

        "min_size": 200,
        "max_size": 1450,

        "burstiness": rng.uniform(
            0.20,
            0.80,
        ),

        "response_min_size": 20,
        "response_max_size": 120,
    }


# ============================================================================
# SYNTHETIC PAYLOAD
# ============================================================================

def synthetic_payload(
    rng: random.Random,
    size: int,
) -> bytes:

    """
    Generate completely synthetic payload bytes.

    No real host data is accessed.
    """

    return bytes(
        rng.randrange(
            0,
            256,
        )
        for _ in range(size)
    )


# ============================================================================
# TCP FLOW
# ============================================================================

def generate_tcp_flow(
    rng: random.Random,
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    start_time: float,
    parameters: dict,
) -> tuple[list, int, int, int]:

    packets = []

    client_seq = rng.randint(
        1_000_000,
        4_000_000_000,
    )

    server_seq = rng.randint(
        1_000_000,
        4_000_000_000,
    )

    # ------------------------------------------------------------------------
    # HANDSHAKE
    # ------------------------------------------------------------------------

    handshake = tcp_handshake(
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        client_seq=client_seq,
        server_seq=server_seq,
    )

    handshake[0].time = start_time
    handshake[1].time = start_time + 0.001
    handshake[2].time = start_time + 0.002

    packets.extend(handshake)

    # SYN consumes one sequence number on both sides.
    client_seq += 1
    server_seq += 1

    current_time = start_time + 0.003

    packet_count = parameters["packet_count"]
    base_interval = parameters["packet_interval"]

    min_size = parameters["min_size"]
    max_size = parameters["max_size"]

    burstiness = parameters["burstiness"]

    response_min_size = parameters["response_min_size"]
    response_max_size = parameters["response_max_size"]

    total_upload_bytes = 0
    total_response_bytes = 0

    # ------------------------------------------------------------------------
    # BIDIRECTIONAL DATA TRANSFER
    # ------------------------------------------------------------------------
    #
    # The client sends substantially more data than the server.
    #
    # This creates:
    #
    #     orig_bytes  >> resp_bytes
    #
    # while still ensuring:
    #
    #     resp_bytes > 0
    #
    # ------------------------------------------------------------------------

    for packet_index in range(packet_count):

        # --------------------------------------------------------------------
        # CLIENT UPLOAD
        # --------------------------------------------------------------------

        payload_size = rng.randint(
            min_size,
            max_size,
        )

        payload = synthetic_payload(
            rng=rng,
            size=payload_size,
        )

        # Variable timing.
        if rng.random() < burstiness:

            interval_multiplier = rng.uniform(
                0.15,
                0.60,
            )

        else:

            interval_multiplier = rng.uniform(
                0.75,
                1.35,
            )

        interval = (
            base_interval
            * interval_multiplier
        )

        upload_packet = (
            IP(
                src=source_ip,
                dst=destination_ip,
            )
            /
            TCP(
                sport=source_port,
                dport=destination_port,
                flags="PA",
                seq=client_seq,
                ack=server_seq,
            )
            /
            Raw(
                load=payload,
            )
        )

        upload_packet.time = current_time

        packets.append(upload_packet)

        client_seq += payload_size
        total_upload_bytes += payload_size

        # --------------------------------------------------------------------
        # SERVER RESPONSE
        # --------------------------------------------------------------------
        #
        # This is intentionally much smaller than the upload.
        #
        # The server response represents application-level acknowledgement /
        # transfer control rather than another large data stream.
        # --------------------------------------------------------------------

        response_size = rng.randint(
            response_min_size,
            response_max_size,
        )

        response_payload = synthetic_payload(
            rng=rng,
            size=response_size,
        )

        response_packet = (
            IP(
                src=destination_ip,
                dst=source_ip,
            )
            /
            TCP(
                sport=destination_port,
                dport=source_port,
                flags="PA",
                seq=server_seq,
                ack=client_seq,
            )
            /
            Raw(
                load=response_payload,
            )
        )

        response_packet.time = current_time + 0.001

        packets.append(response_packet)

        server_seq += response_size
        total_response_bytes += response_size

        # --------------------------------------------------------------------
        # CLIENT ACK
        # --------------------------------------------------------------------

        client_ack = (
            IP(
                src=source_ip,
                dst=destination_ip,
            )
            /
            TCP(
                sport=source_port,
                dport=destination_port,
                flags="A",
                seq=client_seq,
                ack=server_seq,
            )
        )

        client_ack.time = current_time + 0.002

        packets.append(client_ack)

        current_time += interval

    # ------------------------------------------------------------------------
    # TEARDOWN
    # ------------------------------------------------------------------------

    teardown = tcp_teardown(
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        client_seq=client_seq,
        server_seq=server_seq,
    )

    teardown_start = current_time + 0.002

    for index, packet in enumerate(teardown):

        packet.time = (
            teardown_start
            + index * 0.001
        )

    packets.extend(teardown)

    return (
        packets,
        packet_count,
        total_upload_bytes,
        total_response_bytes,
    )


# ============================================================================
# MAIN
# ============================================================================

def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "Generate synthetic TCP-based exfiltration PCAP traffic."
        )
    )

    parser.add_argument(
        "--dst",
        default=DEFAULT_DESTINATION_IP,
        help=(
            "Destination IP address. "
            f"Default: {DEFAULT_DESTINATION_IP}"
        ),
    )

    parser.add_argument(
        "--src",
        default=DEFAULT_SOURCE_IP,
        help=(
            "Source IP address. "
            f"Default: {DEFAULT_SOURCE_IP}"
        ),
    )

    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_DESTINATION_PORT,
        help=(
            "Starting destination port. "
            f"Default: {DEFAULT_DESTINATION_PORT}"
        ),
    )

    parser.add_argument(
        "--flows",
        type=int,
        default=DEFAULT_FLOW_COUNT,
        help=(
            "Number of distinct flows. "
            f"Default: {DEFAULT_FLOW_COUNT}"
        ),
    )

    parser.add_argument(
        "--burst-duration",
        type=float,
        default=5.0,
        help=(
            "Compatibility option retained "
            "from the original interface."
        ),
    )

    parser.add_argument(
        "--idle-gap",
        type=float,
        default=0.05,
        help="Gap between generated flows in seconds.",
    )

    parser.add_argument(
        "--duration",
        type=float,
        default=3600.0,
        help="Maximum nominal capture duration.",
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help="Random seed for reproducibility.",
    )

    parser.add_argument(
        "--output",
        default="/pcaps/exfiltration.pcap",
        help="Output PCAP path.",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print every generated flow.",
    )

    args = parser.parse_args()

    # ------------------------------------------------------------------------
    # VALIDATION
    # ------------------------------------------------------------------------

    if args.flows <= 0:

        parser.error(
            "--flows must be greater than zero"
        )

    if not 1 <= args.port <= 65535:

        parser.error(
            "--port must be between 1 and 65535"
        )

    if args.idle_gap < 0:

        parser.error(
            "--idle-gap must be zero or greater"
        )

    if args.duration <= 0:

        parser.error(
            "--duration must be greater than zero"
        )

    # ------------------------------------------------------------------------
    # RNG
    # ------------------------------------------------------------------------

    rng = random.Random(
        args.seed
    )

    packets = []

    profile_counts = Counter()

    protocol_counts = Counter()

    total_upload_bytes = 0
    total_response_bytes = 0

    total_data_packets = 0

    current_time = 0.0

    # ------------------------------------------------------------------------
    # HEADER
    # ------------------------------------------------------------------------

    print("=" * 76)
    print("Aegis — Synthetic TCP Exfiltration PCAP Generator")
    print("=" * 76)

    print(
        f"Source IP       : {args.src}"
    )

    print(
        f"Destination IP  : {args.dst}"
    )

    print(
        f"Starting port   : {args.port}"
    )

    print(
        f"Flows           : {args.flows}"
    )

    print(
        f"Seed            : {args.seed}"
    )

    print(
        f"Output          : {args.output}"
    )

    print()

    print("Traffic type    : EXFILTRATION ONLY")
    print("Protocol        : TCP ONLY")
    print("Direction       : BIDIRECTIONAL")
    print("Upload          : HIGH")
    print("Response        : SMALL / NON-ZERO")

    print("=" * 76)

    # ------------------------------------------------------------------------
    # GENERATE FLOWS
    # ------------------------------------------------------------------------

    for flow_index in range(args.flows):

        profile = choose_profile(
            rng
        )

        parameters = profile_parameters(
            rng,
            profile,
        )

        protocol = parameters["protocol"]

        # --------------------------------------------------------------------
        # UNIQUE SOURCE PORT
        # --------------------------------------------------------------------

        source_port = (
            10000 + flow_index
        )

        if source_port > 65535:

            source_port = (
                1024
                + (
                    flow_index
                    % 64511
                )
            )

        # --------------------------------------------------------------------
        # DESTINATION PORT
        # --------------------------------------------------------------------

        available_ports = (
            65536 - args.port
        )

        destination_port = (
            args.port
            + (
                flow_index
                % max(
                    available_ports,
                    1,
                )
            )
        )

        if destination_port > 65535:

            destination_port = args.port

        # --------------------------------------------------------------------
        # GENERATE TCP FLOW
        # --------------------------------------------------------------------

        (
            flow_packets,
            data_packets,
            upload_bytes,
            response_bytes,
        ) = generate_tcp_flow(
            rng=rng,
            source_ip=args.src,
            destination_ip=args.dst,
            source_port=source_port,
            destination_port=destination_port,
            start_time=current_time,
            parameters=parameters,
        )

        packets.extend(
            flow_packets
        )

        # --------------------------------------------------------------------
        # STATISTICS
        # --------------------------------------------------------------------

        profile_counts[
            profile
        ] += 1

        protocol_counts[
            protocol
        ] += 1

        total_data_packets += (
            data_packets
        )

        total_upload_bytes += (
            upload_bytes
        )

        total_response_bytes += (
            response_bytes
        )

        # --------------------------------------------------------------------
        # MOVE TO NEXT FLOW
        # --------------------------------------------------------------------

        last_packet_time = max(
            float(packet.time)
            for packet in flow_packets
        )

        if args.idle_gap > 0:

            gap = rng.uniform(
                args.idle_gap * 0.5,
                args.idle_gap * 1.5,
            )

        else:

            gap = 0.001

        current_time = (
            last_packet_time
            + gap
        )

        # --------------------------------------------------------------------
        # PROGRESS
        # --------------------------------------------------------------------

        if (
            args.verbose
            or flow_index == 0
            or (flow_index + 1) % 100 == 0
            or flow_index + 1 == args.flows
        ):

            print(
                f"Generated "
                f"{flow_index + 1:4d}/"
                f"{args.flows} "
                f"| {profile:20s} "
                f"| TCP "
                f"| upload="
                f"{upload_bytes} "
                f"| response="
                f"{response_bytes}"
            )

    # ------------------------------------------------------------------------
    # SORT CHRONOLOGICALLY
    # ------------------------------------------------------------------------

    packets.sort(
        key=lambda packet: float(
            packet.time
        )
    )

    # ------------------------------------------------------------------------
    # WRITE PCAP
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
    # SUMMARY
    # ------------------------------------------------------------------------

    print()
    print("=" * 76)
    print("Generation complete")
    print("=" * 76)

    print(
        f"Flows generated       : {args.flows}"
    )

    print(
        f"Packets written       : {len(packets)}"
    )

    print(
        f"Data packet groups    : {total_data_packets}"
    )

    print(
        f"Upload bytes          : "
        f"{total_upload_bytes:,}"
    )

    print(
        f"Response bytes        : "
        f"{total_response_bytes:,}"
    )

    print(
        f"Upload / response     : "
        f"{total_upload_bytes / max(total_response_bytes, 1):.2f}"
    )

    print(
        f"Upload MiB            : "
        f"{total_upload_bytes / (1024 * 1024):.2f}"
    )

    print(
        f"Response MiB          : "
        f"{total_response_bytes / (1024 * 1024):.2f}"
    )

    print()

    print("Profiles:")

    for profile in PROFILES:

        count = profile_counts[
            profile
        ]

        percentage = (
            count
            / args.flows
            * 100
        )

        print(
            f"  {profile:20s} "
            f"{count:5d} "
            f"({percentage:5.1f}%)"
        )

    print()

    print("Protocols:")

    print(
        f"  TCP       "
        f"{args.flows:5d} "
        f"(100.0%)"
    )

    print()

    print("Direction:")

    print(
        f"  upload    "
        f"{args.flows:5d} "
        f"(100.0% dominant)"
    )

    print(
        "  response  "
        f"{args.flows:5d} "
        "(100.0% non-zero)"
    )

    print()

    print(
        f"PCAP saved to: {output_path}"
    )

    print("=" * 76)


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    main()
