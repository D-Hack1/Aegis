#!/usr/bin/env python3

"""
Aegis — Synthetic Exfiltration PCAP Generator

Generates an offline synthetic dataset containing exactly --flows
distinct network flows.

Profiles:
    Anomalous-like:
        - slow exfiltration
        - low-volume exfiltration
        - medium bursts
        - high-volume bursts
        - irregular transfers

    Benign:
        - large uploads
        - large downloads
        - backup-style transfers
        - normal application transfers

No real files, credentials, documents, databases, or system data
are accessed. Payloads are synthetic bytes only.

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

from scapy.all import IP, TCP, UDP, Raw, wrpcap


# ============================================================================
# CONSTANTS
# ============================================================================

DEFAULT_SOURCE_IP = "10.10.0.2"
DEFAULT_DESTINATION_IP = "10.10.0.3"

DEFAULT_DESTINATION_PORT = 443
DEFAULT_FLOW_COUNT = 1500
DEFAULT_SEED = 42

# IMPORTANT:
# Do NOT name these TCP / UDP because those names are already occupied
# by Scapy's TCP and UDP packet classes imported above.

PROTO_TCP = "tcp"
PROTO_UDP = "udp"

PROFILES = [
    "slow_exfil",
    "low_volume_exfil",
    "medium_burst",
    "high_burst",
    "irregular_exfil",
    "benign_upload",
    "benign_download",
    "benign_backup",
    "benign_application",
]

PROFILE_WEIGHTS = [
    0.10,  # slow_exfil
    0.10,  # low_volume_exfil
    0.12,  # medium_burst
    0.10,  # high_burst
    0.08,  # irregular_exfil
    0.15,  # benign_upload
    0.10,  # benign_download
    0.10,  # benign_backup
    0.15,  # benign_application
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
    """
    Generate a synthetic TCP three-way handshake.
    """

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
    """
    Generate a synthetic TCP FIN teardown.
    """

    packets = []

    fin_ack = (
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

    server_ack = (
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
            fin_ack,
            server_ack,
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
    """
    Select a traffic profile using weighted probabilities.
    """

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
    """
    Generate characteristics for one flow.

    Returns:
        protocol
        direction
        packet_count
        packet_interval
        min_size
        max_size
        burstiness
    """

    if profile == "slow_exfil":

        return {
            "protocol": PROTO_TCP,
            "direction": "upload",
            "packet_count": rng.randint(5, 15),
            "packet_interval": rng.uniform(
                0.8,
                3.0,
            ),
            "min_size": 80,
            "max_size": 350,
            "burstiness": rng.uniform(
                0.05,
                0.25,
            ),
        }

    if profile == "low_volume_exfil":

        return {
            "protocol": rng.choice(
                [
                    PROTO_TCP,
                    PROTO_UDP,
                ]
            ),
            "direction": "upload",
            "packet_count": rng.randint(12, 30),
            "packet_interval": rng.uniform(
                0.15,
                0.8,
            ),
            "min_size": 100,
            "max_size": 700,
            "burstiness": rng.uniform(
                0.10,
                0.35,
            ),
        }

    if profile == "medium_burst":

        return {
            "protocol": rng.choice(
                [
                    PROTO_TCP,
                    PROTO_UDP,
                ]
            ),
            "direction": "upload",
            "packet_count": rng.randint(25, 60),
            "packet_interval": rng.uniform(
                0.02,
                0.12,
            ),
            "min_size": 350,
            "max_size": 1100,
            "burstiness": rng.uniform(
                0.25,
                0.60,
            ),
        }

    if profile == "high_burst":

        return {
            "protocol": rng.choice(
                [
                    PROTO_TCP,
                    PROTO_UDP,
                ]
            ),
            "direction": "upload",
            "packet_count": rng.randint(50, 110),
            "packet_interval": rng.uniform(
                0.005,
                0.04,
            ),
            "min_size": 700,
            "max_size": 1450,
            "burstiness": rng.uniform(
                0.45,
                0.90,
            ),
        }

    if profile == "irregular_exfil":

        return {
            "protocol": rng.choice(
                [
                    PROTO_TCP,
                    PROTO_UDP,
                ]
            ),
            "direction": "upload",
            "packet_count": rng.randint(15, 80),
            "packet_interval": rng.uniform(
                0.02,
                0.5,
            ),
            "min_size": 100,
            "max_size": 1450,
            "burstiness": rng.uniform(
                0.20,
                0.95,
            ),
        }

    if profile == "benign_upload":

        return {
            "protocol": PROTO_TCP,
            "direction": "upload",
            "packet_count": rng.randint(35, 100),
            "packet_interval": rng.uniform(
                0.01,
                0.08,
            ),
            "min_size": 500,
            "max_size": 1450,
            "burstiness": rng.uniform(
                0.20,
                0.70,
            ),
        }

    if profile == "benign_download":

        return {
            "protocol": PROTO_TCP,
            "direction": "download",
            "packet_count": rng.randint(35, 120),
            "packet_interval": rng.uniform(
                0.008,
                0.07,
            ),
            "min_size": 500,
            "max_size": 1450,
            "burstiness": rng.uniform(
                0.20,
                0.70,
            ),
        }

    if profile == "benign_backup":

        return {
            "protocol": PROTO_TCP,
            "direction": rng.choice(
                [
                    "upload",
                    "download",
                ]
            ),
            "packet_count": rng.randint(50, 140),
            "packet_interval": rng.uniform(
                0.015,
                0.15,
            ),
            "min_size": 250,
            "max_size": 1450,
            "burstiness": rng.uniform(
                0.10,
                0.60,
            ),
        }

    # ------------------------------------------------------------------------
    # benign_application
    # ------------------------------------------------------------------------

    return {
        "protocol": rng.choice(
            [
                PROTO_TCP,
                PROTO_UDP,
            ]
        ),
        "direction": rng.choice(
            [
                "upload",
                "download",
            ]
        ),
        "packet_count": rng.randint(
            10,
            50,
        ),
        "packet_interval": rng.uniform(
            0.03,
            0.3,
        ),
        "min_size": 80,
        "max_size": 1200,
        "burstiness": rng.uniform(
            0.05,
            0.50,
        ),
    }


# ============================================================================
# SYNTHETIC PAYLOAD
# ============================================================================

def synthetic_payload(
    rng: random.Random,
    size: int,
    profile: str,
) -> bytes:
    """
    Create synthetic payload data.

    No real data is read from the host.
    """

    # Anomalous-like traffic gets pseudo-random bytes.
    if profile in {
        "slow_exfil",
        "low_volume_exfil",
        "medium_burst",
        "high_burst",
        "irregular_exfil",
    }:

        return bytes(
            rng.randrange(
                0,
                256,
            )
            for _ in range(size)
        )

    # Benign backup.
    if profile == "benign_backup":

        pattern = b"BACKUP_DATA_BLOCK_"

        repetitions = (
            size // len(pattern)
        ) + 1

        return (
            pattern * repetitions
        )[:size]

    # Benign download.
    if profile == "benign_download":

        pattern = b"APPLICATION_DOWNLOAD_DATA_"

        repetitions = (
            size // len(pattern)
        ) + 1

        return (
            pattern * repetitions
        )[:size]

    # Benign upload.
    if profile == "benign_upload":

        pattern = b"USER_UPLOAD_DATA_"

        repetitions = (
            size // len(pattern)
        ) + 1

        return (
            pattern * repetitions
        )[:size]

    # Normal application.
    pattern = b"NORMAL_APPLICATION_DATA_"

    repetitions = (
        size // len(pattern)
    ) + 1

    return (
        pattern * repetitions
    )[:size]


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
    profile: str,
) -> tuple[list, int, int]:
    """
    Generate exactly one TCP connection.
    """

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
    # Handshake
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

    packets.extend(
        handshake
    )

    client_seq += 1
    server_seq += 1

    # ------------------------------------------------------------------------
    # Transfer parameters
    # ------------------------------------------------------------------------

    current_time = (
        start_time + 0.003
    )

    packet_count = parameters[
        "packet_count"
    ]

    base_interval = parameters[
        "packet_interval"
    ]

    min_size = parameters[
        "min_size"
    ]

    max_size = parameters[
        "max_size"
    ]

    direction = parameters[
        "direction"
    ]

    burstiness = parameters[
        "burstiness"
    ]

    # ------------------------------------------------------------------------
    # Data packets
    # ------------------------------------------------------------------------

    for _ in range(packet_count):

        payload_size = rng.randint(
            min_size,
            max_size,
        )

        payload = synthetic_payload(
            rng=rng,
            size=payload_size,
            profile=profile,
        )

        # Variable inter-arrival time.
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

        # --------------------------------------------------------------------
        # Upload: client -> server
        # --------------------------------------------------------------------

        if direction == "upload":

            data_packet = (
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
                    load=payload
                )
            )

            data_packet.time = (
                current_time
            )

            packets.append(
                data_packet
            )

            client_seq += payload_size

            # ACK from server.
            ack_packet = (
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
                    ack=client_seq,
                )
            )

            ack_packet.time = (
                current_time + 0.001
            )

            packets.append(
                ack_packet
            )

        # --------------------------------------------------------------------
        # Download: server -> client
        # --------------------------------------------------------------------

        else:

            data_packet = (
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
                    load=payload
                )
            )

            data_packet.time = (
                current_time
            )

            packets.append(
                data_packet
            )

            server_seq += payload_size

            # ACK from client.
            ack_packet = (
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

            ack_packet.time = (
                current_time + 0.001
            )

            packets.append(
                ack_packet
            )

        current_time += interval

    # ------------------------------------------------------------------------
    # Teardown
    # ------------------------------------------------------------------------

    teardown = tcp_teardown(
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        client_seq=client_seq,
        server_seq=server_seq,
    )

    teardown_start = (
        current_time + 0.002
    )

    for index, packet in enumerate(
        teardown
    ):

        packet.time = (
            teardown_start
            + index * 0.001
        )

    packets.extend(
        teardown
    )

    # ------------------------------------------------------------------------
    # Payload byte count
    # ------------------------------------------------------------------------

    total_payload_bytes = 0

    for packet in packets:

        if Raw in packet:

            total_payload_bytes += len(
                bytes(
                    packet[Raw].load
                )
            )

    return (
        packets,
        packet_count,
        total_payload_bytes,
    )


# ============================================================================
# UDP FLOW
# ============================================================================

def generate_udp_flow(
    rng: random.Random,
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    start_time: float,
    parameters: dict,
    profile: str,
) -> tuple[list, int, int]:
    """
    Generate exactly one UDP flow.
    """

    packets = []

    packet_count = parameters[
        "packet_count"
    ]

    base_interval = parameters[
        "packet_interval"
    ]

    min_size = parameters[
        "min_size"
    ]

    max_size = parameters[
        "max_size"
    ]

    direction = parameters[
        "direction"
    ]

    burstiness = parameters[
        "burstiness"
    ]

    current_time = start_time

    total_payload_bytes = 0

    # ------------------------------------------------------------------------
    # UDP data
    # ------------------------------------------------------------------------

    for _ in range(packet_count):

        payload_size = rng.randint(
            min_size,
            max_size,
        )

        payload = synthetic_payload(
            rng=rng,
            size=payload_size,
            profile=profile,
        )

        if direction == "upload":

            packet = (
                IP(
                    src=source_ip,
                    dst=destination_ip,
                )
                /
                UDP(
                    sport=source_port,
                    dport=destination_port,
                )
                /
                Raw(
                    load=payload
                )
            )

        else:

            packet = (
                IP(
                    src=destination_ip,
                    dst=source_ip,
                )
                /
                UDP(
                    sport=destination_port,
                    dport=source_port,
                )
                /
                Raw(
                    load=payload
                )
            )

        packet.time = current_time

        packets.append(
            packet
        )

        total_payload_bytes += (
            payload_size
        )

        # Variable burstiness.
        if rng.random() < burstiness:

            multiplier = rng.uniform(
                0.15,
                0.60,
            )

        else:

            multiplier = rng.uniform(
                0.75,
                1.35,
            )

        current_time += (
            base_interval
            * multiplier
        )

    return (
        packets,
        packet_count,
        total_payload_bytes,
    )


# ============================================================================
# MAIN
# ============================================================================

def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "Generate synthetic exfiltration "
            "and benign bulk-transfer traffic."
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
            "Compatibility option retained from the "
            "original interface."
        ),
    )

    parser.add_argument(
        "--idle-gap",
        type=float,
        default=0.05,
        help=(
            "Gap between generated flows in seconds."
        ),
    )

    parser.add_argument(
        "--duration",
        type=float,
        default=3600.0,
        help=(
            "Maximum nominal capture duration."
        ),
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help=(
            "Random seed for reproducibility."
        ),
    )

    parser.add_argument(
        "--output",
        default="/pcaps/exfiltration.pcap",
        help=(
            "Output PCAP path."
        ),
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help=(
            "Print every generated flow."
        ),
    )

    args = parser.parse_args()

    # ------------------------------------------------------------------------
    # Validation
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
    # Random generator
    # ------------------------------------------------------------------------

    rng = random.Random(
        args.seed
    )

    packets = []

    profile_counts = Counter()
    protocol_counts = Counter()
    direction_counts = Counter()

    total_payload_bytes = 0
    total_data_packets = 0

    current_time = 0.0

    # ------------------------------------------------------------------------
    # Header
    # ------------------------------------------------------------------------

    print("=" * 76)
    print(
        "Aegis — Synthetic Exfiltration PCAP Generator"
    )
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

    print("=" * 76)

    # ------------------------------------------------------------------------
    # Generate exactly args.flows
    # ------------------------------------------------------------------------

    for flow_index in range(
        args.flows
    ):

        profile = choose_profile(
            rng
        )

        parameters = profile_parameters(
            rng,
            profile,
        )

        protocol = parameters[
            "protocol"
        ]

        direction = parameters[
            "direction"
        ]

        # --------------------------------------------------------------------
        # UNIQUE SOURCE PORT
        #
        # This makes each generated flow distinguishable to Zeek.
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
        # Destination port
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
        # Generate flow
        # --------------------------------------------------------------------

        if protocol == PROTO_TCP:

            (
                flow_packets,
                data_packets,
                payload_bytes,
            ) = generate_tcp_flow(
                rng=rng,
                source_ip=args.src,
                destination_ip=args.dst,
                source_port=source_port,
                destination_port=destination_port,
                start_time=current_time,
                parameters=parameters,
                profile=profile,
            )

        else:

            (
                flow_packets,
                data_packets,
                payload_bytes,
            ) = generate_udp_flow(
                rng=rng,
                source_ip=args.src,
                destination_ip=args.dst,
                source_port=source_port,
                destination_port=destination_port,
                start_time=current_time,
                parameters=parameters,
                profile=profile,
            )

        packets.extend(
            flow_packets
        )

        # --------------------------------------------------------------------
        # Statistics
        # --------------------------------------------------------------------

        profile_counts[
            profile
        ] += 1

        protocol_counts[
            protocol
        ] += 1

        direction_counts[
            direction
        ] += 1

        total_data_packets += (
            data_packets
        )

        total_payload_bytes += (
            payload_bytes
        )

        # --------------------------------------------------------------------
        # Move to next flow
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
        # Progress
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
                f"| {profile:22s} "
                f"| {protocol.upper():3s} "
                f"| {direction:8s} "
                f"| data_pkts="
                f"{data_packets:3d} "
                f"| bytes="
                f"{payload_bytes}"
            )

    # ------------------------------------------------------------------------
    # Sort chronologically
    # ------------------------------------------------------------------------

    packets.sort(
        key=lambda packet: float(
            packet.time
        )
    )

    # ------------------------------------------------------------------------
    # Write PCAP
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
        f"Data packets          : {total_data_packets}"
    )

    print(
        f"Synthetic payload     : "
        f"{total_payload_bytes:,} bytes"
    )

    print(
        f"Synthetic payload     : "
        f"{total_payload_bytes / (1024 * 1024):.2f} MiB"
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
            f"  {profile:22s} "
            f"{count:5d} "
            f"({percentage:5.1f}%)"
        )

    print()
    print("Protocols:")

    for protocol in [
        PROTO_TCP,
        PROTO_UDP,
    ]:

        count = protocol_counts[
            protocol
        ]

        percentage = (
            count
            / args.flows
            * 100
        )

        print(
            f"  {protocol.upper():6s} "
            f"{count:5d} "
            f"({percentage:5.1f}%)"
        )

    print()
    print("Directions:")

    for direction in [
        "upload",
        "download",
    ]:

        count = direction_counts[
            direction
        ]

        percentage = (
            count
            / args.flows
            * 100
        )

        print(
            f"  {direction:10s} "
            f"{count:5d} "
            f"({percentage:5.1f}%)"
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