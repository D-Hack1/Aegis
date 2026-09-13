"""Print the iodine DNS-tunnel workflow used by the isolated lab."""

import argparse
import ipaddress
import shlex
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROFILES = {
    "short_sparse": {"sessions": 300, "session_duration": 1.0, "sessions_per_server": 6, "session_gap": 0.25},
    "steady_medium": {"sessions": 600, "session_duration": 1.5, "sessions_per_server": 12, "session_gap": 0.1},
    "baseline_large": {"sessions": 1500, "session_duration": 2.0, "sessions_per_server": 12, "session_gap": 0.0},
    "long_lived": {"sessions": 500, "session_duration": 5.0, "sessions_per_server": 10, "session_gap": 0.2},
    "dense_batches": {"sessions": 900, "session_duration": 1.0, "sessions_per_server": 15, "session_gap": 0.0},
    "rotating_batches": {"sessions": 1200, "session_duration": 2.5, "sessions_per_server": 6, "session_gap": 0.15},
}
DEFAULTS = {
    "server": "10.10.0.2",
    "domain": "tunnel.lab",
    "password": "test",
    "tunnel_server_ip": "192.168.99.1",
    "output": "/pcaps/dns_tunnel.pcap",
    "sessions": 0,
    "session_duration": 2.0,
    "sessions_per_server": 12,
    "session_gap": 0.0,
    "retries": 3,
    "profile": None,
}


def docker_command(*args):
    return ["docker", *args]


def run_command(command, **kwargs):
    return subprocess.run(command, cwd=ROOT, text=True, **kwargs)


def apply_profile(args):
    profile = getattr(args, "profile", None)
    values = DEFAULTS | (PROFILES[profile] if profile else {}) | vars(args)
    for name, value in values.items():
        setattr(args, name, value)


def stop_capture():
    run_command(
        docker_command(
            "exec",
            "victim",
            "sh",
            "-c",
            "for p in /proc/[0-9]*; do comm=$(cat \"$p/comm\" 2>/dev/null); if [ \"$comm\" = tcpdump ]; then kill -INT \"${p##*/}\"; fi; done",
        ),
        check=True,
    )


def stop_server():
    run_command(
        docker_command(
            "exec",
            "attacker",
            "sh",
            "-c",
            "for p in /proc/[0-9]*; do comm=$(cat \"$p/comm\" 2>/dev/null); if [ \"$comm\" = iodined ]; then kill -TERM \"${p##*/}\"; fi; done",
        ),
        check=True,
    )


def start_server(args):
    run_command(
        docker_command(
            "exec",
            "-d",
            "attacker",
            "iodined",
            "-f",
            "-P",
            args.password,
            args.tunnel_server_ip,
            args.domain,
        ),
        check=True,
    )
    time.sleep(1)


def build_client_command(args):
    client = " ".join(
        shlex.quote(value)
        for value in (
            "iodine",
            "-f",
            "-T",
            "NULL",
            "-P",
            args.password,
            args.server,
            args.domain,
        )
    )
    return client


def run_client_sessions(args, count):
    client = build_client_command(args)
    gap = (
        f"if [ \"$i\" -lt {count} ]; then sleep {args.session_gap:g}; fi; "
        if args.session_gap
        else ""
    )
    loop = (
        "rm -f /tmp/dns_tunnel_sessions.log; "
        f"for i in $(seq 1 {count}); do "
        f"timeout --signal=KILL {args.session_duration:g} {client} "
        ">> /tmp/dns_tunnel_sessions.log 2>&1; "
        f"{gap}"
        "done; grep -c 'Connection setup complete' /tmp/dns_tunnel_sessions.log || true"
    )
    result = run_command(
        docker_command("exec", "victim", "sh", "-c", loop),
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "iodine session loop failed")
    return int(result.stdout.strip() or 0)


def generate_sessions(args):
    stop_server()
    start_server(args)

    stop_capture()
    run_command(
        docker_command(
            "exec",
            "-d",
            "victim",
            "tcpdump",
            "-i",
            "eth0",
            "-U",
            "-w",
            args.output,
        ),
        check=True,
    )
    time.sleep(1)
    completed = 0
    try:
        while completed < args.sessions:
            count = min(args.sessions_per_server, args.sessions - completed)
            batch_completed = 0
            for _ in range(args.retries):
                if batch_completed == count:
                    break
                retry_completed = run_client_sessions(args, count - batch_completed)
                batch_completed += retry_completed
                if retry_completed == 0:
                    break
            if batch_completed != count:
                raise RuntimeError(f"only {batch_completed} of {count} iodine sessions completed")
            completed += batch_completed
            if completed < args.sessions:
                stop_server()
                start_server(args)
    finally:
        try:
            stop_capture()
        finally:
            stop_server()
    print(f"Completed {completed} iodine sessions and captured them to {args.output}.")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Print the reproducible iodine workflow for the Docker lab.",
        argument_default=argparse.SUPPRESS,
    )
    parser.add_argument("--server", help="iodined server IPv4 address")
    parser.add_argument("--domain", help="Tunnel domain")
    parser.add_argument("--password", help="iodine shared password")
    parser.add_argument(
        "--tunnel-server-ip",
        help="Tunnel-side server address assigned by iodined",
    )
    parser.add_argument(
        "--output",
        help="Output PCAP file",
    )
    parser.add_argument("--sessions", type=int, help="Number of short iodine sessions to capture")
    parser.add_argument(
        "--session-duration",
        type=float,
        help="Seconds to keep each iodine client session alive",
    )
    parser.add_argument(
        "--sessions-per-server",
        type=int,
        help="Maximum client sessions before restarting iodined",
    )
    parser.add_argument("--session-gap", type=float, help="Delay between client sessions in seconds")
    parser.add_argument("--retries", type=int, help="Maximum attempts per session batch")
    parser.add_argument("--profile", choices=tuple(PROFILES), help="Bounded iodine session profile")
    args = parser.parse_args(argv)
    apply_profile(args)

    for value, option in ((args.server, "--server"), (args.tunnel_server_ip, "--tunnel-server-ip")):
        try:
            ipaddress.IPv4Address(value)
        except ipaddress.AddressValueError:
            parser.error(f"{option} must be a valid IPv4 address")
    if not args.domain or any(character.isspace() for character in args.domain):
        parser.error("--domain must be a non-empty DNS name without whitespace")
    if not args.password:
        parser.error("--password must not be empty")
    if args.sessions < 0:
        parser.error("--sessions must be zero or greater")
    if args.sessions and args.session_duration <= 0:
        parser.error("--session-duration must be greater than zero when --sessions is used")
    if args.sessions and args.sessions_per_server <= 0:
        parser.error("--sessions-per-server must be greater than zero when --sessions is used")
    if args.session_gap < 0:
        parser.error("--session-gap must be zero or greater")
    if args.retries <= 0:
        parser.error("--retries must be greater than zero")

    return args


def main():
    args = parse_args()

    if args.sessions:
        generate_sessions(args)
        return

    quoted = shlex.quote
    print("Run iodined in the attacker container (10.10.0.2):")
    print(
        f"  iodined -f -P {quoted(args.password)} {quoted(args.tunnel_server_ip)} "
        f"{quoted(args.domain)}"
    )
    print("Capture victim eth0 before starting the client:")
    print(f"  tcpdump -i eth0 -U -w {quoted(args.output)}")
    print("Run the iodine client in the victim container (10.10.0.3):")
    print(f"  iodine -f -P {quoted(args.password)} {quoted(args.server)} {quoted(args.domain)}")
    print("Both containers require /dev/net/tun. This direct lab setup may fall back to raw UDP after DNS negotiation.")
    print("A real deployment requires DNS delegation of the tunnel domain to the iodined endpoint.")


if __name__ == "__main__":
    main()
