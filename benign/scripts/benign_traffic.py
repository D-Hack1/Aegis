"""
benign_traffic.py — Realistic benign traffic generator for Aegis lab.

Runs inside the benign container (10.10.0.4) and generates a mix of:
  - iperf3 TCP throughput tests       → large bidirectional flows
  - curl HTTP downloads               → short-to-medium TCP flows
  - wget file fetches                 → medium TCP flows
  - DNS lookups of real-looking names → normal DNS query pattern

The goal is to produce at least as many flows as the largest attack scenario
so the training dataset is not heavily imbalanced toward attack traffic.

Usage (inside benign container):
    python3 /scripts/benign_traffic.py --target 10.10.0.3 --duration 300

Requirements (already in benign/Dockerfile):
    iperf3, curl, wget
"""

import argparse
import random
import subprocess
import time


# ---------------------------------------------------------------------------
# Real-looking domain names for DNS lookups.
# These are well-known public domains. The container has no internet access
# (masquerade=false in docker-compose), so the lookups will fail to resolve
# but will still generate DNS query traffic that Zeek logs as dns.log rows.
# That is exactly what we want — realistic DNS query patterns.
# ---------------------------------------------------------------------------
DOMAINS = [
    "github.com",
    "google.com",
    "stackoverflow.com",
    "wikipedia.org",
    "npmjs.com",
    "pypi.org",
    "microsoft.com",
    "amazon.com",
    "cloudflare.com",
    "ubuntu.com",
    "debian.org",
    "docs.python.org",
    "api.github.com",
    "mail.google.com",
    "login.microsoftonline.com",
    "s3.amazonaws.com",
    "cdn.jsdelivr.net",
    "fonts.googleapis.com",
    "accounts.google.com",
    "auth.example.com",
]

# HTTP endpoints on the victim (10.10.0.3) — victim runs a plain TCP listener,
# so curl will connect and disconnect cleanly, generating a conn.log row.
HTTP_PATHS = ["/", "/index.html", "/api/v1/status", "/health", "/favicon.ico"]


def run(cmd, timeout=30):
    """Run a shell command, ignoring non-zero exit codes (expected for unreachable hosts)."""
    try:
        subprocess.run(
            cmd,
            shell=True,
            timeout=timeout,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass


def dns_lookup(domain):
    """
    Issue a DNS query using the system resolver.
    Uses 'nslookup' which is available on debian:bookworm-slim without extras.
    Even a failed lookup (NXDOMAIN, timeout) produces a dns.log row in Zeek.
    """
    run(f"nslookup {domain}", timeout=5)


def http_download(target, path):
    """
    Attempt an HTTP GET to the victim.
    curl -s -m 5 suppresses output and gives up after 5 seconds.
    Generates a TCP flow even if the server returns an error or refuses.
    """
    run(f"curl -s -m 5 http://{target}{path}", timeout=8)


def wget_fetch(target, path):
    """
    Attempt a file fetch with wget.
    --tries=1 avoids retry loops. -q suppresses output.
    Generates a distinct TCP flow from the curl flows — different user-agent
    signature means different JA3-like fingerprint characteristics.
    """
    run(f"wget -q --tries=1 -T 5 -O /dev/null http://{target}{path}", timeout=8)


def iperf3_test(target, duration=5, port=5201):
    """
    Run a short iperf3 throughput test against the victim.
    Generates a large bidirectional flow — high orig_bytes AND resp_bytes.
    This is the main source of high-volume benign flows to counterbalance
    the exfiltration scenario which has high orig_bytes only.

    The victim container does not run iperf3 server, so this will fail to
    connect — but the TCP SYN + RST exchange still produces a conn.log row
    with a real flow record. For a more complete test, add iperf3 -s to the
    victim Dockerfile CMD.
    """
    run(f"iperf3 -c {target} -p {port} -t {duration} --json", timeout=duration + 10)


def generate_traffic(target, duration_seconds, seed=None):
    """
    Main loop: randomly mix traffic types for the requested duration.

    The mix is weighted so:
    - DNS lookups are frequent (every ~2-4 seconds) — realistic background noise
    - HTTP/wget are moderate (every ~5-10 seconds)
    - iperf3 tests are occasional (every ~30-60 seconds) — large flows

    Args:
        target:           IP address of the victim container.
        duration_seconds: How long to generate traffic (seconds).
        seed:             Optional random seed for reproducibility.
    """
    if seed is not None:
        random.seed(seed)

    end_time = time.monotonic() + duration_seconds
    flow_count = 0

    print(f"[benign_traffic] Starting benign traffic to {target} for {duration_seconds}s.")

    while time.monotonic() < end_time:
        # Weighted action selection:
        #   40% DNS lookup
        #   25% HTTP curl
        #   20% wget fetch
        #   15% iperf3 test
        action = random.choices(
            ["dns", "http", "wget", "iperf3"],
            weights=[40, 25, 20, 15],
            k=1,
        )[0]

        if action == "dns":
            domain = random.choice(DOMAINS)
            dns_lookup(domain)
            # Extra: sometimes do a subdomain lookup to simulate realistic
            # multi-label DNS activity (not DGA — these are structured names)
            if random.random() < 0.3:
                subdomain = random.choice(["www", "api", "cdn", "static", "mail"])
                dns_lookup(f"{subdomain}.{domain}")
            time.sleep(random.uniform(1.5, 4.0))

        elif action == "http":
            path = random.choice(HTTP_PATHS)
            http_download(target, path)
            time.sleep(random.uniform(3.0, 8.0))

        elif action == "wget":
            path = random.choice(HTTP_PATHS)
            wget_fetch(target, path)
            time.sleep(random.uniform(4.0, 10.0))

        elif action == "iperf3":
            # Short iperf3 test — 3-8 seconds duration
            test_duration = random.randint(3, 8)
            iperf3_test(target, duration=test_duration)
            # Sleep longer after iperf3 to avoid flooding
            time.sleep(random.uniform(20.0, 45.0))

        flow_count += 1

    print(f"[benign_traffic] Done. Generated approximately {flow_count} traffic events.")


def main():
    parser = argparse.ArgumentParser(
        description="Generate realistic benign network traffic for Aegis lab capture."
    )
    parser.add_argument(
        "--target",
        default="10.10.0.3",
        help="IP address of the victim container (default: 10.10.0.3)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=300,
        help="Traffic generation duration in seconds (default: 300)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for reproducible traffic patterns (optional)",
    )
    args = parser.parse_args()

    if args.duration <= 0:
        parser.error("--duration must be greater than zero")

    generate_traffic(
        target=args.target,
        duration_seconds=args.duration,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
