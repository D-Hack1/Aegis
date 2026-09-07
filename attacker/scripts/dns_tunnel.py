"""Print the iodine DNS-tunnel workflow used by the isolated lab."""

import argparse
import ipaddress
import shlex


def main():
    parser = argparse.ArgumentParser(
        description="Print the reproducible iodine workflow for the Docker lab."
    )
    parser.add_argument("--server", default="10.10.0.2", help="iodined server IPv4 address")
    parser.add_argument("--domain", default="tunnel.lab", help="Tunnel domain")
    parser.add_argument("--password", default="test", help="iodine shared password")
    parser.add_argument(
        "--tunnel-server-ip",
        default="192.168.99.1",
        help="Tunnel-side server address assigned by iodined",
    )
    parser.add_argument(
        "--capture",
        default="/pcaps/dns_tunnel.pcap",
        help="Victim-side capture path",
    )
    args = parser.parse_args()

    for value, option in ((args.server, "--server"), (args.tunnel_server_ip, "--tunnel-server-ip")):
        try:
            ipaddress.IPv4Address(value)
        except ipaddress.AddressValueError:
            parser.error(f"{option} must be a valid IPv4 address")
    if not args.domain or any(character.isspace() for character in args.domain):
        parser.error("--domain must be a non-empty DNS name without whitespace")
    if not args.password:
        parser.error("--password must not be empty")

    quoted = shlex.quote
    print("Run iodined in the attacker container (10.10.0.2):")
    print(
        f"  iodined -f -P {quoted(args.password)} {quoted(args.tunnel_server_ip)} "
        f"{quoted(args.domain)}"
    )
    print("Capture victim eth0 before starting the client:")
    print(f"  tcpdump -i eth0 -U -w {quoted(args.capture)}")
    print("Run the iodine client in the victim container (10.10.0.3):")
    print(f"  iodine -f -P {quoted(args.password)} {quoted(args.server)} {quoted(args.domain)}")
    print("Both containers require /dev/net/tun. This direct lab setup may fall back to raw UDP after DNS negotiation.")
    print("A real deployment requires DNS delegation of the tunnel domain to the iodined endpoint.")


if __name__ == "__main__":
    main()
