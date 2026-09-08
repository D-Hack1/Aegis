import argparse
import random
import string
from scapy.all import IP, UDP, DNS, DNSQR, wrpcap

def generate_dga_domain(seed, length=12):
    random.seed(seed)
    tlds = [".com", ".net", ".org", ".info", ".biz"]
    domain = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
    tld = random.choice(tlds)
    return domain + tld

def main():
    parser = argparse.ArgumentParser(description="DGA Traffic Generator")
    parser.add_argument("--dns-server", required=True, help="DNS Server IP (dst)")
    parser.add_argument("--duration", type=int, default=3600, help="Total duration to run in seconds")
    parser.add_argument("--queries-per-min", type=int, default=30, help="Number of queries per minute (20-50)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for DGA generation")
    parser.add_argument("--output", default="data/raw/dga_candidate.pcap", help="Output PCAP file")
    args = parser.parse_args()

    query_interval = 60.0 / args.queries_per_min
    current_seed = args.seed
    
    packets = []
    current_time = 0.0

    print(f"Generating DGA traffic to {args.dns_server} for {args.duration} seconds...")

    while current_time < args.duration:
        domain = generate_dga_domain(current_seed)
        current_seed += 1 # change seed for next domain
        
        # Send DNS query
        pkt = IP(dst=args.dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
        pkt.time = current_time
        packets.append(pkt)
        
        # Calculate next query time with slight jitter
        jitter = random.uniform(-0.1 * query_interval, 0.1 * query_interval)
        current_time += (query_interval + jitter)

    wrpcap(args.output, packets)
    print(f"Completed DGA traffic generation. Wrote {len(packets)} packets to {args.output}.")

if __name__ == "__main__":
    main()
