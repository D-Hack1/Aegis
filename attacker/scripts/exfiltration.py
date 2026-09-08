import argparse
import random
from scapy.all import IP, UDP, Raw, wrpcap

def main():
    parser = argparse.ArgumentParser(description="Data Exfiltration Traffic Generator")
    parser.add_argument("--dst", required=True, help="Destination IP")
    parser.add_argument("--port", type=int, required=True, help="Destination Port")
    parser.add_argument("--burst-duration", type=float, default=5.0, help="Duration of each burst in seconds")
    parser.add_argument("--idle-gap", type=float, default=10.0, help="Idle gap between bursts in seconds")
    parser.add_argument("--duration", type=int, default=3600, help="Total duration to run in seconds")
    parser.add_argument("--output", default="data/raw/exfiltration_candidate.pcap", help="Output PCAP file")
    args = parser.parse_args()

    packets = []
    current_time = 0.0

    print(f"Generating Exfiltration traffic to {args.dst}:{args.port} for {args.duration} seconds...")

    while current_time < args.duration:
        burst_end_time = current_time + args.burst_duration
        
        while current_time < burst_end_time and current_time < args.duration:
            payload_size = random.randint(1200, 1450)
            payload = b"X" * payload_size
            pkt = IP(dst=args.dst) / UDP(dport=args.port) / Raw(load=payload)
            pkt.time = current_time
            packets.append(pkt)
            
            # Small simulated gap to prevent interface buffer overflow on attacker side
            current_time += 0.01
        
        # Idle gap
        current_time += args.idle_gap

    wrpcap(args.output, packets)
    print(f"Completed Exfiltration traffic generation. Wrote {len(packets)} packets to {args.output}.")

if __name__ == "__main__":
    main()
