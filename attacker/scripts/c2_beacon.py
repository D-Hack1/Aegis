import argparse
import random
from scapy.all import IP, TCP, Raw, wrpcap

def main():
    parser = argparse.ArgumentParser(description="C2 Beaconing Traffic Generator")
    parser.add_argument("--dst", required=True, help="Destination IP")
    parser.add_argument("--port", type=int, required=True, help="Destination Port")
    parser.add_argument("--interval", type=int, default=60, help="Base interval between beacons in seconds")
    parser.add_argument("--duration", type=int, default=3600, help="Total duration to run in seconds")
    parser.add_argument("--jitter", type=int, default=5, help="Jitter in seconds")
    parser.add_argument("--output", default="data/raw/c2_beacon_candidate.pcap", help="Output PCAP file")
    args = parser.parse_args()

    packets = []
    current_time = 0.0

    print(f"Generating C2 beaconing traffic to {args.dst}:{args.port} for {args.duration} seconds...")

    while current_time < args.duration:
        # Generate slightly varying payload size
        payload_size = random.randint(10, 50)
        payload = b"A" * payload_size
        
        pkt = IP(dst=args.dst) / TCP(dport=args.port, flags="S") / Raw(load=payload)
        pkt.time = current_time
        packets.append(pkt)
        
        sleep_time = max(1, args.interval + random.randint(-args.jitter, args.jitter))
        current_time += sleep_time

    wrpcap(args.output, packets)
    print(f"Completed C2 beacon generation. Wrote {len(packets)} packets to {args.output}.")

if __name__ == "__main__":
    main()
