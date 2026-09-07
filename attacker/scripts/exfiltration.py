import argparse
import time
import random
from scapy.all import IP, UDP, send, Raw

def main():
    parser = argparse.ArgumentParser(description="Data Exfiltration Traffic Generator")
    parser.add_argument("--dst", required=True, help="Destination IP")
    parser.add_argument("--port", type=int, required=True, help="Destination Port")
    parser.add_argument("--burst-duration", type=float, default=5.0, help="Duration of each burst in seconds")
    parser.add_argument("--idle-gap", type=float, default=10.0, help="Idle gap between bursts in seconds")
    parser.add_argument("--duration", type=int, default=3600, help="Total duration to run in seconds")
    args = parser.parse_args()

    start_time = time.time()

    while time.time() - start_time < args.duration:
        burst_start = time.time()
        packets_sent = 0
        print(f"Starting burst of duration {args.burst_duration}s...")
        while time.time() - burst_start < args.burst_duration:
            if time.time() - start_time >= args.duration:
                break
            
            payload_size = random.randint(1200, 1450)
            payload = b"X" * payload_size
            pkt = IP(dst=args.dst) / UDP(dport=args.port) / Raw(load=payload)
            send(pkt, verbose=False)
            packets_sent += 1
            # Small sleep to prevent interface buffer overflow on attacker side
            time.sleep(0.01)
        
        print(f"Burst complete. Sent {packets_sent} packets. Idling for {args.idle_gap}s...")
        
        # Idle gap
        sleep_time = args.idle_gap
        if time.time() + sleep_time > start_time + args.duration:
            sleep_time = (start_time + args.duration) - time.time()
            
        if sleep_time > 0:
            time.sleep(sleep_time)

if __name__ == "__main__":
    main()
