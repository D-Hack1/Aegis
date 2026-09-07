import argparse
import time
import random
from scapy.all import IP, TCP, send, Raw

def main():
    parser = argparse.ArgumentParser(description="C2 Beaconing Traffic Generator")
    parser.add_argument("--dst", required=True, help="Destination IP")
    parser.add_argument("--port", type=int, required=True, help="Destination Port")
    parser.add_argument("--interval", type=int, default=60, help="Base interval between beacons in seconds")
    parser.add_argument("--duration", type=int, default=3600, help="Total duration to run in seconds")
    parser.add_argument("--jitter", type=int, default=5, help="Jitter in seconds")
    args = parser.parse_args()

    start_time = time.time()
    
    while time.time() - start_time < args.duration:
        # Generate slightly varying payload size
        payload_size = random.randint(10, 50)
        payload = b"A" * payload_size
        
        pkt = IP(dst=args.dst) / TCP(dport=args.port, flags="S") / Raw(load=payload)
        send(pkt, verbose=False)
        print(f"Sent beacon to {args.dst}:{args.port} with payload size {payload_size}")
        
        sleep_time = max(1, args.interval + random.randint(-args.jitter, args.jitter))
        # Ensure we don't sleep past the total duration
        if time.time() + sleep_time > start_time + args.duration:
            sleep_time = (start_time + args.duration) - time.time()
        
        if sleep_time > 0:
            time.sleep(sleep_time)

if __name__ == "__main__":
    main()
