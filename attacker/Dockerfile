FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    hping3\
    nmap\
    python3\
    python3-scapy\
    iodine\
    net-tools\
    tcpreplay\
    && rm -rf /var/lib/apt/lists/*

WORKDIR /scripts
