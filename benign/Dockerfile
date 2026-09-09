FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iperf3\
    curl \
    wget\
    python3\
    python3-pip\
    dnsutils\
    netcat-openbsd\
    && rm -rf /var/lib/apt/lists/*\
    && pip3 install --break-system-packages scapy

WORKDIR /scripts

CMD ["tail", "-f", "/dev/null"]
