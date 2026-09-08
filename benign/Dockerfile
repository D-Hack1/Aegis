FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iperf3\
    curl \
    wget\
    python3\
    && rm -rf /var/lib/apt/lists/*

WORKDIR /scripts

CMD ["tail", "-f", "/dev/null"]
