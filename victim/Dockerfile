FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends\
    tcpdump\
    && rm -rf /var/lib/apt/lists/*

WORKDIR /pcaps

CMD ["tail", "-f", "/dev/null"]
