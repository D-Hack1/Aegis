# Lab Setup

## Requirements
- Docker >= 24.0
- Docker Compose >= 2.0

## Starting the Lab
```
make up
```

## Stopping the Lab
```
make down
```

## Container IPs
| Container | IP |
|---|---|
| attacker | 10.10.0.2 |
| victim | 10.10.0.3 |
| benign | 10.10.0.4 |
| zeek | 10.10.0.5 |
| kafka | 10.10.0.6 |
| zookeeper | 10.10.0.7 |
| elasticsearch | 10.10.0.8 |

## Exec into a container
```
make attacker
make victim
make benign
make zeek
```

## Verify network isolation
```
docker network inspect labnet
```
Confirm no gateway is set and masquerade is false.

## Capturing traffic (run inside victim container)
```
tcpdump -i eth0 -w /pcaps/<scenario_name>.pcap
```
PCAPs land in `data/raw/` on the host.

## Retrieving PCAPs
PCAPs are written directly to `./data/raw/` via the volume mount. No copy needed.

## Running an attack script (run inside attacker container)
```
python3 /scripts/c2_beacon.py --dst 10.10.0.3 --port 443 --duration 300
```

## Kafka topics
```
make health
```

## Zeek logs
Zeek logs are written to `./zeek/logs/` on the host.
```
tail -f zeek/logs/conn.log
```
