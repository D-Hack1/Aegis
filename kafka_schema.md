# Kafka Topics

Bootstrap server: `localhost:9092` (host) / `kafka:9092` (inside Docker)

## Topics

| Topic | Producer | Consumer | Purpose |
|---|---|---|---|
| raw-features | features/producer.py | kafka/consumer.py | Feature rows from pipeline |
| inference-results | kafka/consumer.py | - | Model output per flow |
| alerts | api/main.py | dashboard | Confirmed positive detections |
| pipeline-metrics | kafka/metrics_producer.py | api/main.py (SSE) | Throughput + latency |

Retention: 6 hours (`retention.ms=21600000`)
Partitions: 1
Replication factor: 1

## pipeline-metrics schema

```json
{
  "ts": "<ISO8601>",
  "flows_per_sec": 0,
  "bytes_per_sec": 0,
  "kafka_queue_depth": 0,
  "pipeline_latency_ms": 0
}
```

