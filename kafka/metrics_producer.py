import os
import time
import json
from datetime import datetime, timezone
from confluent_kafka import Producer, Consumer, TopicPartition

TOPIC = "pipeline-metrics"
MONITOR_TOPIC = "raw-features"
GROUP_ID = "feature-consumer-group"
INTERVAL = 2

def get_queue_depth(bootstrap: str) -> int:
    try:
        consumer = Consumer({
            "bootstrap.servers": bootstrap,
            "group.id": GROUP_ID,
            "auto.offset.reset": "earliest"
        })
        partitions = consumer.partitions_for(MONITOR_TOPIC)
        tp = [TopicPartition(MONITOR_TOPIC, p) for p in partitions]
        committed = consumer.committed(tp)
        watermarks = [consumer.get_watermark_offsets(t) for t in committed]
        depth = sum(
            high - t.offset
            for t, (low, high) in zip(committed, watermarks)
            if t.offset >= 0
        )
        consumer.close()
        return depth
    except Exception:
        return -1

def main():
    bootstrap = os.getenv("KAFKA_BOOTSTRAP", "localhost:29092")
    producer = Producer({"bootstrap.servers": bootstrap})

    while True:
        depth = get_queue_depth(bootstrap)
        msg = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "flows_per_sec": 0,
            "bytes_per_sec": 0,
            "kafka_queue_depth": depth,
            "pipeline_latency_ms": 0
        }
        producer.produce(TOPIC, json.dumps(msg).encode())
        producer.flush()
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
