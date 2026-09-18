import sys
import os
from confluent_kafka.admin import AdminClient

topics = {"raw-features", "inference-results", "alerts", "pipeline-metrics"}

def main():
    bootstrap = os.getenv("KAFKA_BOOTSTRAP", "localhost:29092")
    client = AdminClient({"bootstrap.servers": bootstrap})

    metadata = client.list_topics(timeout=10)
    existing = set(metadata.topics.keys())

    missing = topics - existing
    if missing:
        print(f"Fail : missing topics: {missing}")
        sys.exit(1)

    print(f"Success : topics present: {topics}")
    sys.exit(0)

if __name__ == "__main__":
    main()
