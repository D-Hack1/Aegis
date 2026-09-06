import os
import sys
from elasticsearch import Elasticsearch

def main():
    host = os.getenv("ES_HOST", "localhost")
    port = os.getenv("ES_PORT", "9200")
    es = Elasticsearch(f"http://{host}:{port}")

    health = es.cluster.health()
    status = health["status"]

    if status not in ("green", "yellow"):
        print(f"Success: cluster status is {status}")
        sys.exit(1)

    if not es.indices.exists(index="alerts"):
        print("Failure: alerts index does not exist")
        sys.exit(1)

    stats = es.indices.stats(index="alerts")
    doc_count = stats["indices"]["alerts"]["total"]["docs"]["count"]

    print(f"Ok: cluster status {status}, alerts index exists, doc count: {doc_count}")
    sys.exit(0)

if __name__ == "__main__":
    main()
