import os
from elasticsearch import Elasticsearch

def main():
    host = os.getenv("ES_HOST", "localhost")
    port = os.getenv("ES_PORT", "9200")
    es = Elasticsearch(f"http://{host}:{port}")

    mapping = {
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "flow_id": {"type": "keyword"},
                "src_ip": {"type": "ip"},
                "dst_ip": {"type": "ip"},
                "src_port": {"type": "integer"},
                "dst_port": {"type": "integer"},
                "threat_class": {"type": "keyword"},
                "confidence": {"type": "float"},
                "anomaly_score": {"type": "float"},
                "severity": {"type": "keyword"},
                "evidence": {"type": "text"},
                "kill_chain_id": {"type": "keyword"}
            }
        }
    }

    if not es.indices.exists(index="alerts"):
        es.indices.create(index="alerts", mappings=mapping["mappings"])
        print("Success : alerts index created")
    else:
        print("Ok : alerts index already exists")

if __name__ == "__main__":
    main()
