import os
from elasticsearch import Elasticsearch

INDEX = "alerts"

ALERTS_MAPPING = {
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
        "kill_chain_id": {"type": "keyword"},
    }
}


def mapping_is_correct(existing_properties: dict) -> bool:
    """True if every field we aggregate/sort on has its intended explicit type.

    If a document is written before the index exists, Elasticsearch
    auto-creates it with dynamic mapping (strings become analyzed `text`),
    and the /stats and /kill-chains aggregations then fail with
    "Fielddata is disabled on [threat_class]".
    """
    for field in ("threat_class", "severity", "kill_chain_id", "flow_id", "timestamp"):
        want = ALERTS_MAPPING["properties"][field]["type"]
        got = existing_properties.get(field, {}).get("type")
        if got != want:
            return False
    return True


def main():
    host = os.getenv("ES_HOST", "localhost")
    port = os.getenv("ES_PORT", "9200")
    es = Elasticsearch(f"http://{host}:{port}")

    if es.indices.exists(index=INDEX):
        props = es.indices.get_mapping(index=INDEX)[INDEX]["mappings"].get("properties", {})
        if mapping_is_correct(props):
            print("Ok : alerts index already exists with the correct mapping")
            return
        print("Warning : alerts index exists with a WRONG (auto-generated) mapping — "
              "recreating it (existing alerts are dropped; they'd break /stats and /kill-chains anyway)")
        es.indices.delete(index=INDEX)

    es.indices.create(index=INDEX, mappings=ALERTS_MAPPING)
    print("Success : alerts index created")


if __name__ == "__main__":
    main()
