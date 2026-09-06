import json

import pytest

from kafka import producer


def test_serialise_dict():
    row = {
        "flow_id": "C123",
        "src_ip": "192.168.1.10",
        "dst_ip": "8.8.8.8",
    }

    result = producer._serialise(row)

    assert isinstance(result, bytes)

    decoded = json.loads(result.decode("utf-8"))

    assert decoded == row


def test_serialise_feature_row():
    row = {
        "flow_id": "C123",
        "src_ip": "192.168.1.10",
    }

    # This verifies the dictionary path used by the producer.
    result = producer._serialise(row)

    assert result is not None
    assert json.loads(result.decode("utf-8"))["flow_id"] == "C123"


def test_kafka_key_with_src_ip():
    row = {
        "flow_id": "C123",
        "src_ip": "192.168.1.10",
    }

    result = producer._key(row)

    assert result == b"192.168.1.10"


def test_kafka_key_without_src_ip():
    row = {
        "flow_id": "C123",
    }

    result = producer._key(row)

    assert result is None


def test_serialise_invalid_object(monkeypatch):
    class BadObject:
        pass

    def fake_to_json(_):
        raise TypeError("cannot serialize")

    monkeypatch.setattr(producer, "to_json", fake_to_json)

    result = producer._serialise(BadObject())

    assert result is None


def test_publish_calls_kafka_producer():
    class FakeProducer:
        def __init__(self):
            self.called = False
            self.topic = None
            self.value = None
            self.key = None

        def produce(self, topic, key, value, on_delivery):
            self.called = True
            self.topic = topic
            self.key = key
            self.value = value

        def poll(self, timeout):
            pass

    fake = FakeProducer()

    payload = {
        "flow_id": "C123",
        "threat_class": "benign",
    }

    producer._publish(
        fake,
        "raw-features",
        payload,
        key="192.168.1.10",
    )

    assert fake.called is True
    assert fake.topic == "raw-features"
    assert fake.key == b"192.168.1.10"

    decoded = json.loads(fake.value.decode("utf-8"))

    assert decoded["flow_id"] == "C123"