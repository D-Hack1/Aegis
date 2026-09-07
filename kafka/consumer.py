"""
Reads FeatureRow messages from the `raw-features` Kafka topic.
For each message:
  1. Deserialise JSON → FeatureRow
  2. Record arrival timestamp
  3. POST feature vector to FastAPI /infer
  4. Record response timestamp → compute pipeline_latency_ms
  5. Publish inference result to `inference-results` topic
  6. Publish throughput metrics to `pipeline-metrics` topic

Dead-letter log: malformed / unprocessable messages go to
logs/consumer_dead_letter.log — the consumer never crashes on bad input.

Usage:
    python -m kafka.consumer

Environment variables:
    KAFKA_BOOTSTRAP           Kafka broker                  (default: localhost:9092)
    KAFKA_TOPIC_FEATURES      Input topic                   (default: raw-features)
    KAFKA_TOPIC_RESULTS       Output topic                  (default: inference-results)
    KAFKA_TOPIC_METRICS       Metrics topic                 (default: pipeline-metrics)
    KAFKA_CONSUMER_GROUP      Consumer group ID             (default: aegis-consumer)
    KAFKA_AUTO_OFFSET_RESET   Where to start if no offset   (default: earliest)
    INFER_URL                 FastAPI infer endpoint        (default: http://localhost:8000/infer)
    INFER_TIMEOUT             Request timeout seconds       (default: 10)
    DEAD_LETTER_LOG           Dead-letter log path          (default: logs/consumer_dead_letter.log)
    METRICS_INTERVAL          Seconds between metrics msgs  (default: 2)
"""

import os
import sys
import time
import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path

import requests
from confluent_kafka import Consumer, Producer, KafkaException, KafkaError
from confluent_kafka.admin import AdminClient

# Path fix — allow running as  python kafka/consumer.py  from repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from features.schema import from_json, from_dict, FeatureRow

# Logging
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
Path("logs").mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("logs/consumer.log", mode="a"),
    ],
)
logger = logging.getLogger("kafka.consumer")

# Dead-letter logger — separate file, never mixed into main log
DEAD_LETTER_LOG = os.getenv("DEAD_LETTER_LOG", "logs/consumer_dead_letter.log")
dead_letter = logging.getLogger("dead_letter.consumer")
dead_letter.setLevel(logging.ERROR)
dead_letter.addHandler(logging.FileHandler(DEAD_LETTER_LOG, mode="a"))
dead_letter.propagate = False

# Config
KAFKA_BOOTSTRAP         = os.getenv("KAFKA_BOOTSTRAP",         "localhost:9092")
KAFKA_TOPIC_FEATURES    = os.getenv("KAFKA_TOPIC_FEATURES",    "raw-features")
KAFKA_TOPIC_RESULTS     = os.getenv("KAFKA_TOPIC_RESULTS",     "inference-results")
KAFKA_TOPIC_METRICS     = os.getenv("KAFKA_TOPIC_METRICS",     "pipeline-metrics")
KAFKA_CONSUMER_GROUP    = os.getenv("KAFKA_CONSUMER_GROUP",    "aegis-consumer")
KAFKA_AUTO_OFFSET_RESET = os.getenv("KAFKA_AUTO_OFFSET_RESET", "earliest")
INFER_URL               = os.getenv("INFER_URL",               "http://localhost:8000/infer")
INFER_TIMEOUT           = int(os.getenv("INFER_TIMEOUT",       "10"))
METRICS_INTERVAL        = float(os.getenv("METRICS_INTERVAL",  "2"))


# Thread-safe rolling stats for metrics messages
class _RollingStats:
    """Accumulates per-window stats reset after each metrics publish."""

    def __init__(self):
        self._lock = threading.Lock()
        self._reset()

    def _reset(self):
        self.flow_count     = 0      # messages processed in this window
        self.total_bytes    = 0      # raw message bytes in this window
        self.latency_sum    = 0.0    # sum of pipeline_latency_ms values
        self.latency_count  = 0      # number of latency samples
        self.latency_last   = 0.0    # most recent latency measurement
        self.window_start   = time.monotonic()

    def record(self, msg_bytes: int, latency_ms: float):
        with self._lock:
            self.flow_count    += 1
            self.total_bytes   += msg_bytes
            self.latency_sum   += latency_ms
            self.latency_count += 1
            self.latency_last   = latency_ms

    def snapshot(self) -> dict:
        """Return a snapshot and reset counters."""
        with self._lock:
            elapsed = max(time.monotonic() - self.window_start, 0.001)
            snap = {
                "flows_per_sec":      round(self.flow_count / elapsed, 2),
                "bytes_per_sec":      round(self.total_bytes / elapsed, 2),
                "latency_ms_mean":    round(self.latency_sum / max(self.latency_count, 1), 2),
                "latency_ms_last":    round(self.latency_last, 2),
                "window_flows":       self.flow_count,
            }
            self._reset()
            return snap


_stats = _RollingStats()


# Kafka queue depth — queries the broker for consumer group lag
def _get_queue_depth(admin: AdminClient) -> int:
    """
    Returns the current lag (unconsumed messages) on the raw-features topic
    for our consumer group. Returns -1 if the query fails.
    """
    try:
        # list_consumer_group_offsets is available in confluent-kafka >= 1.9
        from confluent_kafka import TopicPartition
        result = admin.list_consumer_group_offsets([
            (KAFKA_CONSUMER_GROUP, [TopicPartition(KAFKA_TOPIC_FEATURES, 0)])
        ])
        # result is a future — resolve it
        for group_id, future in result.items():
            offsets = future.result()
            for tp, offset_info in offsets.items():
                committed = offset_info.offset
                # Get the high watermark (latest offset on broker)
                watermarks = admin.list_offsets(
                    {tp: "latest"},  # type: ignore
                )
                for _, wm_future in watermarks.items():
                    high = wm_future.result().offset
                    return max(0, high - committed)
    except Exception as e:
        logger.debug("Queue depth query failed (non-fatal): %s", e)
    return -1


# Deserialise — returns FeatureRow or None on failure
def _deserialise(raw_value: bytes, raw_key: bytes | None, offset: int) -> FeatureRow | None:
    ts = datetime.now(timezone.utc).isoformat()
    try:
        text = raw_value.decode("utf-8")
    except UnicodeDecodeError as e:
        dead_letter.error(
            "%s | error=unicode_decode | offset=%d | key=%r | detail=%s",
            ts, offset, raw_key, str(e),
        )
        return None

    try:
        d = json.loads(text)
    except json.JSONDecodeError as e:
        dead_letter.error(
            "%s | error=json_decode | offset=%d | key=%r | detail=%s | raw=%r",
            ts, offset, raw_key, str(e), text[:200],
        )
        return None

    try:
        return from_dict(d)
    except (TypeError, KeyError, ValueError) as e:
        dead_letter.error(
            "%s | error=schema_mismatch | offset=%d | key=%r | detail=%s | parsed=%r",
            ts, offset, raw_key, str(e), d,
        )
        return None


# Call FastAPI /infer
def _call_infer(row: FeatureRow, arrival_ts: float) -> tuple[dict | None, float]:
    """
    POST feature row to /infer.
    Returns (result_dict, pipeline_latency_ms).
    result_dict is None on failure.
    """
    payload = {
        # Send everything the model needs — ID columns included so FastAPI
        # can write a complete alert to Elasticsearch
        "flow_id":              row.flow_id,
        "ts":                   row.ts,
        "src_ip":               row.src_ip,
        "dst_ip":               row.dst_ip,
        "src_port":             row.src_port,
        "dst_port":             row.dst_port,
        "protocol":             row.protocol,
        "duration":             row.duration,
        "packets_per_sec":      row.packets_per_sec,
        "bytes_per_sec":        row.bytes_per_sec,
        "outbound_inbound_ratio": row.outbound_inbound_ratio,
        "orig_bytes":           row.orig_bytes,
        "resp_bytes":           row.resp_bytes,
        "orig_pkts":            row.orig_pkts,
        "resp_pkts":            row.resp_pkts,
        "fan_out":              row.fan_out,
        "fan_in":               row.fan_in,
        "unique_dst_ips":       row.unique_dst_ips,
        "unique_dst_ports":     row.unique_dst_ports,
        "iat_mean":             row.iat_mean,
        "iat_std":              row.iat_std,
        "iat_min":              row.iat_min,
        "iat_max":              row.iat_max,
        "connection_frequency": row.connection_frequency,
        "src_ip_entropy":       row.src_ip_entropy,
        "periodicity_score":    row.periodicity_score,
        "dns_query_entropy":    row.dns_query_entropy,
        "domain_length_mean":   row.domain_length_mean,
        "domain_length_max":    row.domain_length_max,
        "subdomain_count":      row.subdomain_count,
        "dns_record_type_a_ratio":   row.dns_record_type_a_ratio,
        "dns_record_type_txt_ratio": row.dns_record_type_txt_ratio,
        "dns_query_count":      row.dns_query_count,
        "ja3_hash":             row.ja3_hash,
        "ja3s_hash":            row.ja3s_hash,
        "tls_version":          row.tls_version,
        "cipher_suite_enc":     row.cipher_suite_enc,
        "is_tls":               row.is_tls,
        "ja4_hash":             row.ja4_hash,
        "is_quic":              row.is_quic,
        "quic_0rtt":            row.quic_0rtt,
        "quic_pkt_size_mean":   row.quic_pkt_size_mean,
        "quic_pkt_size_std":    row.quic_pkt_size_std,
    }

    try:
        response = requests.post(
            INFER_URL,
            json=payload,
            timeout=INFER_TIMEOUT,
        )
        response_ts = time.monotonic()
        latency_ms  = (response_ts - arrival_ts) * 1000

        if response.status_code == 200:
            return response.json(), latency_ms
        else:
            logger.error(
                "/infer returned HTTP %d for flow_id=%s — body: %s",
                response.status_code, row.flow_id, response.text[:200],
            )
            return None, latency_ms

    except requests.exceptions.ConnectionError:
        latency_ms = (time.monotonic() - arrival_ts) * 1000
        logger.error("Cannot reach FastAPI at %s — is the API running?", INFER_URL)
        return None, latency_ms

    except requests.exceptions.Timeout:
        latency_ms = (time.monotonic() - arrival_ts) * 1000
        logger.error(
            "/infer timed out after %ds for flow_id=%s",
            INFER_TIMEOUT, row.flow_id,
        )
        return None, latency_ms

    except Exception as e:
        latency_ms = (time.monotonic() - arrival_ts) * 1000
        logger.exception("Unexpected error calling /infer for flow_id=%s: %s", row.flow_id, e)
        return None, latency_ms


# Kafka producer (for inference-results and pipeline-metrics)
def _build_producer() -> Producer:
    return Producer({
        "bootstrap.servers":      KAFKA_BOOTSTRAP,
        "acks":                   "1",
        "retries":                3,
        "retry.backoff.ms":       200,
        "compression.type":       "lz4",
        "socket.keepalive.enable": True,
    })


def _delivery_cb(err, msg):
    if err:
        logger.error(
            "Publish failed — topic: %s  error: %s",
            msg.topic(), err,
        )


def _publish(producer: Producer, topic: str, payload: dict, key: str | None = None):
    """Serialise payload and publish to topic. Logs on failure, never raises."""
    try:
        value = json.dumps(payload, default=str).encode("utf-8")
        producer.produce(
            topic=topic,
            key=key.encode("utf-8") if key else None,
            value=value,
            on_delivery=_delivery_cb,
        )
        producer.poll(0)
    except BufferError:
        producer.flush(timeout=5.0)
        try:
            producer.produce(topic=topic, value=value, on_delivery=_delivery_cb)
        except KafkaException as e:
            logger.error("Failed to publish to %s after flush: %s", topic, e)
    except KafkaException as e:
        logger.error("Failed to publish to %s: %s", topic, e)


# Metrics publisher — runs in a background thread every METRICS_INTERVAL secs
def _metrics_loop(
    producer: Producer,
    admin: AdminClient,
    stop_event: threading.Event,
):
    logger.info("Metrics publisher started (interval: %.1fs)", METRICS_INTERVAL)
    while not stop_event.is_set():
        time.sleep(METRICS_INTERVAL)
        snap        = _stats.snapshot()
        queue_depth = _get_queue_depth(admin)

        metrics_msg = {
            "ts":                   datetime.now(timezone.utc).isoformat(),
            "flows_per_sec":        snap["flows_per_sec"],
            "bytes_per_sec":        snap["bytes_per_sec"],
            "kafka_queue_depth":    queue_depth,
            "pipeline_latency_ms":  snap["latency_ms_last"],
            "latency_ms_mean":      snap["latency_ms_mean"],
            "window_flows":         snap["window_flows"],
        }

        _publish(producer, KAFKA_TOPIC_METRICS, metrics_msg)
        logger.debug("Metrics published: %s", metrics_msg)



# Main consumer loop
def run():
    logger.info("=" * 60)
    logger.info("Aegis — Kafka Consumer starting")
    logger.info("  Bootstrap    : %s", KAFKA_BOOTSTRAP)
    logger.info("  Input topic  : %s", KAFKA_TOPIC_FEATURES)
    logger.info("  Results topic: %s", KAFKA_TOPIC_RESULTS)
    logger.info("  Metrics topic: %s", KAFKA_TOPIC_METRICS)
    logger.info("  Consumer group: %s", KAFKA_CONSUMER_GROUP)
    logger.info("  Infer URL    : %s", INFER_URL)
    logger.info("  Infer timeout: %ds", INFER_TIMEOUT)
    logger.info("=" * 60)

    # Build Kafka consumer
    consumer = Consumer({
        "bootstrap.servers":        KAFKA_BOOTSTRAP,
        "group.id":                 KAFKA_CONSUMER_GROUP,
        "auto.offset.reset":        KAFKA_AUTO_OFFSET_RESET,
        "enable.auto.commit":       False,   # manual commit after processing
        "max.poll.interval.ms":     60000,   # 60s — enough for slow /infer calls
        "session.timeout.ms":       30000,
        "heartbeat.interval.ms":    10000,
    })
    consumer.subscribe([KAFKA_TOPIC_FEATURES])

    # Build producer (for results + metrics output)
    producer = _build_producer()

    # Build admin client (for queue depth queries)
    admin = AdminClient({"bootstrap.servers": KAFKA_BOOTSTRAP})

    # Start metrics background thread
    stop_event = threading.Event()
    metrics_thread = threading.Thread(
        target=_metrics_loop,
        args=(producer, admin, stop_event),
        daemon=True,
        name="metrics-publisher",
    )
    metrics_thread.start()

    logger.info("Consumer running — waiting for messages on '%s'...", KAFKA_TOPIC_FEATURES)

    processed = 0
    errors    = 0

    try:
        while True:
            # poll() blocks up to 1s waiting for a message
            msg = consumer.poll(timeout=1.0)

            if msg is None:
                # No message in this poll window — normal, keep going
                continue

            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    # Reached end of partition — not an error, just no new messages
                    logger.debug(
                        "Reached end of partition %d at offset %d",
                        msg.partition(), msg.offset(),
                    )
                else:
                    logger.error("Consumer error: %s", msg.error())
                    errors += 1
                continue

            # Step 1 — record arrival timestamp immediately
            arrival_ts = time.monotonic()
            offset     = msg.offset()

            logger.debug(
                "Received message — partition: %d  offset: %d  size: %d bytes",
                msg.partition(), offset, len(msg.value()),
            )

            # Step 2 — deserialise
            row = _deserialise(msg.value(), msg.key(), offset)
            if row is None:
                # Dead-lettered — commit offset so we don't reprocess forever
                consumer.commit(message=msg, asynchronous=False)
                errors += 1
                continue

            # Step 3 + 4 — POST to /infer, get result + latency
            infer_result, latency_ms = _call_infer(row, arrival_ts)

            if infer_result is None:
                # /infer failed — don't commit so we can retry on restart
                # (unless this is a persistent bad message, in which case
                # increase INFER_TIMEOUT or check the API)
                logger.warning(
                    "Skipping commit for offset %d (flow_id=%s) due to infer failure",
                    offset, row.flow_id,
                )
                # Still record stats so metrics aren't blank
                _stats.record(len(msg.value()), latency_ms)
                continue

            logger.debug(
                "flow_id=%s  threat_class=%s  confidence=%.3f  latency=%.1fms",
                row.flow_id,
                infer_result.get("threat_class"),
                infer_result.get("confidence", 0),
                latency_ms,
            )

            # Step 5 — publish to inference-results
            result_msg = {
                "flow_id":       row.flow_id,
                "ts":            row.ts,
                "src_ip":        row.src_ip,
                "dst_ip":        row.dst_ip,
                "src_port":      row.src_port,
                "dst_port":      row.dst_port,
                "protocol":      row.protocol,
                "threat_class":  infer_result.get("threat_class"),
                "confidence":    infer_result.get("confidence"),
                "anomaly_score": infer_result.get("anomaly_score"),
                "evidence":      infer_result.get("evidence", []),
                "latency_ms":    round(latency_ms, 2),
                "consumer_ts":   datetime.now(timezone.utc).isoformat(),
            }
            _publish(
                producer,
                KAFKA_TOPIC_RESULTS,
                result_msg,
                key=row.src_ip,   # partition by src_ip, consistent with producer
            )

            # Step 6 — update rolling stats (metrics thread reads these)
            _stats.record(len(msg.value()), latency_ms)

            # Commit offset — only after successful processing
            
            consumer.commit(message=msg, asynchronous=False)
            processed += 1

            if processed % 100 == 0:
                logger.info(
                    "Progress — processed: %d messages | errors: %d | last latency: %.1fms",
                    processed, errors, latency_ms,
                )

    except KeyboardInterrupt:
        logger.info("Shutting down consumer...")
        stop_event.set()

    finally:
        consumer.close()
        logger.info("Flushing producer...")
        producer.flush(timeout=10.0)
        logger.info(
            "Consumer stopped — total processed: %d | total errors: %d",
            processed, errors,
        )

if __name__ == "__main__":
    run()