"""
Reads FeatureRow dicts from the staging queue (populated by features/watcher.py)
and publishes them to the Kafka `raw-features` topic.

Batching strategy:
  - Collect rows for up to 100ms
  - Publish whatever has accumulated when the window expires
  - Never wait for a full batch — latency over throughput

Usage:
    python -m kafka.producer

Environment variables:
    KAFKA_BOOTSTRAP      Kafka broker address       (default: localhost:9092)
    KAFKA_TOPIC_FEATURES Topic to publish to        (default: raw-features)
    KAFKA_BATCH_WINDOW   Batch window in seconds    (default: 0.1  → 100ms)
    KAFKA_BATCH_MAX      Max rows per batch         (default: 500)
    DEAD_LETTER_LOG      Path to dead-letter log    (default: logs/producer_dead_letter.log)
"""

import os
import sys
import time
import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path

from confluent_kafka import Producer, KafkaException

# Path fix — allow running as  python kafka/producer.py  from repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from features.watcher import get_staging_queue
from features.schema import to_json

# Logging
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("logs/producer.log", mode="a"),
    ],
)
logger = logging.getLogger("kafka.producer")

# Config
KAFKA_BOOTSTRAP      = os.getenv("KAFKA_BOOTSTRAP",      "localhost:9092")
KAFKA_TOPIC_FEATURES = os.getenv("KAFKA_TOPIC_FEATURES", "raw-features")
KAFKA_BATCH_WINDOW   = float(os.getenv("KAFKA_BATCH_WINDOW", "0.1"))   # 100ms
KAFKA_BATCH_MAX      = int(os.getenv("KAFKA_BATCH_MAX",   "500"))
DEAD_LETTER_LOG      = os.getenv("DEAD_LETTER_LOG",       "logs/producer_dead_letter.log")

# Dead-letter logger — malformed rows that can't be serialised go here
Path(DEAD_LETTER_LOG).parent.mkdir(parents=True, exist_ok=True)
dead_letter = logging.getLogger("dead_letter")
dead_letter.setLevel(logging.ERROR)
dead_letter.addHandler(logging.FileHandler(DEAD_LETTER_LOG, mode="a"))
dead_letter.propagate = False  # don't pollute the main log

# Prometheus-style counters (simple thread-safe ints for the metrics topic)
class _Counter:
    def __init__(self): self._v = 0; self._lock = threading.Lock()
    def inc(self, n=1):
        with self._lock: self._v += n
    def get_and_reset(self):
        with self._lock: v = self._v; self._v = 0; return v

_rows_published   = _Counter()
_rows_dropped     = _Counter()
_batches_sent     = _Counter()
_delivery_errors  = _Counter()


# Delivery callback — called by Kafka for every message after broker ack
def _on_delivery(err, msg):
    if err:
        _delivery_errors.inc()
        logger.error(
            "Delivery FAILED — topic: %s  partition: %d  offset: %d  error: %s",
            msg.topic(), msg.partition(), msg.offset(), err,
        )
    else:
        logger.debug(
            "Delivered — topic: %s  partition: %d  offset: %d",
            msg.topic(), msg.partition(), msg.offset(),
        )


# Serialise a raw dict from the staging queue into a Kafka message value
def _serialise(row: dict) -> bytes | None:
    """
    Attempts to serialise a staging queue row to JSON bytes.
    Returns None and writes to dead-letter log on failure.
    """
    try:
        # If the row already came through schema.to_json it's a plain dict —
        # just json.dumps it. If it's a FeatureRow dataclass somehow, handle that too.
        if isinstance(row, dict):
            return json.dumps(row, default=str).encode("utf-8")
        else:
            # Try calling to_json from schema (handles FeatureRow dataclass)
            return to_json(row).encode("utf-8")
    except (TypeError, ValueError, AttributeError) as e:
        dead_letter.error(
            "%s | serialisation_error=%s | row=%r",
            datetime.now(timezone.utc).isoformat(),
            str(e),
            row,
        )
        _rows_dropped.inc()
        return None


# Kafka message key — partition by src_ip so flows from the same host
# land on the same partition and arrive in order at the consumer
def _key(row: dict) -> bytes | None:
    src = row.get("src_ip")
    if src:
        return src.encode("utf-8")
    return None


# Stats logger — runs in a background thread, prints throughput every 10s
def _stats_loop(stop_event: threading.Event):
    while not stop_event.is_set():
        time.sleep(10)
        published  = _rows_published.get_and_reset()
        dropped    = _rows_dropped.get_and_reset()
        batches    = _batches_sent.get_and_reset()
        d_errors   = _delivery_errors.get_and_reset()
        logger.info(
            "Stats (last 10s) — published: %d rows | dropped: %d | "
            "batches: %d | delivery_errors: %d",
            published, dropped, batches, d_errors,
        )


# Main producer loop
def run():
    Path("logs").mkdir(exist_ok=True)

    logger.info("=" * 60)
    logger.info("Aegis — Kafka Producer starting")
    logger.info("  Bootstrap : %s", KAFKA_BOOTSTRAP)
    logger.info("  Topic     : %s", KAFKA_TOPIC_FEATURES)
    logger.info("  Batch win : %.0fms", KAFKA_BATCH_WINDOW * 1000)
    logger.info("  Batch max : %d rows", KAFKA_BATCH_MAX)
    logger.info("=" * 60)

    # Build producer
    producer = Producer({
        "bootstrap.servers":         KAFKA_BOOTSTRAP,
        "acks":                      "1",          # leader ack only — fast enough for SIH
        "linger.ms":                 0,            # we handle batching ourselves
        "batch.num.messages":        1,            # send immediately when we call produce()
        "queue.buffering.max.ms":    0,
        "retries":                   3,
        "retry.backoff.ms":          200,
        "compression.type":          "lz4",        # lightweight compression
        "socket.keepalive.enable":   True,
    })

    q = get_staging_queue()
    stop_event = threading.Event()

    # Start stats background thread
    stats_thread = threading.Thread(
        target=_stats_loop, args=(stop_event,), daemon=True, name="producer-stats"
    )
    stats_thread.start()

    logger.info("Producer running — waiting for rows from staging queue...")

    try:
        while True:
            batch: list[dict] = []
            window_start = time.monotonic()

            # Collect rows until the 100ms window expires OR batch is full.
            # q.get() with a short timeout lets us check the window deadline
            # without busy-spinning.
            while True:
                elapsed   = time.monotonic() - window_start
                remaining = KAFKA_BATCH_WINDOW - elapsed

                if remaining <= 0 or len(batch) >= KAFKA_BATCH_MAX:
                    break   # window expired or batch full — publish now

                try:
                    row = q.get(timeout=min(remaining, 0.01))
                    batch.append(row)
                    q.task_done()
                except Exception:
                    # queue.Empty — nothing arrived in this slice, keep looping
                    pass

            if not batch:
                # Nothing arrived in this window — poll Kafka to handle
                # delivery callbacks and avoid internal buffer buildup
                producer.poll(0)
                continue

            # Publish batch
            published_this_batch = 0
            for row in batch:
                value = _serialise(row)
                if value is None:
                    continue  # dead-lettered, skip

                key = _key(row)

                try:
                    producer.produce(
                        topic=KAFKA_TOPIC_FEATURES,
                        key=key,
                        value=value,
                        on_delivery=_on_delivery,
                    )
                    published_this_batch += 1
                except BufferError:
                    # Kafka internal queue is full — flush and retry once
                    logger.warning("Kafka internal buffer full — flushing before retry")
                    producer.flush(timeout=5.0)
                    try:
                        producer.produce(
                            topic=KAFKA_TOPIC_FEATURES,
                            key=key,
                            value=value,
                            on_delivery=_on_delivery,
                        )
                        published_this_batch += 1
                    except KafkaException as e:
                        logger.error("Retry failed — dropping row: %s", e)
                        dead_letter.error(
                            "%s | kafka_error=%s | row=%r",
                            datetime.now(timezone.utc).isoformat(), str(e), row,
                        )
                        _rows_dropped.inc()
                except KafkaException as e:
                    logger.error("produce() failed — dropping row: %s", e)
                    _rows_dropped.inc()

            # Poll to trigger delivery callbacks for this batch
            producer.poll(0)

            _rows_published.inc(published_this_batch)
            _batches_sent.inc()

            logger.debug(
                "Batch published — %d rows in %.1fms",
                published_this_batch,
                (time.monotonic() - window_start) * 1000,
            )

    except KeyboardInterrupt:
        logger.info("Shutting down producer...")
        stop_event.set()

    finally:
        logger.info("Flushing remaining messages...")
        remaining = producer.flush(timeout=10.0)
        if remaining:
            logger.warning("%d message(s) could not be flushed — may be lost", remaining)
        else:
            logger.info("All messages flushed cleanly.")
        logger.info("Producer stopped.")



if __name__ == "__main__":
    run()