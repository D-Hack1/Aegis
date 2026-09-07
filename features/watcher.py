"""
Watches the Zeek log output directory for new or completed .log files.
When a file lands, triggers Gowri's pipeline.py on it and appends
the resulting FeatureRows to an in-memory staging queue.

The Kafka producer reads from this queue and publishes to raw-features.

Usage:
    python -m features.watcher

    Or with custom paths:
    python -m features.watcher --watch-dir /zeek/logs --output-dir data/features

Environment variables (can also be set in .env):
    ZEEK_LOG_DIR     Directory to watch  (default: ./zeek/logs)
    FEATURES_DIR     Where to write Parquet output  (default: ./data/features)
    PIPELINE_SCRIPT  Path to pipeline.py  (default: ./features/pipeline.py)
    STAGING_MAXSIZE  Max rows in staging queue before blocking  (default: 10000)
"""

import os
import sys
import time
import queue
import logging
import argparse
import subprocess
import threading
from pathlib import Path
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent

# ---------------------------------------------------------------------------
# Logging setup — log to both stdout and a file
# ---------------------------------------------------------------------------
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    datefmt=DATE_FORMAT,
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("watcher.log", mode="a"),
    ],
)
logger = logging.getLogger("watcher")

# ---------------------------------------------------------------------------
# Config — read from env with sensible defaults
# ---------------------------------------------------------------------------
ZEEK_LOG_DIR    = os.getenv("ZEEK_LOG_DIR",    "./zeek/logs")
FEATURES_DIR    = os.getenv("FEATURES_DIR",    "./data/features")
PIPELINE_SCRIPT = os.getenv("PIPELINE_SCRIPT", "./features/pipeline.py")
STAGING_MAXSIZE = int(os.getenv("STAGING_MAXSIZE", "10000"))

# Only process these Zeek log types — ignore rotated/compressed files
WATCHED_EXTENSIONS = {".log"}

# Zeek rotates logs by renaming them — we only want to process a file
# once it stops being written to. These are the stable log names we care about.
WATCHED_LOG_NAMES = {
    "conn.log",
    "dns.log",
    "ssl.log",
    "http.log",
    "quic.log",
}

# How long a file must be unchanged before we consider it complete (seconds).
# Zeek flushes periodically, so we wait for a quiet period before triggering.
FILE_SETTLE_SECONDS = 3.0

# ---------------------------------------------------------------------------
# Staging queue — FeatureRow dicts land here, Kafka producer reads from here
# ---------------------------------------------------------------------------
staging_queue: queue.Queue = queue.Queue(maxsize=STAGING_MAXSIZE)


# ---------------------------------------------------------------------------
# File settle tracker
# Zeek writes log files incrementally. We don't want to trigger pipeline.py
# on every write event — we wait until the file hasn't changed for
# FILE_SETTLE_SECONDS, then process it.
# ---------------------------------------------------------------------------
class SettleTracker:
    """
    Tracks the last-modified time of files that have been seen.
    A background thread polls and triggers pipeline once a file settles.
    """

    def __init__(self, callback, settle_seconds: float = FILE_SETTLE_SECONDS):
        self._callback = callback
        self._settle = settle_seconds
        self._lock = threading.Lock()
        # path -> last event timestamp
        self._pending: dict[str, float] = {}
        self._processed: set[str] = set()
        self._thread = threading.Thread(target=self._poll, daemon=True, name="settle-poller")

    def start(self):
        self._thread.start()
        logger.info("Settle tracker started (settle window: %.1fs)", self._settle)

    def touch(self, path: str):
        """Record that this file was just written to."""
        with self._lock:
            self._pending[path] = time.monotonic()

    def _poll(self):
        """Check every 0.5s whether any pending file has settled."""
        while True:
            time.sleep(0.5)
            now = time.monotonic()
            with self._lock:
                settled = [
                    p for p, last in self._pending.items()
                    if (now - last) >= self._settle
                ]
                for path in settled:
                    del self._pending[path]

            for path in settled:
                # Skip if we've already processed this exact file+mtime combo
                try:
                    mtime = os.path.getmtime(path)
                except OSError:
                    continue
                key = f"{path}:{mtime}"
                if key in self._processed:
                    continue
                self._processed.add(key)
                self._callback(path)


# ---------------------------------------------------------------------------
# Watchdog event handler
# ---------------------------------------------------------------------------
class ZeekLogHandler(FileSystemEventHandler):
    """
    Listens for file system events in the Zeek log directory.
    Passes relevant .log files to the SettleTracker.
    """

    def __init__(self, tracker: SettleTracker):
        super().__init__()
        self._tracker = tracker

    def _is_relevant(self, path: str) -> bool:
        p = Path(path)
        if p.suffix not in WATCHED_EXTENSIONS:
            return False
        # Accept exact names (conn.log) or timestamped rotations (conn_20250101.log)
        base = p.name
        if base in WATCHED_LOG_NAMES:
            return True
        # Also accept rotation copies like conn.2025-01-01-10-00-00.log
        for name in WATCHED_LOG_NAMES:
            stem = name.replace(".log", "")
            if base.startswith(stem):
                return True
        return False

    def on_created(self, event: FileCreatedEvent):
        if not event.is_directory and self._is_relevant(event.src_path):
            logger.info("New file detected: %s", event.src_path)
            self._tracker.touch(event.src_path)

    def on_modified(self, event: FileModifiedEvent):
        if not event.is_directory and self._is_relevant(event.src_path):
            self._tracker.touch(event.src_path)


# ---------------------------------------------------------------------------
# Pipeline trigger
# ---------------------------------------------------------------------------
def trigger_pipeline(log_path: str):
    """
    Called by SettleTracker once a log file has stopped changing.
    Runs Gowri's pipeline.py as a subprocess, then appends resulting
    FeatureRow dicts to the staging queue.
    """
    log_path = Path(log_path)
    ts = datetime.utcnow().isoformat()

    logger.info(
        "[%s] TRIGGER pipeline.py — file: %s  size: %s bytes",
        ts,
        log_path.name,
        _fmt_size(log_path.stat().st_size) if log_path.exists() else "gone",
    )

    # Derive scenario name from the log file's parent directory name,
    # or fall back to a timestamp if the structure is flat.
    scenario = log_path.parent.name if log_path.parent.name != "logs" else f"live_{int(time.time())}"
    output_dir = Path(FEATURES_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{scenario}.parquet"

    cmd = [
    sys.executable, PIPELINE_SCRIPT,
    "--zeek-dir",      str(log_path.parent),
    "--output-dir",    str(output_dir),
    "--scenario-name", scenario,
]

    logger.info("Running: %s", " ".join(cmd))
    t_start = time.monotonic()

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,  # 2 minute max per file — raise if pipeline is hanging
        )
        elapsed = time.monotonic() - t_start

        if result.returncode == 0:
            logger.info(
                "[%s] pipeline.py completed in %.2fs — output: %s",
                datetime.utcnow().isoformat(),
                elapsed,
                output_path,
            )
            if result.stdout.strip():
                logger.debug("pipeline stdout:\n%s", result.stdout.strip())

            # Load the resulting Parquet and push rows into the staging queue
            _enqueue_parquet(output_path)

        else:
            logger.error(
                "pipeline.py FAILED (exit %d) for %s in %.2fs\nstderr:\n%s",
                result.returncode,
                log_path.name,
                elapsed,
                result.stderr.strip(),
            )

    except subprocess.TimeoutExpired:
        logger.error("pipeline.py TIMED OUT after 120s for %s — skipping", log_path.name)
    except FileNotFoundError:
        logger.error(
            "pipeline.py not found at %s — check PIPELINE_SCRIPT env var",
            PIPELINE_SCRIPT,
        )
    except Exception as e:
        logger.exception("Unexpected error triggering pipeline for %s: %s", log_path.name, e)


def _enqueue_parquet(parquet_path: Path):
    """
    Read a Parquet file produced by pipeline.py and push each row
    as a dict onto the staging queue for the Kafka producer to consume.
    """
    try:
        import pandas as pd
        df = pd.read_parquet(parquet_path)

        if df.empty:
            logger.warning("pipeline.py produced an empty Parquet for %s — nothing enqueued", parquet_path.name)
            return

        rows_added = 0
        rows_dropped = 0

        for _, row in df.iterrows():
            row_dict = row.to_dict()
            try:
                staging_queue.put_nowait(row_dict)
                rows_added += 1
            except queue.Full:
                rows_dropped += 1

        if rows_dropped:
            logger.warning(
                "Staging queue full — dropped %d rows from %s (added %d). "
                "Kafka producer may be too slow.",
                rows_dropped, parquet_path.name, rows_added,
            )
        else:
            logger.info(
                "Enqueued %d rows from %s into staging queue (queue size now: %d)",
                rows_added, parquet_path.name, staging_queue.qsize(),
            )

    except ImportError:
        logger.error("pandas not installed — cannot read Parquet. Run: pip install pandas pyarrow")
    except Exception as e:
        logger.exception("Failed to enqueue rows from %s: %s", parquet_path, e)


# ---------------------------------------------------------------------------
# Queue consumer helper — used by Kafka producer (kafka/producer.py)
# ---------------------------------------------------------------------------
def get_staging_queue() -> queue.Queue:
    """
    Returns the shared staging queue.
    Import this in kafka/producer.py:

        from features.watcher import get_staging_queue
        q = get_staging_queue()
        row = q.get(timeout=1.0)
    """
    return staging_queue


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------
def _fmt_size(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ---------------------------------------------------------------------------
# Process existing files on startup
# ---------------------------------------------------------------------------
def process_existing_logs(watch_dir: Path, tracker: SettleTracker):
    """
    On startup, check if there are already .log files sitting in the
    watch directory (e.g. from a previous Zeek run). Queue them immediately.
    """
    found = []
    for ext in WATCHED_EXTENSIONS:
        found.extend(watch_dir.rglob(f"*{ext}"))

    relevant = [f for f in found if f.name in WATCHED_LOG_NAMES]

    if not relevant:
        logger.info("No existing log files found in %s — waiting for new ones", watch_dir)
        return

    logger.info("Found %d existing log file(s) on startup — processing:", len(relevant))
    for f in relevant:
        logger.info("  → %s", f)
        tracker.touch(str(f))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Zeek log watcher — triggers feature pipeline")
    parser.add_argument("--watch-dir",  default=ZEEK_LOG_DIR,    help="Directory to watch for Zeek logs")
    parser.add_argument("--output-dir", default=FEATURES_DIR,    help="Where to write Parquet feature files")
    parser.add_argument("--pipeline",   default=PIPELINE_SCRIPT, help="Path to pipeline.py")
    parser.add_argument("--settle",     default=FILE_SETTLE_SECONDS, type=float, help="Seconds to wait after last write before triggering")
    args = parser.parse_args()

    watch_dir = Path(args.watch_dir)
    watch_dir.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 60)
    logger.info("Aegis — Zeek Log Watcher starting")
    logger.info("  Watch dir : %s", watch_dir.resolve())
    logger.info("  Output dir: %s", Path(args.output_dir).resolve())
    logger.info("  Pipeline  : %s", Path(args.pipeline).resolve())
    logger.info("  Settle    : %.1fs", args.settle)
    logger.info("  Queue max : %d rows", STAGING_MAXSIZE)
    logger.info("=" * 60)

    # Update globals if overridden by CLI args
    global FEATURES_DIR, PIPELINE_SCRIPT
    FEATURES_DIR    = args.output_dir
    PIPELINE_SCRIPT = args.pipeline

    # Set up the settle tracker with our pipeline trigger callback
    tracker = SettleTracker(callback=trigger_pipeline, settle_seconds=args.settle)
    tracker.start()

    # Process any files already sitting in the directory
    process_existing_logs(watch_dir, tracker)

    # Set up watchdog observer
    handler  = ZeekLogHandler(tracker)
    observer = Observer()
    observer.schedule(handler, str(watch_dir), recursive=True)
    observer.start()

    logger.info("Watching %s — press Ctrl+C to stop", watch_dir.resolve())

    try:
        while True:
            time.sleep(1)
            # Heartbeat log every 60s so we know the watcher is alive
            if int(time.time()) % 60 == 0:
                logger.info(
                    "Heartbeat — staging queue: %d rows | watcher alive",
                    staging_queue.qsize(),
                )
    except KeyboardInterrupt:
        logger.info("Shutting down watcher...")
        observer.stop()

    observer.join()
    logger.info("Watcher stopped cleanly.")


if __name__ == "__main__":
    main()