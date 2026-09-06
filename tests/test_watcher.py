import queue
from unittest.mock import MagicMock

import pytest

from features import watcher


def test_staging_queue_is_shared():
    q1 = watcher.get_staging_queue()
    q2 = watcher.get_staging_queue()

    assert q1 is q2


def test_staging_queue_accepts_rows():
    q = watcher.get_staging_queue()

    # Empty the queue first so this test is isolated.
    while not q.empty():
        q.get_nowait()

    test_row = {
        "flow_id": "C123",
        "src_ip": "192.168.1.10",
    }

    q.put(test_row)

    assert q.qsize() == 1

    result = q.get_nowait()

    assert result["flow_id"] == "C123"


def test_non_log_file_is_ignored():
    """
    Replace `YourEventHandler` below with the actual
    event-handler class name from watcher.py.
    """

    handler = watcher.YourEventHandler()

    event = MagicMock()
    event.src_path = "/zeek/logs/test.txt"
    event.is_directory = False

    handler.on_created(event)

    # Verify that no pipeline call / queue insertion occurred.
    # Adapt this depending on your actual implementation.