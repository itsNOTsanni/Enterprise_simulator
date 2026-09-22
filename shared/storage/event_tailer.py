"""
shared/storage/event_tailer.py

A minimal, reusable "tail -f" for the shared JSONL event log.

Monitoring agents need to keep watching storage/events.jsonl as the
simulators append to it, rather than reading it once and exiting.
EventTailer remembers how far into the file it has read (a byte
offset) and, on every poll(), returns only the records appended since
the previous poll.

Behaviour:
  - Only COMPLETE lines are returned. A line a simulator is still in
    the middle of writing is left in the file and picked up on a later
    poll, once its trailing newline exists.
  - If the file shrinks (e.g. someone cleared the log), reading starts
    again from the top.
  - If the file doesn't exist yet, poll() just returns nothing.
  - Lines that aren't valid JSON are skipped and counted in
    `malformed_lines`; they never raise.

This class does NOT deduplicate events or interpret them -- that is
each agent's job. It is read-only and never touches event_writer's
files in any other way.

Usage:
    tailer = EventTailer(DEFAULT_EVENT_LOG_PATH)
    for record in tailer.follow(poll_interval=1.0):
        handle(record)
"""

import json
import logging
import threading
import time
from pathlib import Path
from typing import Iterator, List, Optional

logger = logging.getLogger(__name__)


class EventTailer:

    def __init__(self, path: Path, start_at_end: bool = False):
        self.path = Path(path)
        self.offset = 0
        self.malformed_lines = 0
        if start_at_end and self.path.exists():
            self.offset = self.path.stat().st_size

    def poll(self) -> List[dict]:
        """Return every complete JSON record appended since the last poll."""
        if not self.path.exists():
            return []

        size = self.path.stat().st_size
        if size < self.offset:
            logger.warning("%s shrank (%d < %d bytes); re-reading from start.", self.path, size, self.offset)
            self.offset = 0
        if size == self.offset:
            return []

        # Binary mode so byte offsets stay exact on every OS (text mode
        # on Windows would translate \r\n and break seek positions).
        with open(self.path, "rb") as f:
            f.seek(self.offset)
            chunk = f.read(size - self.offset)

        last_newline = chunk.rfind(b"\n")
        if last_newline == -1:
            return []  # only a partial line so far -- wait for the rest

        complete = chunk[: last_newline + 1]
        self.offset += len(complete)

        records = []
        for raw_line in complete.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                record = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self.malformed_lines += 1
                logger.warning("Skipping malformed line in %s", self.path)
                continue
            if isinstance(record, dict):
                records.append(record)
            else:
                self.malformed_lines += 1
        return records

    def follow(
        self,
        poll_interval: float = 1.0,
        stop_event: Optional[threading.Event] = None,
    ) -> Iterator[dict]:
        """Yield new records forever (until stop_event is set)."""
        while stop_event is None or not stop_event.is_set():
            records = self.poll()
            for record in records:
                yield record
            if not records:
                if stop_event is not None:
                    stop_event.wait(poll_interval)
                else:
                    time.sleep(poll_interval)
