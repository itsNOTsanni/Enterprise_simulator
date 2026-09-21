"""
shared/storage/event_writer.py

The "saver" -- writes simulator events to persistent storage, so they
survive after the terminal window that generated them is closed.

Two separate files are maintained:

  1. THE MAIN EVENT LOG (default: storage/events.jsonl)
     The plain, unlabeled event exactly as CommonEvent produced it.
     This is the file a future Coordinator Agent will read. It NEVER
     contains an [ATTACK]/[NORMAL] tag or any other hint about
     whether an event was an attack -- only the raw event data, one
     JSON object per line (this format is called JSONL).

  2. THE GROUND TRUTH LOG (default: storage/ground_truth.jsonl)
     A separate, much smaller file that records, for ATTACK events
     ONLY, which event_id was actually an attack and which attack_type
     produced it. This exists purely so a person can grade a future
     Coordinator Agent afterward ("did it correctly flag this one?").
     The Coordinator Agent itself must NEVER read this file -- doing
     so would hand it the answer instead of requiring it to detect
     anything.

Both files are append-only: nothing is ever edited or removed, only
added to, which also sets up cleanly for hash-chaining/signing later.
"""

import json
import threading
from pathlib import Path
from typing import Optional

from shared.schemas.event_schema import CommonEvent


# Project root:
# Enterprise_simulator/
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

STORAGE_DIR = PROJECT_ROOT / "storage"
DEFAULT_EVENT_LOG_PATH = STORAGE_DIR / "events.jsonl"
DEFAULT_GROUND_TRUTH_PATH = STORAGE_DIR / "ground_truth.jsonl"

# Multiple simulators run in their own background threads and may try
# to write at the same time; this keeps each line write atomic so
# lines never interleave or get corrupted.
_write_lock = threading.Lock()


def _event_to_dict(event: CommonEvent) -> dict:
    """Convert a CommonEvent to a plain dict, working on both pydantic v1 and v2."""
    if hasattr(event, "model_dump"):
        return event.model_dump()
    return event.dict()


def _append_jsonl(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, default=str)
    with _write_lock:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def write_event(
    event: CommonEvent,
    is_attack: bool,
    attack_type: Optional[str] = None,
    event_log_path: Path = DEFAULT_EVENT_LOG_PATH,
    ground_truth_path: Path = DEFAULT_GROUND_TRUTH_PATH,
) -> None:
    """
    Persist one event.

    Always appends the RAW event -- exactly what CommonEvent produced,
    no attack/normal tag of any kind -- to the main event log.

    If is_attack is True, ALSO appends a small ground-truth record
    (event_id, attack_type, asset_id, timestamp) to the separate
    ground truth log. Normal events get no ground-truth entry at all,
    so that log only ever contains real attacks.

    Usage:
        write_event(event, is_attack=False)                        # normal
        write_event(event, is_attack=True, attack_type="ransomware") # attack
    """
    _append_jsonl(event_log_path, _event_to_dict(event))

    if is_attack:
        _append_jsonl(
            ground_truth_path,
            {
                "event_id": event.event_id,
                "attack_type": attack_type,
                "asset_id": event.source.asset_id,
                "timestamp": event.timestamp,
            },
        )


def read_events(path: Path = DEFAULT_EVENT_LOG_PATH):
    """Yield each raw event dict from the main event log, in order."""
    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def read_ground_truth(path: Path = DEFAULT_GROUND_TRUTH_PATH):
    """Yield each ground-truth record from the ground truth log, in order."""
    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)