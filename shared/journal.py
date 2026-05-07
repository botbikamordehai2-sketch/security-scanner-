"""
Execution Journal — A7.7
Append-only JSON log of every agent execution.
Used for debugging, cost tracking, RLHF, and audit trails.
"""

import json
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class JournalEntry:
    agent: str
    task: str
    provider: str
    decision: str           # success | failure | circuit_open | fallback_success | fallback_stub
    retries: int
    duration_s: float
    cost: float
    tools_used: list
    error: Optional[str] = None
    confidence: Optional[float] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


class ExecutionJournal:
    """
    Thread-safe append-only journal.
    Writes one JSON object per line to journal.jsonl.
    Falls back to in-memory if the file can't be written (e.g. read-only FS on Fly.io).
    """

    def __init__(self, path: Optional[Path] = None):
        self._path = path or Path("/tmp/signalforge_journal.jsonl")
        self._lock = threading.Lock()
        self._entries: list[JournalEntry] = []
        self._file_ok: Optional[bool] = None

    def _can_write(self) -> bool:
        if self._file_ok is not None:
            return self._file_ok
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.touch(exist_ok=True)
            self._file_ok = True
        except OSError:
            self._file_ok = False
        return self._file_ok

    def record(self, entry: JournalEntry) -> None:
        with self._lock:
            self._entries.append(entry)
            if self._can_write():
                try:
                    with self._path.open("a", encoding="utf-8") as f:
                        f.write(json.dumps(entry.to_dict()) + "\n")
                except OSError:
                    pass  # in-memory fallback already captured it

    def recent(self, n: int = 50) -> list[dict]:
        with self._lock:
            return [e.to_dict() for e in self._entries[-n:]]

    def stats(self) -> dict:
        with self._lock:
            if not self._entries:
                return {"total": 0}
            successes = sum(1 for e in self._entries if e.decision == "success")
            failures  = sum(1 for e in self._entries if e.decision == "failure")
            total_cost = sum(e.cost for e in self._entries)
            avg_duration = sum(e.duration_s for e in self._entries) / len(self._entries)
            providers: dict[str, int] = {}
            for e in self._entries:
                providers[e.provider] = providers.get(e.provider, 0) + 1
            return {
                "total": len(self._entries),
                "successes": successes,
                "failures": failures,
                "fallbacks": len(self._entries) - successes - failures,
                "total_cost_usd": round(total_cost, 6),
                "avg_duration_s": round(avg_duration, 3),
                "providers": providers,
            }

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            if self._can_write():
                try:
                    self._path.write_text("", encoding="utf-8")
                except OSError:
                    pass
