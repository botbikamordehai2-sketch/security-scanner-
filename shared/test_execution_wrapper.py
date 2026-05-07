"""Unit tests for execution_wrapper.py and journal.py — no cloud credentials needed."""

import sys
import time
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared.journal import ExecutionJournal, JournalEntry
from shared.execution_wrapper import execute_with_resilience


# ── Journal tests ─────────────────────────────────

class TestJournal:
    def setup_method(self):
        self.j = ExecutionJournal(path=Path("/tmp/test_journal.jsonl"))
        self.j.clear()

    def _entry(self, decision="success", provider="deepseek", cost=0.001):
        return JournalEntry(
            agent="test_agent", task="test_task", provider=provider,
            decision=decision, retries=0, duration_s=0.1,
            cost=cost, tools_used=["web_search"],
        )

    def test_record_and_recent(self):
        self.j.record(self._entry())
        entries = self.j.recent(10)
        assert len(entries) == 1
        assert entries[0]["decision"] == "success"

    def test_recent_limit(self):
        for _ in range(10):
            self.j.record(self._entry())
        assert len(self.j.recent(3)) == 3

    def test_stats_empty(self):
        assert self.j.stats()["total"] == 0

    def test_stats_counts(self):
        self.j.record(self._entry("success", cost=0.01))
        self.j.record(self._entry("success", cost=0.02))
        self.j.record(self._entry("failure", cost=0.0))
        s = self.j.stats()
        assert s["total"] == 3
        assert s["successes"] == 2
        assert s["failures"] == 1
        assert round(s["total_cost_usd"], 3) == 0.03

    def test_stats_providers(self):
        self.j.record(self._entry(provider="deepseek"))
        self.j.record(self._entry(provider="claude"))
        self.j.record(self._entry(provider="deepseek"))
        assert self.j.stats()["providers"]["deepseek"] == 2
        assert self.j.stats()["providers"]["claude"] == 1

    def test_clear(self):
        self.j.record(self._entry())
        self.j.clear()
        assert self.j.stats()["total"] == 0

    def test_entry_has_timestamp(self):
        self.j.record(self._entry())
        e = self.j.recent(1)[0]
        assert "timestamp" in e
        assert "T" in e["timestamp"]


# ── Execution Wrapper tests ────────────────────────

class TestExecutionWrapper:
    def test_success_returns_value(self):
        result = execute_with_resilience(
            provider="deepseek", task="test",
            fn=lambda: {"status": "ok"},
            agent="test", circuit_breaker=False,
        )
        assert result == {"status": "ok"}

    def test_retries_on_failure_then_succeeds(self):
        calls = {"n": 0}
        def flaky():
            calls["n"] += 1
            if calls["n"] < 2:
                raise ValueError("transient")
            return "ok"

        result = execute_with_resilience(
            provider="deepseek", task="test",
            fn=flaky, retries=2, agent="test", circuit_breaker=False,
        )
        assert result == "ok"
        assert calls["n"] == 2

    def test_all_retries_exhausted_hits_stub_fallback(self):
        result = execute_with_resilience(
            provider="deepseek", task="test",
            fn=lambda: (_ for _ in ()).throw(RuntimeError("always fails")),
            retries=1, agent="test", circuit_breaker=False,
        )
        assert result["status"] == "degraded"
        assert result["provider"] == "stub"

    def test_fallback_fn_called_on_failure(self):
        def fb(provider):
            return {"status": "fallback", "used": provider}

        result = execute_with_resilience(
            provider="deepseek", task="test",
            fn=lambda: (_ for _ in ()).throw(RuntimeError("fail")),
            fallback_fn=fb, retries=0,
            agent="test", circuit_breaker=False,
        )
        assert result["status"] == "fallback"

    def test_timeout_triggers_stub_fallback(self):
        def slow():
            time.sleep(5)
            return "never"

        result = execute_with_resilience(
            provider="deepseek", task="slow_task",
            fn=slow, timeout=0.1, retries=0,
            agent="test", circuit_breaker=False,
        )
        assert result["status"] == "degraded"

    def test_journal_records_success(self):
        from shared.execution_wrapper import _journal
        _journal.clear()
        execute_with_resilience(
            provider="aws", task="scan",
            fn=lambda: "done",
            agent="sec_agent", circuit_breaker=False,
        )
        recent = _journal.recent(1)
        assert recent[0]["decision"] == "success"
        assert recent[0]["provider"] == "aws"
