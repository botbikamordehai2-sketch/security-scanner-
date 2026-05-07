"""
Unified Execution Wrapper — A7.1
Every agent call goes through here: retry, timeout, fallback, circuit breaker, journaling.
"""

import time
import threading
from typing import Any, Callable, Optional

from shared.circuit_breaker import get_breaker, CircuitOpenError
from shared.journal import ExecutionJournal, JournalEntry

_journal = ExecutionJournal()
_lock = threading.Lock()

FALLBACK_CHAIN: dict[str, list[str]] = {
    "deepseek": ["claude", "stub"],
    "claude":   ["deepseek", "stub"],
    "gcp":      ["stub"],
    "aws":      ["stub"],
}


def execute_with_resilience(
    provider: str,
    task: str,
    fn: Callable[[], Any],
    *,
    timeout: float = 30.0,
    retries: int = 2,
    fallback_fn: Optional[Callable[[str], Any]] = None,
    circuit_breaker: bool = True,
    agent: str = "unknown",
    tools_used: Optional[list[str]] = None,
    cost_estimate: float = 0.0,
) -> Any:
    """
    Execute fn() with:
    - circuit breaker guard (optional)
    - retry loop with exponential backoff
    - per-attempt timeout via threading
    - fallback chain on exhausted retries
    - journal entry on every outcome

    Returns the result of fn() or fallback_fn(provider).
    Raises RuntimeError if all attempts and fallbacks fail.
    """
    start = time.monotonic()
    last_error: Optional[Exception] = None

    for attempt in range(1, retries + 2):  # retries+1 total attempts
        try:
            if circuit_breaker:
                breaker = get_breaker(f"{provider}-{task}")
            else:
                from contextlib import nullcontext
                breaker = nullcontext()

            result_holder: list = []
            exc_holder:    list = []

            def _run():
                try:
                    result_holder.append(fn())
                except Exception as e:
                    exc_holder.append(e)

            t = threading.Thread(target=_run, daemon=True)

            with breaker:
                t.start()
                t.join(timeout=timeout)

            if t.is_alive():
                raise TimeoutError(f"[{provider}/{task}] timed out after {timeout}s")

            if exc_holder:
                raise exc_holder[0]

            result = result_holder[0]
            duration = time.monotonic() - start

            _journal.record(JournalEntry(
                agent=agent,
                task=task,
                provider=provider,
                decision="success",
                retries=attempt - 1,
                duration_s=round(duration, 3),
                cost=cost_estimate,
                tools_used=tools_used or [],
            ))

            return result

        except CircuitOpenError as e:
            last_error = e
            _journal.record(JournalEntry(
                agent=agent,
                task=task,
                provider=provider,
                decision="circuit_open",
                retries=attempt - 1,
                duration_s=round(time.monotonic() - start, 3),
                cost=0.0,
                tools_used=[],
                error=str(e),
            ))
            break  # circuit open — skip retries, go to fallback immediately

        except Exception as e:
            last_error = e
            backoff = 2 ** (attempt - 1)
            if attempt <= retries:
                time.sleep(backoff)

    # ── Fallback ──
    fallbacks = FALLBACK_CHAIN.get(provider, ["stub"])
    for fb_provider in fallbacks:
        if fb_provider == "stub":
            _journal.record(JournalEntry(
                agent=agent,
                task=task,
                provider="stub",
                decision="fallback_stub",
                retries=retries,
                duration_s=round(time.monotonic() - start, 3),
                cost=0.0,
                tools_used=[],
                error=str(last_error),
            ))
            return {"status": "degraded", "provider": "stub", "task": task, "error": str(last_error)}

        if fallback_fn:
            try:
                result = fallback_fn(fb_provider)
                _journal.record(JournalEntry(
                    agent=agent,
                    task=task,
                    provider=fb_provider,
                    decision="fallback_success",
                    retries=retries,
                    duration_s=round(time.monotonic() - start, 3),
                    cost=cost_estimate * 0.5,
                    tools_used=tools_used or [],
                ))
                return result
            except Exception:
                continue

    raise RuntimeError(f"All attempts and fallbacks failed for {provider}/{task}: {last_error}")
