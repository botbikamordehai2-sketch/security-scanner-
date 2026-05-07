"""
Circuit Breaker — prevents repeated calls to a failing external API.

States:
  CLOSED   → normal operation, calls pass through
  OPEN     → too many failures, calls blocked immediately
  HALF_OPEN → cooldown passed, one test call allowed

Usage:
    cb = CircuitBreaker("gcp-firewall", failure_threshold=3, recovery_timeout=60)
    with cb:
        result = some_gcp_call()
"""

import time
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Any


class State(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitOpenError(Exception):
    """Raised when a call is blocked by an open circuit."""
    def __init__(self, name: str, retry_after: float):
        self.name = name
        self.retry_after = retry_after
        super().__init__(
            f"Circuit '{name}' is OPEN. Retry after {retry_after:.1f}s."
        )


@dataclass
class CircuitBreaker:
    name: str
    failure_threshold: int = 3       # failures before opening
    recovery_timeout: float = 60.0   # seconds before HALF_OPEN
    success_threshold: int = 1       # successes in HALF_OPEN to close

    _state: State = field(default=State.CLOSED, init=False, repr=False)
    _failure_count: int = field(default=0, init=False, repr=False)
    _success_count: int = field(default=0, init=False, repr=False)
    _opened_at: float = field(default=0.0, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    @property
    def state(self) -> State:
        with self._lock:
            if self._state == State.OPEN:
                if time.monotonic() - self._opened_at >= self.recovery_timeout:
                    self._state = State.HALF_OPEN
                    self._success_count = 0
            return self._state

    def _on_success(self) -> None:
        with self._lock:
            if self._state == State.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.success_threshold:
                    self._state = State.CLOSED
                    self._failure_count = 0
            elif self._state == State.CLOSED:
                self._failure_count = 0

    def _on_failure(self) -> None:
        with self._lock:
            self._failure_count += 1
            if self._failure_count >= self.failure_threshold or self._state == State.HALF_OPEN:
                self._state = State.OPEN
                self._opened_at = time.monotonic()

    def retry_after(self) -> float:
        elapsed = time.monotonic() - self._opened_at
        return max(0.0, self.recovery_timeout - elapsed)

    def __enter__(self) -> "CircuitBreaker":
        current = self.state
        if current == State.OPEN:
            raise CircuitOpenError(self.name, self.retry_after())
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        if exc_type is None:
            self._on_success()
        else:
            self._on_failure()
        return False  # never suppress exceptions

    def call(self, fn: Callable, *args, **kwargs) -> Any:
        with self:
            return fn(*args, **kwargs)

    def status(self) -> dict:
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self._failure_count,
            "retry_after_seconds": self.retry_after() if self._state == State.OPEN else 0,
        }


# ── Registry — one breaker per named resource ─────────

_registry: dict[str, CircuitBreaker] = {}
_registry_lock = threading.Lock()


def get_breaker(
    name: str,
    failure_threshold: int = 3,
    recovery_timeout: float = 60.0,
) -> CircuitBreaker:
    """Get or create a named circuit breaker (singleton per name)."""
    with _registry_lock:
        if name not in _registry:
            _registry[name] = CircuitBreaker(
                name=name,
                failure_threshold=failure_threshold,
                recovery_timeout=recovery_timeout,
            )
        return _registry[name]


def all_statuses() -> list[dict]:
    """Return status of all registered circuit breakers."""
    with _registry_lock:
        return [cb.status() for cb in _registry.values()]
