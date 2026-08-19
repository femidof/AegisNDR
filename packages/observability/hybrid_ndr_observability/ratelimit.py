"""Small fixed-window rate limiter for the product HTTP APIs.

Keys are tenant/actor identities, never IP addresses alone, so the limiter
bounds authenticated abuse without penalizing a shared customer network. The
window is a fixed 60-second bucket; `retry_after` returns whole seconds until
the current bucket resets. State is kept in memory only: a restart clears the
counters, which is acceptable for an abuse bound rather than an accounting
control.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Mapping


class FixedWindowLimiter:
    def __init__(
        self,
        limit_per_minute: int,
        *,
        window_seconds: int = 60,
        maximum_key_bytes: int = 256,
        maximum_entries: int = 100_000,
        now: Callable[[], float] | None = None,
    ) -> None:
        if limit_per_minute < 1 or window_seconds < 1:
            raise ValueError("rate limit and window must be positive")
        if maximum_key_bytes < 16 or maximum_entries < 1:
            raise ValueError("limiter caps must be positive and sane")
        self.limit = int(limit_per_minute)
        self.window_seconds = int(window_seconds)
        self.maximum_key_bytes = int(maximum_key_bytes)
        self.maximum_entries = int(maximum_entries)
        self._now = now or time.monotonic
        self._windows: dict[str, tuple[float, int]] = {}
        self._lock = threading.RLock()

    def _prune(self, current: float) -> None:
        stale = [key for key, (started, _count) in self._windows.items() if current - started >= self.window_seconds]
        for key in stale:
            del self._windows[key]

    def _bounded_key(self, key: str) -> str:
        """Deterministically truncate oversized keys so a flood of unique,
        multi-megabyte keys cannot exhaust memory before the window prunes."""
        return key if len(key) <= self.maximum_key_bytes else key[: self.maximum_key_bytes]

    def _evict_one(self) -> None:
        """Bound total window entries: drop the oldest bucket so a burst of
        unique keys cannot grow the table without limit."""
        oldest = min(self._windows, key=lambda key: self._windows[key][0])
        del self._windows[oldest]

    def allow(self, key: str) -> bool:
        """Return True when the key may proceed, otherwise False (429)."""
        current = self._now()
        bounded = self._bounded_key(key)
        with self._lock:
            self._prune(current)
            if bounded not in self._windows and len(self._windows) >= self.maximum_entries:
                self._evict_one()
            started, count = self._windows.get(bounded, (current, 0))
            if current - started >= self.window_seconds:
                started, count = current, 0
            count += 1
            self._windows[bounded] = (started, count)
            return count <= self.limit

    def retry_after(self, key: str) -> int:
        """Whole seconds until the current bucket resets, for Retry-After."""
        current = self._now()
        with self._lock:
            started, _count = self._windows.get(self._bounded_key(key), (current, 0))
            remaining = self.window_seconds - int(current - started)
            return max(1, remaining)

    def snapshot(self) -> Mapping[str, int]:
        with self._lock:
            return {key: count for key, (_started, count) in self._windows.items()}
