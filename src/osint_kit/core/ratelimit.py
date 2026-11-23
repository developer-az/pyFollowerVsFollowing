"""Per-host token-bucket rate limiting.

The clock and sleep functions are injectable so tests run instantly and
deterministically.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Protocol
from urllib.parse import urlsplit


class Clock(Protocol):
    def __call__(self) -> float: ...


class RateLimiter:
    """Token bucket for a single logical target (usually a host)."""

    def __init__(
        self,
        rate: float,
        *,
        period: float = 1.0,
        burst: float | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if rate <= 0:
            raise ValueError("rate must be positive")
        if period <= 0:
            raise ValueError("period must be positive")
        self.rate = rate
        self.period = period
        self.burst = max(1.0, float(burst) if burst is not None else max(1.0, rate))
        self._clock = clock
        self._sleep = sleep
        self._tokens = self.burst
        self._updated = clock()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = self._clock()
        elapsed = now - self._updated
        if elapsed > 0:
            self._tokens = min(self.burst, self._tokens + elapsed * self.rate / self.period)
            self._updated = now

    def acquire(self, tokens: float = 1.0) -> float:
        """Block until ``tokens`` are available. Returns seconds waited."""
        if tokens <= 0:
            return 0.0
        waited = 0.0
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return waited
                missing = tokens - self._tokens
                delay = missing * self.period / self.rate
            # Sleep outside the lock so other threads can make progress.
            self._sleep(delay)
            waited += delay

    def try_acquire(self, tokens: float = 1.0) -> bool:
        """Non-blocking variant: take tokens if available."""
        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False


class HostRateLimiter:
    """A bucket per URL host, with a global default and per-host overrides."""

    def __init__(
        self,
        default_rate: float = 1.0,
        *,
        period: float = 1.0,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if default_rate <= 0:
            raise ValueError("default_rate must be positive")
        self.default_rate = default_rate
        self.period = period
        self._clock = clock
        self._sleep = sleep
        self._overrides: dict[str, float] = {}
        self._limiters: dict[str, RateLimiter] = {}
        self._lock = threading.Lock()

    def set_rate(self, host: str, rate: float) -> None:
        """Override the rate for one host (requests per period)."""
        with self._lock:
            self._overrides[host.lower()] = rate
            self._limiters.pop(host.lower(), None)

    def limiter_for(self, host: str) -> RateLimiter:
        key = host.lower()
        with self._lock:
            limiter = self._limiters.get(key)
            if limiter is None:
                limiter = RateLimiter(
                    self._overrides.get(key, self.default_rate),
                    period=self.period,
                    clock=self._clock,
                    sleep=self._sleep,
                )
                self._limiters[key] = limiter
            return limiter

    def acquire(self, url: str, tokens: float = 1.0) -> float:
        """Rate-limit by the URL's host. Returns seconds waited."""
        host = urlsplit(url).hostname or ""
        return self.limiter_for(host).acquire(tokens)
