"""Cache and rate-limiter tests (no network, no real sleeping)."""

from __future__ import annotations

from pathlib import Path

import pytest

from osint_kit.core.cache import CachedResponse, FileCache, NullCache, cache_key
from osint_kit.core.ratelimit import HostRateLimiter, RateLimiter


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def test_cache_key_is_order_independent() -> None:
    first = cache_key("GET", "https://example.com/x", {"b": "2", "a": "1"})
    second = cache_key("get", "https://example.com/x", {"a": "1", "b": "2"})
    assert first == second
    assert first != cache_key("GET", "https://example.com/x")


def test_file_cache_roundtrip_and_ttl(tmp_path: Path) -> None:
    clock = FakeClock()
    cache = FileCache(tmp_path, ttl=10, clock=clock)
    response = CachedResponse(
        url="https://example.com/",
        status_code=200,
        headers={"content-type": "text/plain"},
        content=b"hello",
        stored_at=clock(),
    )
    assert cache.get("key") is None
    cache.put("key", response)
    cached = cache.get("key")
    assert cached is not None
    assert cached.content == b"hello"
    assert cached.headers == {"content-type": "text/plain"}

    clock.now = 11
    assert cache.get("key") is None


def test_file_cache_ignores_corruption(tmp_path: Path) -> None:
    cache = FileCache(tmp_path)
    path = tmp_path / "ab" / "abc.json"
    path.parent.mkdir()
    path.write_text("{not json", encoding="utf-8")
    assert cache.get("abc") is None

    path.write_text('{"stored_at": "later"}', encoding="utf-8")
    assert cache.get("abc") is None


def test_file_cache_clear_and_null_cache(tmp_path: Path) -> None:
    cache = FileCache(tmp_path)
    cache.put(
        "k1",
        CachedResponse(url="u", status_code=200, headers={}, content=b"x", stored_at=0),
    )
    assert cache.clear() == 1
    assert cache.clear() == 0

    null = NullCache()
    null.put("k", CachedResponse(url="u", status_code=200, headers={}, content=b""))
    assert null.get("k") is None


def test_rate_limiter_blocks_and_refills() -> None:
    clock = FakeClock()
    limiter = RateLimiter(1.0, clock=clock, sleep=clock.sleep)
    assert limiter.try_acquire() is True
    assert limiter.try_acquire() is False
    waited = limiter.acquire()
    assert waited == pytest.approx(1.0)
    assert clock.sleeps == [pytest.approx(1.0)]
    assert limiter.acquire(0) == 0.0


def test_rate_limiter_validates_inputs() -> None:
    with pytest.raises(ValueError):
        RateLimiter(0)
    with pytest.raises(ValueError):
        RateLimiter(1, period=0)


def test_host_rate_limiter_override() -> None:
    clock = FakeClock()
    limiter = HostRateLimiter(10.0, clock=clock, sleep=clock.sleep)
    limiter.acquire("https://example.com/a")
    limiter.set_rate("example.com", 0.5)
    assert limiter.limiter_for("example.com").rate == 0.5
    assert limiter.acquire("https://example.com/b") == 0.0
    assert limiter.acquire("https://example.com/c") == pytest.approx(2.0)

    slow = HostRateLimiter(1.0, clock=clock, sleep=clock.sleep)
    assert slow.acquire("https://other.example/a") == 0.0
    assert slow.acquire("https://other.example/b") == pytest.approx(1.0)
    assert slow.acquire("https://elsewhere.example/a") == 0.0


def test_host_rate_limiter_rejects_bad_default() -> None:
    with pytest.raises(ValueError):
        HostRateLimiter(0)
