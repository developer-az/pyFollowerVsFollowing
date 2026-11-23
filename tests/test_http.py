"""HTTP client tests using httpx.MockTransport only."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from osint_kit.core.cache import FileCache
from osint_kit.core.errors import HttpError
from osint_kit.core.http import HttpClient
from osint_kit.core.ratelimit import HostRateLimiter


def client(
    handler: object,
    *,
    retries: int = 0,
    sleeps: list[float] | None = None,
    cache: FileCache | None = None,
    max_bytes: int = 8_000_000,
) -> HttpClient:
    return HttpClient(
        transport=httpx.MockTransport(handler),  # type: ignore[arg-type]
        retries=retries,
        backoff=0.1,
        sleep=(sleeps.append if sleeps is not None else (lambda _seconds: None)),
        cache=cache,
        limiter=HostRateLimiter(10_000.0),
        random_source=lambda: 0.0,
        max_bytes=max_bytes,
    )


def test_get_returns_response_and_user_agent() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, text="hello", headers={"X-Test": "yes"})

    with client(handler) as http:
        response = http.get("https://example.com/x")
    assert response.status_code == 200
    assert response.text == "hello"
    assert response.headers["x-test"] == "yes"
    assert seen[0].headers["user-agent"].startswith("osint-kit/")


def test_get_json_and_errors() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/ok":
            return httpx.Response(200, json={"ok": True})
        if request.url.path == "/bad-json":
            return httpx.Response(200, text="not json")
        return httpx.Response(404, text="missing")

    with client(handler) as http:
        assert http.get_json("https://example.com/ok") == {"ok": True}
        with pytest.raises(HttpError, match="not JSON"):
            http.get_json("https://example.com/bad-json")
        with pytest.raises(HttpError, match="HTTP 404"):
            http.get_text("https://example.com/missing")


def test_retry_then_success_and_retry_after() -> None:
    calls: list[int] = []
    sleeps: list[float] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(429, headers={"Retry-After": "2"})
        return httpx.Response(200, text="ok")

    with client(handler, retries=1, sleeps=sleeps) as http:
        response = http.get("https://example.com/")
    assert response.status_code == 200
    assert len(calls) == 2
    assert sleeps and sleeps[0] >= 2.0


def test_retries_exhausted_raises_http_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    with (
        client(handler, retries=1) as http,
        pytest.raises(HttpError, match="failed after 2 attempt"),
    ):
        http.get("https://example.com/")


def test_non_retryable_status_is_returned() -> None:
    calls: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(418, text="teapot")

    with client(handler, retries=2) as http:
        response = http.get("https://example.com/")
    assert response.status_code == 418
    assert len(calls) == 1


def test_cache_hit_avoids_second_request(tmp_path: Path) -> None:
    calls: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(200, text="cached", headers={"Content-Type": "text/plain"})

    cache = FileCache(tmp_path, ttl=60)
    with client(handler, cache=cache) as http:
        first = http.get("https://example.com/cache")
        second = http.get("https://example.com/cache")
    assert len(calls) == 1
    assert first.from_cache is False
    assert second.from_cache is True
    assert second.text == "cached"


def test_response_size_cap() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 100)

    with client(handler, max_bytes=10) as http, pytest.raises(HttpError, match="exceeded"):
        http.get("https://example.com/big")


def test_cache_key_not_used_for_post(tmp_path: Path) -> None:
    calls: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(200, text="x")

    cache = FileCache(tmp_path)
    with client(handler, cache=cache) as http:
        http.request("POST", "https://example.com/x")
        http.request("POST", "https://example.com/x")
    assert len(calls) == 2


def test_invalid_constructor_arguments() -> None:
    with pytest.raises(ValueError):
        HttpClient(retries=-1)
