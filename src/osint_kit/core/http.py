"""HTTP client with timeouts, retries, backoff, caching, and rate limiting.

The client is deliberately boring: it returns responses for any HTTP status so
callers can decide what a 404 means, and raises only for transport failures
after retries are exhausted.
"""

from __future__ import annotations

import json
import random
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx

from osint_kit.core.cache import Cache, CachedResponse, NullCache, cache_key
from osint_kit.core.errors import HttpError
from osint_kit.core.ratelimit import HostRateLimiter

DEFAULT_USER_AGENT = (
    "osint-kit/0.1 (passive OSINT; +https://github.com/developer-az/pyFollowerVsFollowing)"
)

RETRY_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})


@dataclass(frozen=True)
class HttpResponse:
    """A transport-independent response."""

    url: str
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    content: bytes = b""
    from_cache: bool = False

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        try:
            return json.loads(self.text)
        except ValueError as exc:
            raise HttpError(f"response from {self.url} was not JSON", url=self.url) from exc


class HttpClient:
    """Small wrapper around ``httpx.Client`` with the behaviours we want."""

    def __init__(
        self,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 15.0,
        retries: int = 2,
        backoff: float = 0.5,
        max_backoff: float = 8.0,
        cache: Cache | None = None,
        limiter: HostRateLimiter | None = None,
        user_agent: str = DEFAULT_USER_AGENT,
        max_bytes: int = 8_000_000,
        sleep: Callable[[float], None] = time.sleep,
        random_source: Callable[[], float] = random.random,
    ) -> None:
        if retries < 0:
            raise ValueError("retries must be non-negative")
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.max_backoff = max_backoff
        self.cache = cache or NullCache()
        self.limiter = limiter or HostRateLimiter(default_rate=1.0)
        self.max_bytes = max_bytes
        self._sleep = sleep
        self._random = random_source
        self._client = httpx.Client(
            transport=transport,
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": user_agent},
        )

    def __enter__(self) -> HttpClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def _cacheable(self, method: str, status: int) -> bool:
        return method.upper() == "GET" and 200 <= status < 300

    def _sleep_for_retry(self, attempt: int, response: httpx.Response | None) -> None:
        delay = min(self.max_backoff, self.backoff * (2**attempt))
        if response is not None:
            retry_after = response.headers.get("Retry-After", "")
            if retry_after.isdigit():
                delay = min(self.max_backoff, max(delay, float(retry_after)))
        delay += self._random() * self.backoff
        self._sleep(delay)

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        use_cache: bool = True,
    ) -> HttpResponse:
        """Perform one logical request, retrying transient failures."""
        key = cache_key(method, url, params)
        if use_cache and method.upper() == "GET":
            cached = self.cache.get(key)
            if cached is not None:
                return HttpResponse(
                    url=cached.url,
                    status_code=cached.status_code,
                    headers=dict(cached.headers),
                    content=cached.content,
                    from_cache=True,
                )

        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            self.limiter.acquire(url)
            try:
                raw = self._client.request(method, url, params=params, headers=headers)
            except httpx.TransportError as exc:
                last_error = exc
                if attempt < self.retries:
                    self._sleep_for_retry(attempt, None)
                    continue
                raise HttpError(
                    f"{method.upper()} {url} failed after {attempt + 1} attempt(s): {exc}",
                    url=url,
                ) from exc

            if raw.status_code in RETRY_STATUSES and attempt < self.retries:
                self._sleep_for_retry(attempt, raw)
                continue

            if len(raw.content) > self.max_bytes:
                raise HttpError(
                    f"response from {url} exceeded {self.max_bytes} bytes",
                    url=url,
                    status=raw.status_code,
                )

            response = HttpResponse(
                url=str(raw.url),
                status_code=raw.status_code,
                headers={key.lower(): value for key, value in raw.headers.items()},
                content=raw.content,
            )
            if use_cache and self._cacheable(method, response.status_code):
                self.cache.put(
                    key,
                    CachedResponse(
                        url=response.url,
                        status_code=response.status_code,
                        headers=response.headers,
                        content=response.content,
                    ),
                )
            return response

        # Unreachable in practice: the loop either returns or raises.
        raise HttpError(f"{method.upper()} {url} failed: {last_error}", url=url)

    def get(
        self,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        use_cache: bool = True,
    ) -> HttpResponse:
        return self.request("GET", url, params=params, headers=headers, use_cache=use_cache)

    def get_json(
        self,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        response = self.get(url, params=params, headers=headers)
        if not 200 <= response.status_code < 300:
            raise HttpError(
                f"GET {url} returned HTTP {response.status_code}",
                url=url,
                status=response.status_code,
            )
        return response.json()

    def get_text(
        self,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> str:
        response = self.get(url, params=params, headers=headers)
        if not 200 <= response.status_code < 300:
            raise HttpError(
                f"GET {url} returned HTTP {response.status_code}",
                url=url,
                status=response.status_code,
            )
        return response.text
