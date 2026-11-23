"""On-disk response cache.

Only successful GET bodies are cached. Keys hash the method, URL, and sorted
query so two plugins asking for the same document share one fetch. Corrupt
entries are discarded rather than raising.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class CachedResponse:
    url: str
    status_code: int
    headers: dict[str, str]
    content: bytes
    stored_at: float = field(default_factory=time.time)


class Cache(Protocol):
    """Minimal cache interface; keep implementations interchangeable."""

    def get(self, key: str) -> CachedResponse | None: ...

    def put(self, key: str, response: CachedResponse) -> None: ...


class NullCache:
    """A cache that stores nothing, used by ``--no-cache``."""

    def get(self, key: str) -> CachedResponse | None:
        return None

    def put(self, key: str, response: CachedResponse) -> None:
        return None


class FileCache:
    """JSON-per-entry cache under a directory."""

    def __init__(
        self,
        root: Path,
        *,
        ttl: float = 3600.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if ttl < 0:
            raise ValueError("ttl must be non-negative")
        self.root = root
        self.ttl = ttl
        self._clock = clock

    def _path(self, key: str) -> Path:
        return self.root / key[:2] / f"{key}.json"

    def get(self, key: str) -> CachedResponse | None:
        path = self._path(key)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        try:
            stored_at = float(payload["stored_at"])
            if self.ttl >= 0 and self._clock() - stored_at > self.ttl:
                return None
            return CachedResponse(
                url=str(payload["url"]),
                status_code=int(payload["status_code"]),
                headers={str(k): str(v) for k, v in dict(payload["headers"]).items()},
                content=base64.b64decode(payload["body_b64"]),
                stored_at=stored_at,
            )
        except (KeyError, TypeError, ValueError):
            return None

    def put(self, key: str, response: CachedResponse) -> None:
        path = self._path(key)
        payload = {
            "url": response.url,
            "status_code": response.status_code,
            "headers": response.headers,
            "body_b64": base64.b64encode(response.content).decode("ascii"),
            "stored_at": response.stored_at,
        }
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=path.parent, delete=False, suffix=".tmp"
            ) as handle:
                json.dump(payload, handle)
                temp_name = handle.name
            os.replace(temp_name, path)
        except OSError:
            # A cache is an optimisation; never fail an analysis over it.
            return

    def clear(self) -> int:
        """Delete every cached entry. Returns the number of files removed."""
        removed = 0
        if not self.root.exists():
            return 0
        for path in self.root.rglob("*.json"):
            try:
                path.unlink()
                removed += 1
            except OSError:
                continue
        return removed


def cache_key(method: str, url: str, params: Mapping[str, str] | None = None) -> str:
    """Stable key for a request. Sorted params make ordering irrelevant."""
    normalised = f"{method.upper()} {url}"
    if params:
        normalised += "?" + "&".join(f"{key}={params[key]}" for key in sorted(params))
    return hashlib.sha256(normalised.encode("utf-8")).hexdigest()
