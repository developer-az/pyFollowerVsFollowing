"""Plugin contract, registry glue, and the runtime context plugins receive.

A plugin is anything that satisfies :class:`Plugin`. In-tree plugins subclass
:class:`BasePlugin` for the boilerplate; third parties may implement the
protocol directly and register through the ``osint_kit.plugins`` entry-point
group.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar, Protocol, TextIO, runtime_checkable

import httpx

from osint_kit.core.cache import Cache, FileCache, NullCache
from osint_kit.core.errors import NetworkDisabledError
from osint_kit.core.http import HttpClient
from osint_kit.core.models import Report
from osint_kit.core.ratelimit import HostRateLimiter
from osint_kit.core.robots import RobotsCache

NETWORK_NOTICE = (
    "osint-kit: network plugin - read-only requests to public services only; "
    "no logins, no scraping behind auth, no rate-limit bypass. Use lawfully."
)


def default_cache_dir() -> Path:
    """Per-user cache location, following platform conventions."""
    override = os.environ.get("OSINT_KIT_CACHE_DIR")
    if override:
        return Path(override).expanduser()
    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        return Path(local_appdata) / "osint-kit" / "cache"
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg).expanduser() / "osint-kit"
    return Path.home() / ".cache" / "osint-kit"


@dataclass
class PluginContext:
    """Runtime knobs and lazily-created network machinery."""

    offline: bool = False
    cache_dir: Path | None = None
    use_cache: bool = True
    cache_ttl: float = 3600.0
    timeout: float = 15.0
    retries: int = 2
    rate_limit: float = 1.0
    stderr: TextIO = sys.stderr
    transport: httpx.BaseTransport | None = None
    sleep: Callable[[float], None] = time.sleep
    _client: HttpClient | None = field(default=None, init=False, repr=False)
    _robots: RobotsCache | None = field(default=None, init=False, repr=False)
    _notice_shown: bool = field(default=False, init=False, repr=False)

    def announce_network(self) -> None:
        """Print the passive-use notice once per process."""
        if not self._notice_shown:
            print(NETWORK_NOTICE, file=self.stderr)
            self._notice_shown = True

    def _build_cache(self) -> Cache:
        if not self.use_cache:
            return NullCache()
        root = self.cache_dir or default_cache_dir()
        return FileCache(Path(root), ttl=self.cache_ttl)

    def http(self) -> HttpClient:
        """Return the shared HTTP client, creating it on first use."""
        if self.offline:
            raise NetworkDisabledError(
                "this plugin needs the network; rerun without --offline or pick a local plugin"
            )
        if self._client is None:
            self._client = HttpClient(
                transport=self.transport,
                timeout=self.timeout,
                retries=self.retries,
                cache=self._build_cache(),
                limiter=HostRateLimiter(default_rate=self.rate_limit),
                sleep=self.sleep,
            )
        return self._client

    def robots(self) -> RobotsCache:
        if self._robots is None:
            self._robots = RobotsCache(self.http())
        return self._robots

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None


@runtime_checkable
class Plugin(Protocol):
    """Structural contract every plugin satisfies."""

    @property
    def name(self) -> str: ...

    @property
    def summary(self) -> str: ...

    @property
    def network(self) -> bool: ...

    def configure_parser(self, parser: argparse.ArgumentParser) -> None: ...

    def run(self, options: argparse.Namespace, ctx: PluginContext) -> Report: ...


class BasePlugin:
    """Convenience base: declare NAME/SUMMARY/NETWORK and implement ``run``."""

    NAME: ClassVar[str] = ""
    SUMMARY: ClassVar[str] = ""
    NETWORK: ClassVar[bool] = False

    @property
    def name(self) -> str:
        return self.NAME

    @property
    def summary(self) -> str:
        return self.SUMMARY

    @property
    def network(self) -> bool:
        return self.NETWORK

    def configure_parser(self, parser: argparse.ArgumentParser) -> None:
        """Add plugin arguments. Default: none."""

    def run(self, options: argparse.Namespace, ctx: PluginContext) -> Report:
        raise NotImplementedError
