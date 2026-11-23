"""Shared fixtures and helpers for the test suite.

All fixtures are synthetic. Network is never used: plugins receive an
``httpx.MockTransport`` through :class:`PluginContext`.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any

import httpx
import pytest

from osint_kit.core.plugin import PluginContext

FIXTURES = Path(__file__).parent / "fixtures"

Handler = Callable[[httpx.Request], httpx.Response]


def load_json(relative: str) -> Any:
    return json.loads((FIXTURES / relative).read_text(encoding="utf-8"))


def read_text(relative: str) -> str:
    return (FIXTURES / relative).read_text(encoding="utf-8")


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def context_factory() -> Iterator[Callable[..., PluginContext]]:
    contexts: list[PluginContext] = []

    def make(
        handler: Handler | None = None,
        *,
        retries: int = 0,
        rate_limit: float = 10_000.0,
        **overrides: object,
    ) -> PluginContext:
        transport = httpx.MockTransport(handler) if handler is not None else None
        options: dict[str, Any] = {
            "transport": transport,
            "use_cache": False,
            "sleep": lambda _seconds: None,
            "rate_limit": rate_limit,
            "retries": retries,
        }
        options.update(overrides)
        context = PluginContext(**options)
        contexts.append(context)
        return context

    yield make
    for context in contexts:
        context.close()


class RouteHandler:
    """Tiny router for MockTransport: ``(host, path)`` or predicate -> response."""

    def __init__(self) -> None:
        self.routes: list[tuple[Callable[[httpx.Request], bool], Handler]] = []

    def add(self, predicate: Callable[[httpx.Request], bool], handler: Handler) -> RouteHandler:
        self.routes.append((predicate, handler))
        return self

    def json(self, url_part: str, payload: Any, status: int = 200) -> RouteHandler:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(status, json=payload)

        return self.add(lambda request: url_part in str(request.url), handler)

    def text(self, url_part: str, body: str, status: int = 200) -> RouteHandler:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(status, text=body)

        return self.add(lambda request: url_part in str(request.url), handler)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        for predicate, handler in self.routes:
            if predicate(request):
                return handler(request)
        return httpx.Response(404, text="no route")


@pytest.fixture
def routes() -> RouteHandler:
    return RouteHandler()


@pytest.fixture
def sample_received() -> Mapping[str, str]:
    return {
        "newest": (
            "from mx.example.org (mx.example.org [203.0.113.20])\n"
            "\tby inbox.example.com (Postfix) with ESMTPS id ABC123\n"
            "\tfor <user@example.com>; Tue, 1 Nov 2025 12:00:03 +0000"
        ),
        "middle": (
            "from relay.example.org (relay.example.org [203.0.113.10])\n"
            "\tby mx.example.org with ESMTP id DEF456; Tue, 1 Nov 2025 12:00:02 +0000"
        ),
        "oldest": (
            "from sender.example.net (sender.example.net [198.51.100.5])\n"
            "\tby relay.example.org with ESMTP id GHI789; Tue, 1 Nov 2025 12:00:00 +0000"
        ),
    }
