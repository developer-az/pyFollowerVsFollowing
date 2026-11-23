"""Core plugin runtime: base class defaults, context, cache dir resolution."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import pytest

from osint_kit.core.cache import FileCache
from osint_kit.core.errors import NetworkDisabledError
from osint_kit.core.plugin import BasePlugin, PluginContext, default_cache_dir


def test_base_plugin_defaults() -> None:
    plugin = BasePlugin()
    assert plugin.name == ""
    assert plugin.summary == ""
    assert plugin.network is False
    parser = argparse.ArgumentParser()
    plugin.configure_parser(parser)  # no arguments added
    assert parser.parse_args([]) == argparse.Namespace()
    with pytest.raises(NotImplementedError):
        plugin.run(argparse.Namespace(), PluginContext())


def test_default_cache_dir_resolution(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("OSINT_KIT_CACHE_DIR", str(tmp_path / "custom"))
    assert default_cache_dir() == tmp_path / "custom"

    monkeypatch.delenv("OSINT_KIT_CACHE_DIR")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    assert default_cache_dir() == tmp_path / "local" / "osint-kit" / "cache"

    monkeypatch.delenv("LOCALAPPDATA")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    assert default_cache_dir() == tmp_path / "xdg" / "osint-kit"

    monkeypatch.delenv("XDG_CACHE_HOME")
    assert default_cache_dir() == Path.home() / ".cache" / "osint-kit"


def test_offline_context_refuses_network() -> None:
    context = PluginContext(offline=True)
    with pytest.raises(NetworkDisabledError, match="needs the network"):
        context.http()
    context.close()  # no client was created


def test_context_builds_and_reuses_client(context_factory: Any, tmp_path: Path) -> None:
    context = context_factory(cache_dir=tmp_path / "cache", use_cache=True)
    first = context.http()
    assert context.http() is first
    assert isinstance(context._build_cache(), FileCache)
    assert context.robots() is context.robots()
    context.close()
    assert context._client is None


def test_context_cache_can_be_disabled(context_factory: Any) -> None:
    context = context_factory(use_cache=False)
    assert context._build_cache().__class__.__name__ == "NullCache"
