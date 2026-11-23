"""Registry and CLI tests."""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path
from typing import Any

import pytest

from osint_kit import cli
from osint_kit.core import registry
from osint_kit.core.models import Report
from osint_kit.core.plugin import BasePlugin, Plugin, PluginContext
from osint_kit.core.registry import by_name, load_plugins


class ExtraPlugin(BasePlugin):
    NAME = "extra"
    SUMMARY = "An extra plugin registered by a fake entry point."
    NETWORK = False

    def run(self, options: Any, ctx: PluginContext) -> Report:
        return Report(plugin=self.name, target="extra")


class FakeEntryPoint:
    def __init__(self, name: str, value: str, loaded: object) -> None:
        self.name = name
        self.value = value
        self._loaded = loaded

    def load(self) -> object:
        if isinstance(self._loaded, Exception):
            raise self._loaded
        return self._loaded


def builtin_plugins() -> dict[str, Plugin]:
    return load_plugins(include_entry_points=False)


def test_builtin_registry_has_eight_plugins() -> None:
    plugins = builtin_plugins()
    assert set(plugins) == {
        "social_diff",
        "domain_recon",
        "rdap",
        "email_headers",
        "exif",
        "log_analyzer",
        "hashing",
        "username_check",
    }
    assert all(isinstance(plugin, Plugin) for plugin in plugins.values())
    assert by_name(plugins)["social_diff"].network is False


def test_entry_points_extend_and_warn(monkeypatch: pytest.MonkeyPatch) -> None:
    warnings: list[str] = []

    def fake_entry_points(*, group: str) -> list[FakeEntryPoint]:
        assert group == "osint_kit.plugins"
        return [
            FakeEntryPoint("extra", "thirdparty.extra:ExtraPlugin", ExtraPlugin),
            FakeEntryPoint("hashing", "thirdparty.hashing:Nope", ExtraPlugin),
            FakeEntryPoint(
                "email_headers", "osint_kit.plugins.email_headers:EmailHeadersPlugin", ExtraPlugin
            ),
            FakeEntryPoint("broken", "thirdparty.broken:Nope", RuntimeError("kaboom")),
            FakeEntryPoint("not-a-plugin", "thirdparty.bad:Nope", object),
        ]

    monkeypatch.setattr(registry, "entry_points", fake_entry_points)
    plugins = registry.load_plugins(warn=warnings.append)
    assert "extra" in plugins
    assert "broken" not in plugins
    assert "not-a-plugin" not in plugins
    assert any("thirdparty.hashing" in message or "hashing" in message for message in warnings)
    assert any("could not load" in message for message in warnings)
    assert any("protocol" in message for message in warnings)
    assert not any("email_headers" in message for message in warnings)


def test_list_report_and_parser() -> None:
    plugins = builtin_plugins()
    report = cli.list_report(plugins)
    assert report.stats == {"plugins": 8, "network": 3, "local": 5}
    parser = cli.build_parser(plugins)
    help_text = parser.format_help()
    assert "social_diff" in help_text
    assert "list" in help_text


def test_cli_list_json() -> None:
    stdout = StringIO()
    code = cli.main(["list", "--format", "json"], plugins=builtin_plugins(), stdout=stdout)
    assert code == 0
    payload = json.loads(stdout.getvalue())
    assert payload["plugin"] == "list"
    assert payload["stats"]["plugins"] == 8


def test_cli_version(capsys: pytest.CaptureFixture[str]) -> None:
    code = cli.main(["--version"], plugins=builtin_plugins())
    assert code == 0
    assert "osint-kit 0.1.0" in capsys.readouterr().out


def test_cli_argparse_error_returns_two(capsys: pytest.CaptureFixture[str]) -> None:
    code = cli.main(["social_diff"], plugins=builtin_plugins())
    assert code == 2
    assert "required" in capsys.readouterr().err


def test_cli_social_diff_end_to_end(fixtures: Path) -> None:
    stdout = StringIO()
    code = cli.main(
        [
            "social_diff",
            "--followers",
            str(fixtures / "instagram_html"),
            "--following",
            str(fixtures / "instagram_html"),
            "--format",
            "json",
        ],
        plugins=builtin_plugins(),
        stdout=stdout,
    )
    assert code == 0
    payload = json.loads(stdout.getvalue())
    categories = {finding["category"] for finding in payload["findings"]}
    assert {"non_follower", "fan"} <= categories
    assert payload["stats"]["followers"] == 4
    assert "not_instagram" not in json.dumps(payload)


def test_cli_writes_output_file(fixtures: Path, tmp_path: Path) -> None:
    destination = tmp_path / "out" / "report.md"
    code = cli.main(
        [
            "social_diff",
            "--followers",
            str(fixtures / "instagram_html" / "followers_1.html"),
            "--following",
            str(fixtures / "instagram_html" / "following.html"),
            "--format",
            "md",
            "--output",
            str(destination),
        ],
        plugins=builtin_plugins(),
    )
    assert code == 0
    assert destination.read_text(encoding="utf-8").startswith("# osint-kit report")


def test_cli_errors_are_nonzero(fixtures: Path) -> None:
    stderr = StringIO()
    code = cli.main(
        [
            "social_diff",
            "--followers",
            str(fixtures / "missing.html"),
            "--following",
            str(fixtures / "instagram_html" / "following.html"),
        ],
        plugins=builtin_plugins(),
        stderr=stderr,
    )
    assert code == 2
    assert "does not exist" in stderr.getvalue()

    stderr = StringIO()
    code = cli.main(
        ["domain_recon", "example.com", "--offline"],
        plugins=builtin_plugins(),
        stderr=stderr,
    )
    assert code == 2
    assert "needs the network" in stderr.getvalue()

    stderr = StringIO()
    code = cli.main(
        ["hashing", "--text", "x", "--retries", "-1"],
        plugins=builtin_plugins(),
        stderr=stderr,
    )
    assert code == 2
    assert "retries" in stderr.getvalue()


def test_cli_unknown_plugin_is_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    stderr = StringIO()
    code = cli.main(["nope"], plugins=builtin_plugins(), stderr=stderr)
    assert code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_network_notice_printed_once() -> None:
    stderr = StringIO()
    context = PluginContext(stderr=stderr, use_cache=False)
    context.announce_network()
    context.announce_network()
    assert stderr.getvalue().count("read-only requests") == 1
    context.close()
