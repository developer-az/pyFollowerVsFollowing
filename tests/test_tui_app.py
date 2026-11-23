"""The interactive flow, driven end to end with a scripted prompter."""

from __future__ import annotations

import io
import json
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest
from rich.console import Console

import osint_kit.cli as cli
import osint_kit.tui as tui_package
from osint_kit.core.plugin import Plugin
from osint_kit.core.registry import load_plugins
from osint_kit.tui.app import TuiApp
from osint_kit.tui.detect import ExportCandidate
from osint_kit.tui.prompt import Choice
from tests.conftest import FIXTURES
from tests.tui_driver import ScriptedPrompter

HTML = FIXTURES / "instagram_html"
OUTPUT = FIXTURES / "logs" / "access.log"


class BoomPrompter(ScriptedPrompter):
    """Raises on the first menu question."""

    def __init__(self, error: BaseException) -> None:
        super().__init__([])
        self.error = error

    def choice(self, label: str, choices: Sequence[Choice], *, default: str | None = None) -> str:
        del label, choices, default
        raise self.error


def make() -> tuple[Console, io.StringIO]:
    buffer = io.StringIO()
    return (
        Console(file=buffer, width=100, force_terminal=False, no_color=True, highlight=False),
        buffer,
    )


def app(
    queue: list[tuple[str, str]],
    *,
    registry: Mapping[str, Plugin] | None = None,
    offline: bool = False,
    exports: list[ExportCandidate] | None = None,
    prompter: ScriptedPrompter | None = None,
) -> tuple[TuiApp, io.StringIO]:
    console, buffer = make()
    prompter = prompter if prompter is not None else ScriptedPrompter(queue)
    return (
        TuiApp(
            registry=registry if registry is not None else load_plugins(),
            prompter=prompter,
            console=console,
            offline=offline,
            exports=exports or [],
        ),
        buffer,
    )


def test_quit_immediately() -> None:
    session, output = app([("choice", "q")])
    assert session.run() == 0
    assert "osint-kit" in output.getvalue()
    assert "Bye." in output.getvalue()


def test_social_diff_reports_and_saves_json(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    session, output = app(
        [
            ("choice", "1"),
            ("text", str(HTML)),
            ("text", str(HTML / "following.html")),
            ("text", ""),
            ("confirm", "n"),
            ("choice", "save"),
            ("choice", "json"),
            ("text", str(target)),
            ("choice", "back"),
            ("choice", "q"),
        ]
    )
    assert session.run() == 0
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["plugin"] == "social_diff"
    assert payload["findings"]
    assert "Saved to" in output.getvalue()


@pytest.mark.parametrize(
    ("fmt", "needle"), [("csv", "category,subject"), ("md", "# osint-kit report")]
)
def test_save_other_formats(tmp_path: Path, fmt: str, needle: str) -> None:
    target = tmp_path / f"report.{fmt}"
    session, _output = app(
        [
            ("choice", "1"),
            ("text", str(HTML)),
            ("text", str(HTML / "following.html")),
            ("text", ""),
            ("confirm", "n"),
            ("choice", "save"),
            ("choice", fmt),
            ("text", str(target)),
            ("choice", "back"),
            ("choice", "q"),
        ]
    )
    assert session.run() == 0
    assert needle in target.read_text(encoding="utf-8")


def test_save_failure_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*_args: object, **_kwargs: object) -> str:
        raise OSError("disk full")

    monkeypatch.setattr("osint_kit.tui.app.write_report", explode)
    session, output = app(
        [
            ("choice", "1"),
            ("text", str(HTML)),
            ("text", str(HTML / "following.html")),
            ("text", ""),
            ("confirm", "n"),
            ("choice", "save"),
            ("choice", "md"),
            ("text", str(tmp_path / "x.md")),
            ("choice", "back"),
            ("choice", "q"),
        ]
    )
    assert session.run() == 0
    assert "disk full" in output.getvalue()


def test_bad_input_returns_to_the_menu() -> None:
    session, output = app(
        [
            ("choice", "1"),
            ("text", "nope.html"),
            ("text", "also-nope.html"),
            ("text", ""),
            ("confirm", "n"),
            ("choice", "q"),
        ]
    )
    assert session.run() == 0
    assert "stopped" in output.getvalue()
    assert "does not exist" in output.getvalue()


def test_run_again_loops_back_into_the_form() -> None:
    session, _output = app(
        [
            ("choice", "1"),
            ("text", str(HTML)),
            ("text", str(HTML / "following.html")),
            ("text", ""),
            ("confirm", "n"),
            ("choice", "again"),
            ("text", str(HTML)),
            ("text", str(HTML / "following.html")),
            ("text", ""),
            ("confirm", "n"),
            ("choice", "back"),
            ("choice", "q"),
        ]
    )
    assert session.run() == 0


def test_quit_from_the_result_menu() -> None:
    session, _output = app(
        [
            ("choice", "1"),
            ("text", str(HTML)),
            ("text", str(HTML / "following.html")),
            ("text", ""),
            ("confirm", "n"),
            ("choice", "quit"),
        ]
    )
    assert session.run() == 0


def test_advanced_options_and_flag() -> None:
    session, output = app(
        [
            ("choice", "1"),
            ("text", str(HTML)),
            ("text", str(HTML / "following.html")),
            ("text", ""),
            ("confirm", "y"),
            ("confirm", "y"),
            ("choice", "back"),
            ("choice", "q"),
        ]
    )
    assert session.run() == 0
    assert "mutual" in output.getvalue().lower()


def test_choice_and_number_fields() -> None:
    session, output = app(
        [
            ("choice", "6"),
            ("text", str(OUTPUT)),
            ("confirm", "y"),
            ("choice", "auto"),
            ("text", "60"),
            ("text", "5"),
            ("text", "10"),
            ("text", "1"),
            ("choice", "back"),
            ("choice", "q"),
        ]
    )
    assert session.run() == 0
    assert "log_analyzer" in output.getvalue()


def test_number_is_asked_again_when_not_a_number() -> None:
    session, _output = app([], prompter=ScriptedPrompter([("text", "abc"), ("text", "7")]))
    parser = session._parser(session.registry["log_analyzer"])
    from osint_kit.tui.copy import field_copy
    from osint_kit.tui.fields import iter_fields

    field = next(item for item in iter_fields(parser) if item.dest == "top")
    assert session._ask_number(field, field_copy("log_analyzer", "top")) == 7


def test_network_plugin_is_refused_when_offline() -> None:
    session, output = app([("choice", "7"), ("choice", "q")], offline=True)
    assert session.run() == 0
    assert "offline" in output.getvalue().lower()


def test_network_plugin_can_be_declined() -> None:
    session, output = app([("choice", "7"), ("confirm", "n"), ("choice", "q")])
    assert session.run() == 0
    assert "network plugin" not in output.getvalue()


def test_detected_export_is_offered() -> None:
    candidate = ExportCandidate(
        folder=HTML,
        followers=(HTML / "followers_1.html", HTML / "followers_2.html"),
        following=HTML / "following.html",
    )
    session, output = app(
        [
            ("choice", "1"),
            ("choice", "1"),
            ("choice", "1"),
            ("text", ""),
            ("confirm", "n"),
            ("choice", "back"),
            ("choice", "q"),
        ],
        exports=[candidate],
    )
    assert session.run() == 0
    assert "followers=4" in output.getvalue()


def test_detected_export_can_be_bypassed_for_a_typed_path() -> None:
    candidate = ExportCandidate(
        folder=HTML,
        followers=(HTML / "followers_1.html",),
        following=HTML / "following.html",
    )
    session, _output = app(
        [
            ("choice", "1"),
            ("choice", "other"),
            ("text", str(HTML)),
            ("choice", "other"),
            ("text", str(HTML / "following.html")),
            ("text", ""),
            ("confirm", "n"),
            ("choice", "back"),
            ("choice", "q"),
        ],
        exports=[candidate],
    )
    assert session.run() == 0


def test_keyboard_interrupt_exits_130() -> None:
    session, _output = app([], prompter=BoomPrompter(KeyboardInterrupt()))
    assert session.run() == 130


def test_eof_exits_1() -> None:
    session, _output = app([], prompter=BoomPrompter(EOFError()))
    assert session.run() == 1


def test_run_factory_wires_everything() -> None:
    console, _buffer = make()
    prompter = ScriptedPrompter([("choice", "q")])
    code = tui_package.run(
        registry=load_plugins(),
        console=console,
        prompter=prompter,
        discover_exports=False,
    )
    assert code == 0


def test_run_factory_forwards_stderr() -> None:
    console, _buffer = make()
    prompter = ScriptedPrompter([("choice", "q")])
    stream = io.StringIO()
    code = tui_package.run(
        registry=load_plugins(),
        console=console,
        prompter=prompter,
        stderr=stream,
        discover_exports=False,
    )
    assert code == 0


def test_fullscreen_needs_a_real_terminal() -> None:
    console, _buffer = make()
    assert tui_package.fullscreen_available(console) is False


def test_fullscreen_available_with_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    class Tty(io.StringIO):
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr("sys.stdin", Tty())
    monkeypatch.setattr("sys.stdout", Tty())
    assert tui_package.fullscreen_available() is True


def test_run_dispatches_to_the_fullscreen_app(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake(plugins: object, **kwargs: object) -> int:
        seen["plugins"] = plugins
        seen["kwargs"] = kwargs
        return 0

    monkeypatch.setattr("osint_kit.tui.textual_app.run_fullscreen", fake)
    assert tui_package.run(registry=load_plugins(), mode="fullscreen", discover_exports=False) == 0
    assert "plugins" in seen


# ------------------------------------------------------------------ CLI wiring


def test_cli_without_a_command_starts_the_tui(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, object] = {}

    def fake(**kwargs: object) -> int:
        calls.update(kwargs)
        return 0

    monkeypatch.setattr(tui_package, "run", fake)
    assert cli.main([], plugins={}, stdout=io.StringIO(), stderr=io.StringIO()) == 0
    assert calls["offline"] is False


def test_cli_tui_subcommand_forwards_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, object] = {}

    def fake(**kwargs: object) -> int:
        calls.update(kwargs)
        return 0

    monkeypatch.setattr(tui_package, "run", fake)
    assert cli.main(["tui", "--offline"], plugins={}, stdout=io.StringIO()) == 0
    assert calls["offline"] is True
