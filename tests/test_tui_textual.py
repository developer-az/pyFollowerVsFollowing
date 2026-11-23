"""The full-screen app, driven headlessly with textual's pilot."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Any

import pytest
from textual.pilot import Pilot
from textual.widgets import Collapsible, Input, OptionList, Select, Static

from osint_kit.core.registry import load_plugins
from osint_kit.tui import textual_app
from osint_kit.tui.detect import ExportCandidate
from osint_kit.tui.textual_app import (
    ConsentScreen,
    OsintKitApp,
    PluginFormScreen,
    PluginListScreen,
    ResultScreen,
    SaveScreen,
)
from tests.conftest import FIXTURES

HTML = FIXTURES / "instagram_html"


async def wait_for(pilot: Pilot[None], predicate: Callable[[], bool], timeout: float = 5.0) -> None:
    """Pump messages until ``predicate`` holds (workers run in a thread)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        await pilot.pause()
        if predicate():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("timed out waiting for the app")


Body = Callable[[OsintKitApp, Pilot[None]], Coroutine[Any, Any, None]]


def scenario(body: Body) -> None:
    """Run one async body against a fresh app."""

    async def runner() -> None:
        app = OsintKitApp(load_plugins(), exports=[], offline=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await body(app, pilot)

    asyncio.run(runner())


async def open_social_diff(app: OsintKitApp, pilot: Pilot[None]) -> PluginFormScreen:
    await pilot.press("1")
    await pilot.pause()
    screen = app.screen
    assert isinstance(screen, PluginFormScreen)
    return screen


async def fill_social_diff(
    app: OsintKitApp, pilot: Pilot[None], followers: Path = HTML
) -> PluginFormScreen:
    form = await open_social_diff(app, pilot)
    form.query_one("#field-followers", Input).value = str(followers)
    form.query_one("#field-following", Input).value = str(followers / "following.html")
    await pilot.pause()
    return form


def test_list_shows_every_plugin() -> None:
    async def body(app: OsintKitApp, _pilot: Pilot[None]) -> None:
        screen = app.screen
        assert isinstance(screen, PluginListScreen)
        options = screen.query_one("#plugins", OptionList)
        assert options.option_count == len(load_plugins())

    scenario(body)


def test_number_key_opens_the_form() -> None:
    async def body(app: OsintKitApp, pilot: Pilot[None]) -> None:
        await pilot.press("1")
        await pilot.pause()
        assert isinstance(app.screen, PluginFormScreen)
        assert app.screen.plugin.name == "social_diff"

    scenario(body)


def test_escape_from_the_form_returns_to_the_list() -> None:
    async def body(app: OsintKitApp, pilot: Pilot[None]) -> None:
        await open_social_diff(app, pilot)
        await pilot.press("escape")
        await pilot.pause()
        assert isinstance(app.screen, PluginListScreen)

    scenario(body)


def test_running_social_diff_shows_results() -> None:
    async def body(app: OsintKitApp, pilot: Pilot[None]) -> None:
        await fill_social_diff(app, pilot)
        await pilot.click("#run")
        await wait_for(pilot, lambda: isinstance(app.screen, ResultScreen))
        result = app.screen
        assert isinstance(result, ResultScreen)
        table = result.query_one("#findings")
        assert table.row_count == 4  # type: ignore[attr-defined]

    scenario(body)


def test_missing_input_reports_an_error() -> None:
    async def body(app: OsintKitApp, pilot: Pilot[None]) -> None:
        await open_social_diff(app, pilot)
        await pilot.click("#run")
        await pilot.pause()
        assert isinstance(app.screen, PluginFormScreen)
        message = app.screen.query_one("#error", Static)
        assert "required" in str(message.render()).lower()

    scenario(body)


def test_advanced_section_is_collapsed() -> None:
    async def body(app: OsintKitApp, pilot: Pilot[None]) -> None:
        form = await open_social_diff(app, pilot)
        collapsible = form.query_one("#advanced", Collapsible)
        assert collapsible.collapsed is True

    scenario(body)


def test_back_from_results_reaches_the_list() -> None:
    async def body(app: OsintKitApp, pilot: Pilot[None]) -> None:
        await fill_social_diff(app, pilot)
        await pilot.click("#run")
        await wait_for(pilot, lambda: isinstance(app.screen, ResultScreen))
        await pilot.press("escape")
        await pilot.pause()
        assert isinstance(app.screen, PluginListScreen)

    scenario(body)


def test_run_again_returns_to_the_form() -> None:
    async def body(app: OsintKitApp, pilot: Pilot[None]) -> None:
        await fill_social_diff(app, pilot)
        await pilot.click("#run")
        await wait_for(pilot, lambda: isinstance(app.screen, ResultScreen))
        await pilot.press("r")
        await pilot.pause()
        assert isinstance(app.screen, PluginFormScreen)

    scenario(body)


def test_save_writes_the_report(tmp_path: Path) -> None:
    target = tmp_path / "report.json"

    async def body(app: OsintKitApp, pilot: Pilot[None]) -> None:
        await fill_social_diff(app, pilot)
        await pilot.click("#run")
        await wait_for(pilot, lambda: isinstance(app.screen, ResultScreen))
        await pilot.press("s")
        await pilot.pause()
        assert isinstance(app.screen, SaveScreen)
        app.screen.query_one("#format", Select).value = "json"
        await pilot.pause()
        app.screen.query_one("#path", Input).value = str(target)
        await pilot.pause()
        await pilot.click("#save")
        await wait_for(pilot, lambda: isinstance(app.screen, ResultScreen))

    scenario(body)
    assert target.exists()
    assert '"plugin": "social_diff"' in target.read_text(encoding="utf-8")


def test_save_dialog_switches_extension() -> None:
    async def body(app: OsintKitApp, pilot: Pilot[None]) -> None:
        await fill_social_diff(app, pilot)
        await pilot.click("#run")
        await wait_for(pilot, lambda: isinstance(app.screen, ResultScreen))
        await pilot.press("s")
        await pilot.pause()
        assert isinstance(app.screen, SaveScreen)
        app.screen.query_one("#format", Select).value = "csv"
        await pilot.pause()
        path = app.screen.query_one("#path", Input).value
        assert path.endswith(".csv")

    scenario(body)


def test_save_cancel_leaves_no_file(tmp_path: Path) -> None:
    target = tmp_path / "never.json"

    async def body(app: OsintKitApp, pilot: Pilot[None]) -> None:
        await fill_social_diff(app, pilot)
        await pilot.click("#run")
        await wait_for(pilot, lambda: isinstance(app.screen, ResultScreen))
        await pilot.press("s")
        await pilot.pause()
        app.screen.query_one("#path", Input).value = str(target)
        await pilot.click("#cancel")
        await pilot.pause()

    scenario(body)
    assert not target.exists()


def test_save_failure_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*_args: object, **_kwargs: object) -> str:
        raise OSError("disk full")

    monkeypatch.setattr("osint_kit.tui.textual_app.write_report", explode)

    async def body(app: OsintKitApp, pilot: Pilot[None]) -> None:
        await fill_social_diff(app, pilot)
        await pilot.click("#run")
        await wait_for(pilot, lambda: isinstance(app.screen, ResultScreen))
        await pilot.press("s")
        await pilot.pause()
        app.screen.query_one("#path", Input).value = str(tmp_path / "x.md")
        await pilot.click("#save")
        await pilot.pause()
        assert isinstance(app.screen, SaveScreen)

    scenario(body)


def test_offline_refuses_a_network_plugin() -> None:
    async def runner() -> None:
        app = OsintKitApp(load_plugins(), offline=True)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.press("7")
            await pilot.pause()
            assert isinstance(app.screen, PluginFormScreen)
            assert app.screen.plugin.network
            await pilot.click("#run")
            await pilot.pause()
            assert isinstance(app.screen, PluginFormScreen)
            message = str(app.screen.query_one("#error", Static).render())
            assert "offline" in message.lower()
            assert not isinstance(app.screen, ConsentScreen)

    asyncio.run(runner())


def test_network_plugin_asks_before_running() -> None:
    async def body(app: OsintKitApp, pilot: Pilot[None]) -> None:
        await pilot.press("7")
        await pilot.pause()
        form = app.screen
        assert isinstance(form, PluginFormScreen)
        form.query_one("#field-target", Input).value = "example.com"
        await pilot.click("#run")
        await pilot.pause()
        assert isinstance(app.screen, ConsentScreen)
        await pilot.press("escape")
        await pilot.pause()
        assert isinstance(app.screen, PluginFormScreen)

    scenario(body)


def test_group_select_shows_only_the_chosen_row() -> None:
    async def body(app: OsintKitApp, pilot: Pilot[None]) -> None:
        await pilot.press("5")
        await pilot.pause()
        form = app.screen
        assert isinstance(form, PluginFormScreen)
        assert form.plugin.name == "hashing"
        for dest in ("text", "file"):
            assert form.query_one(f"#row-{dest}").display is False
        form.query_one("#group-file_text", Select).value = "file"
        await pilot.pause()
        assert form.query_one("#row-file").display is True
        assert form.query_one("#row-text").display is False

    scenario(body)


def test_detected_export_does_not_break_the_form() -> None:
    candidate = ExportCandidate(
        folder=HTML,
        followers=(HTML / "followers_1.html", HTML / "followers_2.html"),
        following=HTML / "following.html",
    )

    async def runner() -> None:
        app = OsintKitApp(load_plugins(), exports=[candidate])
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.press("1")
            await pilot.pause()
            form = app.screen
            assert isinstance(form, PluginFormScreen)
            followers = form.query_one("#field-followers", Input).value
            assert "followers_1.html" in followers
            assert "followers_2.html" in followers
            assert form.query_one("#field-following", Input).value.endswith("following.html")

    asyncio.run(runner())


def test_run_fullscreen_builds_the_app(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_run(self: OsintKitApp) -> None:
        seen["app"] = self

    monkeypatch.setattr(OsintKitApp, "run", fake_run)
    assert textual_app.run_fullscreen(load_plugins()) == 0
    assert isinstance(seen["app"], OsintKitApp)
