"""Full-screen interactive app, built on textual.

Same job as :mod:`osint_kit.tui.app`, different surface: a navigable list, a
form with real inputs, a results table, and a save dialog. It reuses the form
description (:mod:`osint_kit.tui.fields`) and the answer-to-argv path
(:mod:`osint_kit.tui.runner`), so the two front ends cannot disagree.
"""

from __future__ import annotations

import argparse
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar, Literal, TextIO, cast

from textual import events
from textual.app import App, ComposeResult
from textual.binding import BindingType
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.screen import ModalScreen, Screen
from textual.theme import Theme
from textual.widget import Widget
from textual.widgets import (
    Button,
    Checkbox,
    Collapsible,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    OptionList,
    Select,
    Static,
)
from textual.widgets.option_list import Option

from osint_kit import __version__
from osint_kit.core.errors import OsintKitError
from osint_kit.core.models import Report
from osint_kit.core.plugin import Plugin, PluginContext
from osint_kit.core.registry import load_plugins
from osint_kit.report import write_report
from osint_kit.tui.copy import field_copy, group_copy, tagline
from osint_kit.tui.detect import ExportCandidate, find_exports
from osint_kit.tui.fields import Answer, Field, iter_fields
from osint_kit.tui.picker import (
    FilePickerScreen,
    Target,
    native_available,
    pick_native,
    target_for,
)
from osint_kit.tui.runner import execute, plugin_parser, prepare

SAVE_FORMATS: tuple[tuple[str, str, str], ...] = (
    ("md", "Markdown (.md)", "md"),
    ("json", "JSON (.json)", "json"),
    ("csv", "CSV (.csv)", "csv"),
)
SKIP = "__none__"
WIDGET = "field-"
SEVERITY_ORDER = ("high", "medium", "low", "info")

OSINT_THEME = Theme(
    name="osint-kit",
    primary="#006bff",
    secondary="#004eba",
    accent="#006bff",
    warning="#b45309",
    error="#b91c1c",
    success="#15803d",
    foreground="#0b3558",
    background="#f8f9fb",
    surface="#ffffff",
    panel="#f0f3f8",
    dark=False,
    text_alpha=1.0,
    luminosity_spread=0.2,
)

CSS = """
Screen {
    background: $background;
    color: $foreground;
}

ModalScreen {
    align: center middle;
    background: #0b3558 45%;
}

* {
    scrollbar-background: transparent;
    scrollbar-color: #c9d6e5;
    scrollbar-color-hover: #a6bbd1;
    scrollbar-color-active: #006bff;
    scrollbar-size-vertical: 1;
}

Header {
    background: $panel;
    color: $foreground;
}

Footer {
    background: $panel;
    color: $foreground;
}

#hero {
    height: auto;
    margin: 1 2 0 2;
    padding: 1 2;
    background: $surface;
    border: round #d4e0ed;
}

#brand {
    text-style: bold;
    color: $foreground;
}

.hint {
    color: #476788;
}

.warning {
    color: #b45309;
    text-style: bold;
}

.section {
    margin: 1 2 0 2;
    text-style: bold;
    color: $foreground;
}

#plugins {
    height: 1fr;
    margin: 1 2;
    border: round #d4e0ed;
    background: $surface;
}

OptionList {
    background: $surface;
    color: $foreground;
}

OptionList > .option-list--option {
    color: $foreground;
}

OptionList > .option-list--option-hover {
    background: #e8f1ff;
    color: $foreground;
}

OptionList > .option-list--option-highlighted {
    background: $primary;
    color: #ffffff;
    text-style: bold;
}

#plugin-title {
    text-style: bold;
    color: $foreground;
}

#form {
    height: 1fr;
    margin: 1 2 0 2;
    padding: 0 1 1 1;
    border: round #d4e0ed;
    background: $surface;
}

.field {
    height: auto;
    margin: 1 0 0 0;
}

.field-label {
    height: auto;
    color: $foreground;
}

.field > Label {
    text-style: bold;
}

.subfield {
    height: auto;
    padding-left: 2;
}

.path-row {
    height: auto;
}

.path-row Input {
    width: 1fr;
}

.path-row Button {
    width: auto;
    min-width: 0;
    margin-left: 1;
}

Input {
    border: tall #d4e0ed;
    background: #f0f3f8;
    color: $foreground;
}

Input:focus {
    border: tall $primary;
}

Input > .input--placeholder {
    color: #6b7f95;
}

Select {
    background: #f0f3f8;
    color: $foreground;
}

Collapsible {
    background: $surface;
    border: round #d4e0ed;
    margin-top: 1;
}

CollapsibleTitle {
    background: $panel;
    color: $foreground;
    text-style: bold;
    width: 1fr;
}

CollapsibleTitle:hover {
    background: #e2eaf5;
}

#error {
    height: auto;
    margin: 1 2 0 2;
    color: #b91c1c;
    text-style: bold;
}

#actions {
    height: auto;
    margin: 1 2;
    align-horizontal: right;
}

#actions Button {
    margin-left: 1;
}

#summary {
    margin: 1 2 0 2;
    color: #476788;
}

#findings {
    height: 1fr;
    margin: 1 2;
    border: round #d4e0ed;
    background: $surface;
}

DataTable > .datatable--header {
    background: $panel;
    color: $foreground;
    text-style: bold;
}

DataTable > .datatable--even-row {
    background: #f7f9fc;
}

DataTable > .datatable--cursor {
    background: #e3edff;
    color: $foreground;
}

.dialog {
    width: 76;
    height: auto;
    padding: 1 2;
    background: $surface;
    border: thick $primary;
}

.dialog Label {
    text-style: bold;
    color: $foreground;
}

.dialog Input, .dialog Select {
    margin: 0 0 1 0;
}

.dialog-actions {
    height: auto;
    align-horizontal: right;
}

.picker {
    width: 88;
    max-height: 90%;
}

.picker-title {
    text-style: bold;
    color: $foreground;
}

#picker-path {
    margin: 0 0 1 0;
    text-style: italic;
}

#picker-entries {
    height: 14;
    border: round #d4e0ed;
    background: $surface;
}

#picker-entries > .option-list--option-highlighted {
    background: $primary;
    color: #ffffff;
    text-style: bold;
}
"""


class OsintKitApp(App[None]):
    """The application shell: registry, settings, and navigation."""

    TITLE = "osint-kit"
    SUB_TITLE = f"v{__version__}"
    CSS = CSS

    def __init__(
        self,
        registry: Mapping[str, Plugin],
        *,
        offline: bool = False,
        exports: Sequence[ExportCandidate] = (),
        context_factory: Callable[[], PluginContext] = PluginContext,
    ) -> None:
        super().__init__()
        self.register_theme(OSINT_THEME)
        self.registry = registry
        self.offline = offline
        self.exports = list(exports)
        self.context_factory = context_factory

    def on_mount(self) -> None:
        self.theme = OSINT_THEME.name
        self.push_screen(PluginListScreen())

    def context(self) -> PluginContext:
        return self.context_factory()

    @property
    def ordered(self) -> list[Plugin]:
        priority = ("social_diff",)
        return sorted(
            self.registry.values(),
            key=lambda plugin: (
                0 if plugin.name in priority else 1,
                priority.index(plugin.name) if plugin.name in priority else 0,
                plugin.name,
            ),
        )

    def open_plugin(self, name: str | None) -> None:
        if name is None:
            return
        plugin = self.registry.get(name)
        if plugin is None:
            self.notify(f"Unknown plugin {name!r}", severity="error")
            return
        self.push_screen(PluginFormScreen(plugin))


# --------------------------------------------------------------------- helpers


def app_of(widget: Widget) -> OsintKitApp:
    """Typed access to the app from inside a screen."""
    return cast(OsintKitApp, widget.app)


def _slug(group: str) -> str:
    return group.replace("|", "_")


def _unselected(value: object) -> bool:
    """True for a Select's blank/NULL sentinel or the group skip key."""
    return value is Select.BLANK or value is Select.NULL or value == SKIP or value == ""


def _value(field: Field, widget: Widget) -> Answer:
    if isinstance(widget, Checkbox):
        return widget.value
    if isinstance(widget, Select):
        value = widget.value
        if _unselected(value):
            return None
        return str(value)
    if isinstance(widget, Input):
        raw = widget.value.strip()
        if not raw:
            return None
        if field.many:
            return [part.strip() for part in raw.split(";") if part.strip()]
        return raw
    return None


def _summary(report: Report, elapsed: float) -> str:
    counts = Counter(finding.severity.value for finding in report.findings)
    parts = [f"{counts[severity]} {severity}" for severity in SEVERITY_ORDER if counts[severity]]
    total = len(report.findings)
    noun = "finding" if total == 1 else "findings"
    return f"{total} {noun} ({', '.join(parts) or 'nothing to flag'}) in {elapsed:.2f}s"


# ---------------------------------------------------------------------- screens


class PluginListScreen(Screen[None]):
    """Pick a plugin; number keys work as well as arrows."""

    BINDINGS: ClassVar[list[BindingType]] = [("escape", "app.quit", "Quit")]

    def compose(self) -> ComposeResult:
        shell = app_of(self)
        yield Header()
        with Vertical(id="hero"):
            yield Static(
                "Passive, lawful OSINT on data you own or public data you name.", id="brand"
            )
            yield Static(
                "No logins, no scraping behind auth, no rate-limit bypass.",
                classes="hint",
            )
            if shell.offline:
                yield Static("Offline session: network plugins are disabled.", classes="warning")
        yield Static("What do you want to do?", classes="section")
        yield OptionList(
            *[
                Option(f"{index}. {plugin.name}  -  {tagline(plugin.name)}", id=plugin.name)
                for index, plugin in enumerate(shell.ordered, start=1)
            ],
            id="plugins",
        )
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#plugins", OptionList).focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        app_of(self).open_plugin(event.option.id)

    def on_key(self, event: events.Key) -> None:
        if event.character is None or not event.character.isdigit():
            return
        index = int(event.character)
        plugins = app_of(self).ordered
        if 1 <= index <= len(plugins):
            app_of(self).open_plugin(plugins[index - 1].name)


class PluginFormScreen(Screen[None]):
    """A form generated from the plugin's own argument parser."""

    BINDINGS: ClassVar[list[BindingType]] = [
        ("escape", "go_back", "Back"),
        ("ctrl+r", "run", "Run"),
    ]

    def __init__(self, plugin: Plugin) -> None:
        super().__init__()
        self.plugin = plugin
        self.parser = plugin_parser(plugin)
        self.fields = iter_fields(self.parser)
        self._inputs: dict[str, Widget] = {}
        self._groups: dict[str, Select[str]] = {}
        self._options: argparse.Namespace | None = None

    # ---------------------------------------------------------------- layout

    def _primary(self) -> list[Field]:
        return [
            field
            for field in self.fields
            if field.required or field_copy(self.plugin.name, field.dest).primary
        ]

    def _advanced(self, primary: Sequence[Field]) -> list[Field]:
        return [field for field in self.fields if field not in primary]

    def compose(self) -> ComposeResult:
        primary = self._primary()
        yield Header()
        with Vertical(id="hero"):
            yield Static(self.plugin.name, id="plugin-title")
            yield Static(tagline(self.plugin.name), classes="hint")
            yield Static(self.plugin.summary, classes="hint")
        with VerticalScroll(id="form"):
            seen: set[str] = set()
            for field in primary:
                if field.group is not None:
                    if field.group in seen:
                        continue
                    seen.add(field.group)
                    yield from self._group_block(field.group)
                    continue
                yield from self._field_block(field)
            advanced = self._advanced(primary)
            if advanced:
                with Collapsible(title="Advanced options", collapsed=True, id="advanced"):
                    for field in advanced:
                        if field.group is not None:
                            if field.group in seen:
                                continue
                            seen.add(field.group)
                            yield from self._group_block(field.group)
                            continue
                        yield from self._field_block(field)
        yield Static("", id="error")
        with Horizontal(id="actions"):
            yield Button("Run", id="run", variant="primary")
            yield Button("Back", id="back")
        yield Footer()

    def _field_block(self, field: Field, *, bare: bool = False) -> ComposeResult:
        wording = field_copy(self.plugin.name, field.dest)
        widget = self._widget(field, compact=bare)
        if bare:
            yield widget
            return
        line = f"[bold]{wording.label}[/bold]"
        if wording.hint:
            line = f"{line}  [dim]{wording.hint}[/dim]"
        with Vertical(classes="field"):
            yield Static(line, classes="field-label")
            yield widget

    def _group_block(self, group: str) -> ComposeResult:
        members = [field for field in self.fields if field.group == group]
        wording = group_copy(self.plugin.name, group)
        options = [
            (field_copy(self.plugin.name, field.dest).label, field.dest) for field in members
        ]
        options.append((wording.skip_label, SKIP))
        with Vertical(classes="field"):
            yield Label(wording.question)
            yield Select[str](
                options,
                prompt="Choose one",
                value=SKIP,
                allow_blank=False,
                id=f"group-{_slug(group)}",
            )
            for field in members:
                with Vertical(classes="subfield", id=f"row-{field.dest}"):
                    yield from self._field_block(field, bare=True)

    def _widget(self, field: Field, *, compact: bool = False) -> Widget:
        wording = field_copy(self.plugin.name, field.dest)
        widget_id = f"{WIDGET}{field.dest}"
        if field.kind == "choice":
            options = [(choice, choice) for choice in field.choices]
            extra: dict[str, Any] = {}
            if field.default is not None and field.default in field.choices:
                extra["value"] = field.default
            return Select[str](
                options,
                prompt=wording.label,
                allow_blank=not field.required,
                id=widget_id,
                **extra,
            )
        if field.kind == "flag":
            return Checkbox(wording.label, value=False, id=widget_id)
        hint = ""
        if compact:
            hint = wording.hint
            if field.many:
                hint = f"{hint} Separate several paths with ;".strip()
        placeholder = hint if compact else wording.example
        input_type: Literal["number", "text"] = "number" if field.kind == "number" else "text"
        box = Input(
            placeholder=placeholder,
            value=field.default or "",
            type=input_type,
            id=widget_id,
        )
        target = target_for(self.plugin.name, field)
        if target is None:
            return box
        buttons: list[Widget] = [Button("Browse…", id=f"browse-{field.dest}")]
        if target.folder_ok:
            buttons.append(Button("Folder…", id=f"browse-folder-{field.dest}"))
        return Horizontal(box, *buttons, classes="path-row")

    def on_mount(self) -> None:
        for field in self.fields:
            try:
                self._inputs[field.dest] = self.query_one(f"#{WIDGET}{field.dest}")
            except NoMatches:  # pragma: no cover - every field is composed
                continue
            if field.group is not None:
                self.query_one(f"#row-{field.dest}").display = False
        for group in {field.group for field in self.fields if field.group}:
            self._groups[group] = self.query_one(f"#group-{_slug(group)}", Select)
        self._prefill_from_export()
        focus = self._first_input()
        if focus is not None:
            focus.focus()

    def _prefill_from_export(self) -> None:
        """Fill the export questions from a folder found on disk."""
        app = app_of(self)
        if self.plugin.name != "social_diff" or not app.exports:
            return
        candidate = app.exports[0]
        followers = self._inputs.get("followers")
        following = self._inputs.get("following")
        if isinstance(followers, Input) and not followers.value:
            followers.value = "; ".join(str(path) for path in candidate.followers)
        if isinstance(following, Input) and not following.value:
            following.value = str(candidate.following)
        app.notify(f"Prefilled from {candidate.folder}", timeout=5)

    def _first_input(self) -> Widget | None:
        for field in self._primary():
            if field.group is not None:
                return self._groups.get(field.group)
            widget = self._inputs.get(field.dest)
            if widget is not None:
                return widget
        return None

    # ---------------------------------------------------------------- events

    def on_select_changed(self, event: Select.Changed) -> None:
        select_id = event.select.id or ""
        if not select_id.startswith("group-"):
            return
        for group in self._groups:
            if f"group-{_slug(group)}" != select_id:
                continue
            for field in self.fields:
                if field.group != group:
                    continue
                row = self.query_one(f"#row-{field.dest}")
                row.display = event.value == field.dest

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id == "run":
            self.action_run()
        elif button_id == "back":
            self.action_go_back()
        elif button_id.startswith("browse-"):
            self._browse(button_id)

    # ---------------------------------------------------------------- browsing

    def _browse_field(self, button_id: str) -> tuple[Field, bool] | None:
        """The field a Browse button belongs to, and whether it wants a folder."""
        for prefix, folder in (("browse-folder-", True), ("browse-", False)):
            if not button_id.startswith(prefix):
                continue
            dest = button_id[len(prefix) :]
            field = next((item for item in self.fields if item.dest == dest), None)
            if field is not None:
                return field, folder
        return None

    def _browse(self, button_id: str) -> None:
        found = self._browse_field(button_id)
        if found is None:  # pragma: no cover - a button always names a field
            return
        field, folder = found
        target = target_for(self.plugin.name, field)
        if target is None:  # pragma: no cover - the button implies a target
            return
        start = self._start_from(field)
        if native_available():
            self._native_browse(field, target, folder, start)
            return
        self._open_picker(field, target, start)

    def _start_from(self, field: Field) -> Path | None:
        """Open the picker where the field already points, if it points anywhere."""
        widget = self._inputs.get(field.dest)
        if not isinstance(widget, Input):
            return None
        raw = widget.value.split(";")[0].strip()
        return Path(raw).expanduser() if raw else None

    def _native_browse(
        self, field: Field, target: Target, folder: bool, start: Path | None
    ) -> None:
        """Ask the operating system for a path without blocking the UI."""

        def pick() -> None:
            try:
                chosen = pick_native(target, folder=folder, multiple=field.many, start=start)
            except Exception:  # pragma: no cover - broken Tcl install, or no desktop
                self.app.call_from_thread(self._open_picker, field, target, start)
                return
            self.app.call_from_thread(self._apply_picked, field, chosen)

        self.run_worker(pick, thread=True, group="browse", exclusive=True)

    def _open_picker(self, field: Field, target: Target, start: Path | None) -> None:
        screen = FilePickerScreen(target, start=start)
        app_of(self).push_screen(screen, callback=lambda chosen: self._apply_picked(field, chosen))

    def _apply_picked(self, field: Field, chosen: tuple[Path, ...] | None) -> None:
        """Write what was picked into the field, keeping earlier picks."""
        if not chosen:
            return
        widget = self._inputs.get(field.dest)
        if not isinstance(widget, Input):
            return  # pragma: no cover - Browse only sits beside an Input
        picked = [str(path) for path in chosen]
        if field.many and not any(path.is_dir() for path in chosen):
            current = [part.strip() for part in widget.value.split(";") if part.strip()]
            merged = current + [item for item in picked if item not in current]
            widget.value = "; ".join(merged)
        else:
            widget.value = picked[0]
        widget.focus()

    def action_go_back(self) -> None:
        self.dismiss()

    def action_run(self) -> None:
        self._clear_error()
        if self.plugin.network and app_of(self).offline:
            self._show_error(
                "This plugin needs the network and the session is offline. "
                "Restart without --offline, or pick a local plugin."
            )
            return
        prepared = prepare(self.parser, self.fields, self._answers())
        if prepared.error is not None or prepared.options is None:
            self._show_error(prepared.error or "Those inputs did not validate.")
            return
        self._options = prepared.options
        if self.plugin.network:
            app_of(self).push_screen(ConsentScreen(self.plugin.name), callback=self._after_consent)
            return
        self._start()

    def _after_consent(self, allowed: bool | None) -> None:
        if allowed:
            self._start()

    # ------------------------------------------------------------------- run

    def _answers(self) -> dict[str, Answer]:
        answers: dict[str, Answer] = {}
        grouped = {field.dest for field in self.fields if field.group is not None}
        for field in self.fields:
            if field.dest in grouped:
                continue
            widget = self._inputs.get(field.dest)
            if widget is not None:
                answers[field.dest] = _value(field, widget)
        for select in self._groups.values():
            chosen = select.value
            if _unselected(chosen):
                continue
            dest = str(chosen)
            member = next((item for item in self.fields if item.dest == dest), None)
            widget = self._inputs.get(dest)
            if member is not None and widget is not None:
                answers[dest] = _value(member, widget)
        return answers

    def _start(self) -> None:
        if self._options is None:  # pragma: no cover - guarded by action_run
            return
        self._set_busy(True)
        self.run_worker(self._work, thread=True, exclusive=True, group="run")

    def _work(self) -> None:
        options = self._options
        if options is None:  # pragma: no cover - guarded by _start
            return
        ctx = app_of(self).context()
        started = time.perf_counter()
        report: Report | None = None
        error: str | None = None
        try:
            report = execute(self.plugin, options, ctx)
        except OsintKitError as exc:
            error = str(exc)
        finally:
            ctx.close()
        elapsed = time.perf_counter() - started
        self.app.call_from_thread(self._finish, report, error, elapsed)

    def _finish(self, report: Report | None, error: str | None, elapsed: float) -> None:
        self._set_busy(False)
        if error is not None:
            self._show_error(error)
            return
        if report is None:  # pragma: no cover - execute always returns or raises
            return
        app_of(self).push_screen(ResultScreen(self.plugin, report, elapsed))

    def _set_busy(self, busy: bool) -> None:
        button = self.query_one("#run", Button)
        button.disabled = busy
        button.label = "Running..." if busy else "Run"

    def _show_error(self, message: str) -> None:
        self.query_one("#error", Static).update(message)

    def _clear_error(self) -> None:
        self.query_one("#error", Static).update("")


class ResultScreen(Screen[None]):
    """Findings, then save, repeat, or go back."""

    BINDINGS: ClassVar[list[BindingType]] = [
        ("s", "save", "Save"),
        ("r", "again", "Run again"),
        ("escape", "back", "Menu"),
    ]

    def __init__(self, plugin: Plugin, report: Report, elapsed: float) -> None:
        super().__init__()
        self.plugin = plugin
        self.report = report
        self.elapsed = elapsed

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="hero"):
            yield Static(f"{self.plugin.name} result", id="plugin-title")
            yield Static(_summary(self.report, self.elapsed), id="summary")
        yield DataTable(id="findings", cursor_type="row", zebra_stripes=True)
        with Horizontal(id="actions"):
            yield Button("Save", id="save", variant="primary")
            yield Button("Run again", id="again")
            yield Button("Menu", id="back")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#findings", DataTable)
        table.add_columns("Category", "Subject", "Severity", "Summary")
        for finding in self.report.findings:
            table.add_row(
                finding.category,
                finding.subject,
                finding.severity.value,
                finding.summary,
            )
        table.focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save":
            self.action_save()
        elif event.button.id == "again":
            self.action_again()
        elif event.button.id == "back":
            self.action_back()

    def action_save(self) -> None:
        app_of(self).push_screen(SaveScreen(self.plugin, self.report))

    def action_again(self) -> None:
        self.dismiss()

    def action_back(self) -> None:
        app = app_of(self)
        app.pop_screen()
        app.pop_screen()


class SaveScreen(ModalScreen[Path | None]):
    """Pick a format and a destination."""

    BINDINGS: ClassVar[list[BindingType]] = [("escape", "cancel", "Cancel")]

    def __init__(self, plugin: Plugin, report: Report) -> None:
        super().__init__()
        self.plugin = plugin
        self.report = report
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.stem = f"osint-kit-{plugin.name}-{stamp}"

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Label("Save this report")
            yield Static("Format", classes="hint")
            yield Select[str](
                [(label, key) for key, label, _ext in SAVE_FORMATS],
                value="md",
                allow_blank=False,
                id="format",
            )
            yield Static("Path", classes="hint")
            yield Input(value=f"{self.stem}.md", id="path")
            with Horizontal(classes="dialog-actions"):
                yield Button("Save", id="save", variant="primary")
                yield Button("Cancel", id="cancel")

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id != "format":
            return
        suffix = next(ext for key, _label, ext in SAVE_FORMATS if key == event.value)
        path_input = self.query_one("#path", Input)
        path_input.value = f"{path_input.value.rsplit('.', 1)[0]}.{suffix}"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.action_cancel()
        elif event.button.id == "save":
            self._write()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _write(self) -> None:
        fmt = str(self.query_one("#format", Select).value)
        target = Path(self.query_one("#path", Input).value).expanduser()
        try:
            write_report(self.report, fmt=fmt, output=target)
        except OSError as exc:
            self.notify(f"Could not write {target}: {exc}", severity="error")
            return
        self.notify(f"Saved to {target}", title="osint-kit")
        self.dismiss(target)


class ConsentScreen(ModalScreen[bool]):
    """Ask before a plugin sends requests."""

    BINDINGS: ClassVar[list[BindingType]] = [("escape", "decline", "Cancel")]

    def __init__(self, plugin_name: str) -> None:
        super().__init__()
        self.plugin_name = plugin_name

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Label(f"Run {self.plugin_name}?")
            yield Static(
                "This sends a few read-only requests to public services, one at a "
                "time, within their robots and rate limits.",
                classes="hint",
            )
            with Horizontal(classes="dialog-actions"):
                yield Button("Continue", id="continue", variant="primary")
                yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "continue")

    def action_decline(self) -> None:
        self.dismiss(False)


def run_fullscreen(
    registry: Mapping[str, Plugin],
    *,
    offline: bool = False,
    exports: Sequence[ExportCandidate] = (),
    stderr: TextIO | None = None,
) -> int:
    """Run the full-screen app until the user quits."""
    factory: Callable[[], PluginContext]
    if stderr is None:
        factory = PluginContext
    else:

        def _make() -> PluginContext:
            return PluginContext(offline=offline, stderr=stderr)

        factory = _make

    app = OsintKitApp(registry, offline=offline, exports=exports, context_factory=factory)
    app.run()
    return 0


def run(registry: Mapping[str, Plugin] | None = None, *, offline: bool = False) -> int:
    """Convenience entry point used by ``osint-kit tui``."""
    plugins = registry if registry is not None else load_plugins()
    return run_fullscreen(plugins, offline=offline, exports=find_exports())


__all__ = [
    "ConsentScreen",
    "OsintKitApp",
    "PluginFormScreen",
    "PluginListScreen",
    "ResultScreen",
    "SaveScreen",
    "run",
    "run_fullscreen",
]
