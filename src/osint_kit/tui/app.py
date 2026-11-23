"""Interactive session: a menu, a guided form per plugin, and the result.

The flow never re-implements a plugin: it asks for the inputs the plugin's own
parser declares, hands the answers back through that parser, and then calls the
same ``plugin.run`` the command line calls.
"""

from __future__ import annotations

import argparse
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from osint_kit import __version__
from osint_kit.core.errors import OsintKitError
from osint_kit.core.models import Report
from osint_kit.core.plugin import Plugin, PluginContext
from osint_kit.report import render_table, write_report
from osint_kit.tui.copy import FieldCopy, field_copy, group_copy, tagline
from osint_kit.tui.detect import ExportCandidate
from osint_kit.tui.fields import Answer, Field, iter_fields
from osint_kit.tui.prompt import Choice, Prompter
from osint_kit.tui.runner import execute, plugin_parser, prepare

PRIORITY = ("social_diff",)
SAVE_FORMATS: tuple[tuple[str, str, str], ...] = (
    ("md", "Markdown (.md)", "md"),
    ("json", "JSON (.json)", "json"),
    ("csv", "CSV (.csv)", "csv"),
)
_SEVERITY_ORDER = ("high", "medium", "low", "info")


@dataclass
class TuiApp:
    """One interactive session. Pure wiring; all questions go through ``prompter``."""

    registry: Mapping[str, Plugin]
    prompter: Prompter
    console: Console
    offline: bool = False
    context_factory: Callable[[], PluginContext] = PluginContext
    exports: list[ExportCandidate] = field(default_factory=list)

    def run(self) -> int:
        """Run until the user quits. Returns a process exit code."""
        try:
            self._menu()
        except KeyboardInterrupt:
            self.console.print()
            self.console.print("[dim]Interrupted.[/dim]")
            return 130
        except EOFError:
            self.console.print()
            self.console.print("[dim]Input closed.[/dim]")
            return 1
        self.console.print("[dim]Bye.[/dim]")
        return 0

    # ----------------------------------------------------------------- screens

    def _banner(self) -> None:
        self.console.print(
            Panel(
                "[bold]osint-kit[/bold] [dim]v"
                f"{__version__}[/dim]\n"
                "Passive, lawful OSINT on data you own or public data you name.\n"
                "[dim]No logins, no scraping behind auth, no rate-limit bypass.[/dim]",
                border_style="cyan",
            )
        )

    def _ordered(self) -> list[Plugin]:
        plugins = list(self.registry.values())
        return sorted(
            plugins,
            key=lambda p: (
                0 if p.name in PRIORITY else 1,
                PRIORITY.index(p.name) if p.name in PRIORITY else 0,
                p.name,
            ),
        )

    def _menu(self) -> None:
        self._banner()
        plugins = self._ordered()
        while True:
            choices = [
                Choice(
                    str(index),
                    plugin.name,
                    f"start here. {tagline(plugin.name)}"
                    if index == 1 and plugin.name in PRIORITY
                    else tagline(plugin.name),
                )
                for index, plugin in enumerate(plugins, start=1)
            ]
            choices.append(Choice("q", "Quit"))
            picked = self.prompter.choice("What do you want to do?", choices, default="q")
            if picked == "q":
                return
            if self._plugin_flow(plugins[int(picked) - 1]):
                return

    def _plugin_flow(self, plugin: Plugin) -> bool:
        """Run one plugin, then offer to save, repeat, or leave. True = quit."""
        while True:
            report = self._run_once(plugin)
            if report is None:
                return False
            action = self._after_report(plugin, report)
            if action == "again":
                continue
            return action == "quit"

    def _after_report(self, plugin: Plugin, report: Report) -> str:
        choices = [
            Choice("save", "Save this report"),
            Choice("again", f"Run {plugin.name} again"),
            Choice("back", "Back to the menu"),
            Choice("quit", "Quit"),
        ]
        while True:
            picked = self.prompter.choice("What next?", choices, default="back")
            if picked != "save":
                return picked
            self._save(plugin, report)

    # ------------------------------------------------------------------- runs

    def _run_once(self, plugin: Plugin) -> Report | None:
        self.console.print()
        self.console.print(
            Panel(
                f"[bold]{plugin.name}[/bold]\n{tagline(plugin.name)}\n[dim]{plugin.summary}[/dim]",
                title="plugin",
                border_style="cyan",
            )
        )
        if not self._network_ok(plugin):
            return None
        parser = self._parser(plugin)
        fields = iter_fields(parser)
        answers = self._ask(plugin, fields)
        options = self._parse(parser, fields, answers)
        if options is None:
            return None
        return self._execute(plugin, options)

    def _network_ok(self, plugin: Plugin) -> bool:
        if not plugin.network:
            return True
        if self.offline:
            self._error(
                "This plugin needs the network, and the session is offline.",
                "Start the session without --offline, or pick a local plugin.",
            )
            return False
        return self.prompter.confirm(
            "This sends a few read-only requests to public services. Continue?", default=True
        )

    def _parser(self, plugin: Plugin) -> argparse.ArgumentParser:
        return plugin_parser(plugin)

    def _execute(self, plugin: Plugin, options: argparse.Namespace) -> Report | None:
        ctx = self.context_factory()
        started = time.perf_counter()
        try:
            report = execute(plugin, options, ctx)
        except OsintKitError as exc:
            self._error(str(exc), "Nothing was written.")
            return None
        finally:
            ctx.close()
        self._render_report(plugin, report, time.perf_counter() - started)
        return report

    def _parse(
        self,
        parser: argparse.ArgumentParser,
        fields: Sequence[Field],
        answers: Mapping[str, Answer],
    ) -> argparse.Namespace | None:
        prepared = prepare(parser, fields, answers)
        if prepared.error is not None:
            self._error("Those inputs did not validate.", prepared.error)
            return None
        return prepared.options

    # ------------------------------------------------------------------ forms

    def _ask(self, plugin: Plugin, fields: Sequence[Field]) -> dict[str, Answer]:
        answers: dict[str, Answer] = {}
        primary = [f for f in fields if f.required or field_copy(plugin.name, f.dest).primary]
        handled: set[str] = set()
        for item in primary:
            if item.group is not None:
                if item.group in handled:
                    continue
                handled.add(item.group)
                self._ask_group(plugin, item.group, fields, answers)
                continue
            answers.update(self._ask_field(plugin, item))

        rest = [
            f
            for f in fields
            if f not in primary and not (f.group is not None and f.group in handled)
        ]
        if rest and self.prompter.confirm("Change any advanced options?", default=False):
            for item in rest:
                if item.group is not None:
                    if item.group in handled:
                        continue
                    handled.add(item.group)
                    self._ask_group(plugin, item.group, fields, answers)
                    continue
                answers.update(self._ask_field(plugin, item))
        return answers

    def _ask_group(
        self,
        plugin: Plugin,
        group: str,
        fields: Sequence[Field],
        answers: dict[str, Answer],
    ) -> None:
        members = [f for f in fields if f.group == group]
        wording = group_copy(plugin.name, group)
        choices = [
            Choice(str(i), field_copy(plugin.name, f.dest).label) for i, f in enumerate(members, 1)
        ]
        choices.append(Choice("none", wording.skip_label))
        picked = self.prompter.choice(wording.question, choices, default="none")
        if picked == "none":
            return
        answers.update(self._ask_field(plugin, members[int(picked) - 1]))

    def _ask_field(self, plugin: Plugin, item: Field) -> dict[str, Answer]:
        wording = field_copy(plugin.name, item.dest)
        if item.kind == "flag":
            return {item.dest: self.prompter.confirm(wording.label, default=False)}
        if item.kind == "choice":
            choices = [Choice(choice, choice) for choice in item.choices]
            default = item.default if item.default in item.choices else None
            return {item.dest: self.prompter.choice(wording.label, choices, default=default)}
        if item.kind in {"paths", "path"}:
            return {item.dest: self._ask_paths(plugin, item, wording)}
        if item.kind == "number":
            return {item.dest: self._ask_number(item, wording)}
        raw = self.prompter.text(
            wording.label,
            hint=wording.hint or None,
            allow_empty=not item.required,
        )
        return {item.dest: raw}

    def _ask_paths(self, plugin: Plugin, item: Field, wording: FieldCopy) -> Answer:
        if (
            plugin.name == "social_diff"
            and item.dest in {"followers", "following"}
            and self.exports
        ):
            choices = [
                Choice(
                    str(index),
                    f"Use {candidate.folder}",
                    f"{len(candidate.followers)} followers file(s), 1 following file",
                )
                for index, candidate in enumerate(self.exports, start=1)
            ]
            choices.append(Choice("other", "Type a path instead"))
            picked = self.prompter.choice(wording.label, choices, default="1")
            if picked != "other":
                candidate = self.exports[int(picked) - 1]
                if item.dest == "followers":
                    return [str(path) for path in candidate.followers]
                return [str(candidate.following)]
        raw = self.prompter.text(
            wording.label,
            hint=wording.hint or None,
            allow_empty=not item.required,
        )
        return [part for part in raw.split(";") if part] if item.many else raw

    def _ask_number(self, item: Field, wording: FieldCopy) -> Answer:
        while True:
            raw = self.prompter.text(
                wording.label,
                hint=wording.hint or None,
                default=item.default,
                allow_empty=not item.required,
            )
            if raw == "":
                return None
            try:
                return float(raw) if "." in raw else int(raw)
            except ValueError:
                self.console.print(f"[yellow]{raw!r} is not a number.[/yellow]")

    # ----------------------------------------------------------------- output

    def _render_report(self, plugin: Plugin, report: Report, elapsed: float) -> None:
        self.console.print()
        table = render_table(report, width=max(60, self.console.width))
        self.console.print(table.rstrip(), soft_wrap=True)
        counts = Counter(finding.severity.value for finding in report.findings)
        parts = [f"{counts[sev]} {sev}" for sev in _SEVERITY_ORDER if counts[sev]]
        summary = ", ".join(parts) if parts else "nothing to flag"
        total = len(report.findings)
        self.console.print(
            f"[bold]{total} finding{'s' if total != 1 else ''}[/bold] "
            f"[dim]({summary}) in {elapsed:.2f}s[/dim]"
        )
        if plugin.name == "social_diff" and total:
            self.console.print(
                "[dim]Tip: keep this export. Next month, point the older-export question at it.[/dim]"
            )

    def _save(self, plugin: Plugin, report: Report) -> None:
        choices = [Choice(key, label) for key, label, _suffix in SAVE_FORMATS]
        fmt = self.prompter.choice("Save as", choices, default="md")
        suffix = next(ext for key, _label, ext in SAVE_FORMATS if key == fmt)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        suggested = Path.cwd() / f"osint-kit-{plugin.name}-{stamp}.{suffix}"
        raw = self.prompter.text("Save to", default=str(suggested))
        path = Path(raw).expanduser()
        try:
            write_report(report, fmt=fmt, output=path)
        except OSError as exc:
            self._error(f"Could not write {path}.", str(exc))
            return
        self.console.print(Panel(f"Saved to [bold]{path}[/bold]", border_style="green"))

    def _error(self, title: str, detail: str = "") -> None:
        body = f"[bold red]{title}[/bold red]"
        if detail:
            body = f"{body}\n[dim]{detail}[/dim]"
        self.console.print()
        self.console.print(Panel(body, border_style="red", title="stopped"))


__all__ = ["SAVE_FORMATS", "TuiApp"]
