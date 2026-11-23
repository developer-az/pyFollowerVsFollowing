"""Terminal prompting.

The interactive flow talks to this module, never to ``rich`` directly, so the
whole session can be driven from tests with a scripted prompter.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from rich.console import Console


@dataclass(frozen=True)
class Choice:
    """One selectable row in a menu."""

    key: str
    label: str
    detail: str = ""


@runtime_checkable
class Prompter(Protocol):
    """Everything the interactive flow needs from a terminal."""

    def text(
        self,
        label: str,
        *,
        hint: str | None = None,
        default: str | None = None,
        allow_empty: bool = False,
    ) -> str:
        """Ask for a line of text. Empty input means the default, if any."""
        ...

    def choice(self, label: str, choices: Sequence[Choice], *, default: str | None = None) -> str:
        """Ask the user to pick one choice by number or key."""
        ...

    def confirm(self, label: str, *, default: bool = False) -> bool:
        """Ask a yes/no question."""
        ...


class RichPrompter:
    """A :class:`Prompter` backed by a rich console and real keyboard input."""

    def __init__(self, console: Console) -> None:
        self.console = console

    def text(
        self,
        label: str,
        *,
        hint: str | None = None,
        default: str | None = None,
        allow_empty: bool = False,
    ) -> str:
        self.console.print(f"[bold]{label}[/bold]")
        if hint:
            self.console.print(f"[dim]{hint}[/dim]")
        while True:
            suffix = f" [dim]\\[{default}]\\[/dim]" if default is not None else ""
            raw = self.console.input(f"[cyan]>[/cyan]{suffix} ").strip()
            if raw:
                return raw
            if default is not None:
                return default
            if allow_empty:
                return ""
            self.console.print("[yellow]Please enter a value.[/yellow]")

    def choice(self, label: str, choices: Sequence[Choice], *, default: str | None = None) -> str:
        self.console.print(f"[bold]{label}[/bold]")
        for index, option in enumerate(choices, start=1):
            line = f"  [cyan]{index}[/cyan]. {option.label}"
            if option.detail:
                line = f"{line} [dim]- {option.detail}[/dim]"
            self.console.print(line)
        if default is not None:
            self.console.print(f"[dim]Enter accepts {default}.[/dim]")
        while True:
            raw = self.console.input("[cyan]>[/cyan] ").strip().lower()
            if not raw and default is not None:
                return default
            if raw.isdigit() and 1 <= int(raw) <= len(choices):
                return choices[int(raw) - 1].key
            for option in choices:
                if raw == option.key.lower():
                    return option.key
            keys = ", ".join(option.key for option in choices)
            self.console.print(f"[yellow]Choose one of: {keys}.[/yellow]")

    def confirm(self, label: str, *, default: bool = False) -> bool:
        suffix = "[Y/n]" if default else "[y/N]"
        self.console.print(f"[bold]{label}[/bold] {suffix}")
        raw = self.console.input("[cyan]>[/cyan] ").strip().lower()
        if not raw:
            return default
        return raw in {"y", "yes"}


__all__ = ["Choice", "Prompter", "RichPrompter"]
