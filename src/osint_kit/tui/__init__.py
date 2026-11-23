"""Interactive terminal front ends for the toolkit.

Two surfaces, one engine:

* **Full-screen app** (``textual``) for a real terminal: navigable list, form
  widgets, results table, save dialog.
* **Guided menu** for everything else: piped input, CI, terminals where
  ``textual`` is not installed, and ``--plain``.

``osint-kit`` with no command picks the full-screen app when the terminal
supports it and falls back to the menu otherwise.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Mapping
from typing import Literal, TextIO

from rich.console import Console

from osint_kit.core.plugin import Plugin, PluginContext
from osint_kit.core.registry import load_plugins
from osint_kit.tui.app import TuiApp
from osint_kit.tui.detect import find_exports
from osint_kit.tui.prompt import Choice, Prompter, RichPrompter

Mode = Literal["auto", "fullscreen", "menu"]


def fullscreen_available(console: Console | None = None) -> bool:
    """Whether the full-screen app can run here."""
    if console is not None:
        if not console.is_terminal:
            return False
    elif not sys.stdout.isatty():
        return False
    if not sys.stdin.isatty():
        return False
    try:
        import textual  # noqa: F401
    except ImportError:
        return False
    return True


def run(
    *,
    registry: Mapping[str, Plugin] | None = None,
    console: Console | None = None,
    prompter: Prompter | None = None,
    offline: bool = False,
    stderr: TextIO | None = None,
    discover_exports: bool = True,
    mode: Mode = "auto",
) -> int:
    """Start an interactive session. Returns a process exit code."""
    plugins = registry if registry is not None else load_plugins()
    exports = find_exports() if discover_exports else []
    use_fullscreen = prompter is None and (
        mode == "fullscreen" or (mode == "auto" and fullscreen_available(console))
    )
    if use_fullscreen:
        from osint_kit.tui.textual_app import run_fullscreen

        return run_fullscreen(plugins, offline=offline, exports=exports, stderr=stderr)
    out = console if console is not None else Console()
    return TuiApp(
        registry=plugins,
        prompter=prompter if prompter is not None else RichPrompter(out),
        console=out,
        offline=offline,
        context_factory=_context_factory(offline, stderr),
        exports=exports,
    ).run()


def _context_factory(offline: bool, stderr: TextIO | None) -> Callable[[], PluginContext]:
    if stderr is None:
        return lambda: PluginContext(offline=offline)

    def make() -> PluginContext:
        return PluginContext(offline=offline, stderr=stderr)

    return make


__all__ = [
    "Choice",
    "Mode",
    "Prompter",
    "RichPrompter",
    "TuiApp",
    "fullscreen_available",
    "run",
]
