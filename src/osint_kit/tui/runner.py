"""Shared plumbing between the two front ends.

Both the guided menu and the full-screen app turn answers into a plugin call
the same way: render the answers as argv, let the plugin's own parser validate
and convert them, then call ``plugin.run``. Keeping that here means neither
front end can drift from the CLI.
"""

from __future__ import annotations

import argparse
import contextlib
import io
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from osint_kit.core.models import Report
from osint_kit.core.plugin import Plugin, PluginContext
from osint_kit.tui.fields import Answer, Field, to_argv


@dataclass(frozen=True)
class Prepared:
    """Either a namespace ready for ``plugin.run`` or the reason it was not."""

    options: argparse.Namespace | None = None
    error: str | None = None

    def __bool__(self) -> bool:
        return self.options is not None


def plugin_parser(plugin: Plugin) -> argparse.ArgumentParser:
    """The plugin's own parser, without help or the shared network options."""
    parser = argparse.ArgumentParser(prog=f"osint-kit {plugin.name}", add_help=False)
    plugin.configure_parser(parser)
    return parser


def prepare(
    parser: argparse.ArgumentParser, fields: Sequence[Field], answers: Mapping[str, Answer]
) -> Prepared:
    """Turn form answers into a validated namespace."""
    argv = to_argv(fields, answers)
    problem = io.StringIO()
    with contextlib.redirect_stderr(problem):
        try:
            options, _unknown = parser.parse_known_args(argv)
        except SystemExit:
            message = "\n".join(
                line
                for line in problem.getvalue().splitlines()
                if line and not line.startswith("usage:")
            )
            return Prepared(error=message or "those inputs did not validate")
    return Prepared(options=options)


def execute(plugin: Plugin, options: argparse.Namespace, ctx: PluginContext) -> Report:
    """Run the plugin, announcing network use first when it applies."""
    if plugin.network:
        ctx.announce_network()
    return plugin.run(options, ctx)


__all__ = ["Prepared", "execute", "plugin_parser", "prepare"]
