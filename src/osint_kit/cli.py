"""Command-line interface.

``osint-kit <plugin> [plugin args] --format json|csv|md|table --output FILE``
and ``osint-kit list``. Errors are human-readable and exit non-zero.

``osint-kit`` with no command, or ``osint-kit tui``, starts the interactive
session in :mod:`osint_kit.tui` instead.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TextIO

from rich.console import Console

from osint_kit import __version__
from osint_kit.core.errors import OsintKitError, UsageError
from osint_kit.core.models import Report, Severity
from osint_kit.core.plugin import Plugin, PluginContext
from osint_kit.core.registry import by_name, load_plugins
from osint_kit.report import FORMATS, write_report


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=FORMATS,
        default="table",
        help="output format (default: table)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        metavar="FILE",
        help="write the rendered report to FILE instead of stdout",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="refuse network access; local plugins still work",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="do not read or write the HTTP response cache",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        metavar="DIR",
        help="cache directory (default: per-user cache dir)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        metavar="SECONDS",
        help="per-request timeout (default: 15)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        metavar="N",
        help="retries for transient failures (default: 2)",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=1.0,
        metavar="RPS",
        help="requests per second per host (default: 1)",
    )


def build_parser(plugins: Mapping[str, Plugin]) -> argparse.ArgumentParser:
    """Build the full CLI parser, including one subcommand per plugin."""
    parser = argparse.ArgumentParser(
        prog="osint-kit",
        description=(
            "Passive, lawful OSINT toolkit. Analyze data you own or public data "
            "you name; no authentication is attempted and no rate limit is bypassed. "
            "Run with no command for the interactive menu."
        ),
    )
    parser.add_argument("--version", action="version", version=f"osint-kit {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    list_parser = subparsers.add_parser(
        "list",
        help="list available plugins",
        description="List available plugins and whether they use the network.",
    )
    _add_common_options(list_parser)

    tui_parser = subparsers.add_parser(
        "tui",
        help="interactive menu (the same thing as running with no command)",
        description=(
            "Pick a plugin, answer a few questions, read and save the report. "
            "Uses the full-screen app when textual is installed and the terminal "
            "allows it, otherwise a line-by-line menu."
        ),
    )
    _add_common_options(tui_parser)
    tui_parser.add_argument(
        "--plain",
        action="store_true",
        help="force the line-by-line menu instead of the full-screen app",
    )

    common = argparse.ArgumentParser(add_help=False)
    _add_common_options(common)

    for name, plugin in by_name(plugins).items():
        plugin_parser = subparsers.add_parser(
            name,
            parents=[common],
            help=plugin.summary,
            description=plugin.summary,
            epilog=(
                "Network plugin: read-only public requests only."
                if plugin.network
                else "Local plugin: reads only the files you name."
            ),
        )
        plugin.configure_parser(plugin_parser)
    return parser


def list_report(plugins: Mapping[str, Plugin]) -> Report:
    """Represent the plugin registry as a report so every format works."""
    report = Report(plugin="list", target="installed plugins")
    ordered = by_name(plugins)
    report.stats["plugins"] = len(ordered)
    report.stats["network"] = sum(1 for plugin in ordered.values() if plugin.network)
    report.stats["local"] = len(ordered) - report.stats["network"]
    for name, plugin in ordered.items():
        report.add(
            category="network_plugin" if plugin.network else "local_plugin",
            subject=name,
            summary=plugin.summary,
            severity=Severity.INFO,
            details={"name": name, "network": plugin.network},
        )
    return report


def _context_from_options(options: argparse.Namespace, *, stderr: TextIO) -> PluginContext:
    return PluginContext(
        offline=options.offline,
        cache_dir=options.cache_dir,
        use_cache=not options.no_cache,
        timeout=options.timeout,
        retries=options.retries,
        rate_limit=options.rate_limit,
        stderr=stderr,
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    plugins: Mapping[str, Plugin] | None = None,
    context: PluginContext | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run the CLI. Returns a process exit code (0 success, 2 user error)."""
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    registry = (
        plugins
        if plugins is not None
        else load_plugins(warn=lambda message: print(f"osint-kit: warning: {message}", file=err))
    )
    parser = build_parser(registry)
    try:
        options = parser.parse_args(argv)
    except SystemExit as exc:  # argparse already printed usage; keep the code.
        return int(exc.code or 0)

    if options.command is None or options.command == "tui":
        from osint_kit.tui import run as run_tui

        return run_tui(
            registry=registry,
            console=Console(file=out),
            offline=getattr(options, "offline", False),
            stderr=err,
            mode="menu" if getattr(options, "plain", False) else "auto",
        )
    ctx = context if context is not None else _context_from_options(options, stderr=err)
    try:
        if options.command == "list":
            report = list_report(registry)
        else:
            plugin = registry.get(options.command)
            if plugin is None:
                raise UsageError(f"unknown plugin: {options.command}")
            if plugin.network and options.offline:
                raise UsageError(
                    f"{plugin.name} needs the network; remove --offline or use a local plugin"
                )
            if plugin.network:
                ctx.announce_network()
            if options.retries < 0:
                raise UsageError("--retries cannot be negative")
            if options.timeout <= 0:
                raise UsageError("--timeout must be positive")
            if options.rate_limit <= 0:
                raise UsageError("--rate-limit must be positive")
            report = plugin.run(options, ctx)
        write_report(report, fmt=options.format, output=options.output, stdout=out)
    except OsintKitError as exc:
        print(f"osint-kit: error: {exc}", file=err)
        return 2
    except KeyboardInterrupt:
        print("osint-kit: interrupted", file=err)
        return 130
    finally:
        if context is None:
            ctx.close()
    return 0


__all__ = ["build_parser", "list_report", "main"]
