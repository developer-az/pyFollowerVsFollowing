"""Rich table rendering for terminal output."""

from __future__ import annotations

import io

from rich import box
from rich.console import Console
from rich.table import Table

from osint_kit.core.models import Report


def render_table(report: Report, *, width: int = 120) -> str:
    """Render a report as a text table (no ANSI codes, fixed width)."""
    table = Table(
        title=f"osint-kit - {report.plugin}",
        caption=" | ".join(f"{key}={value}" for key, value in report.stats.items()) or None,
        show_lines=False,
        header_style="bold",
        box=box.ASCII,
    )
    table.add_column("Category", style="cyan", no_wrap=True)
    table.add_column("Subject", style="bold")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Summary")
    for finding in report.findings:
        severity_style = {
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }[finding.severity.value]
        table.add_row(
            finding.category,
            finding.subject,
            f"[{severity_style}]{finding.severity.value}[/{severity_style}]",
            finding.summary,
        )

    buffer = io.StringIO()
    console = Console(
        file=buffer,
        force_terminal=False,
        no_color=True,
        width=max(40, width),
        highlight=False,
    )
    console.print(table)
    if report.metadata:
        console.print(f"[dim]target:[/dim] {report.target}")
    return buffer.getvalue()
