"""Report renderers: JSON, CSV, Markdown, and a rich table."""

from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path
from typing import TextIO

from osint_kit.core.models import Report
from osint_kit.report.markdown import render_markdown
from osint_kit.report.table import render_table

FORMATS: tuple[str, ...] = ("json", "csv", "md", "table")

_CSV_COLUMNS = (
    "plugin",
    "target",
    "generated_at",
    "category",
    "subject",
    "severity",
    "summary",
    "details",
    "tags",
)


def render_json(report: Report) -> str:
    """Stable, UTF-8-friendly JSON."""
    payload = report.model_dump(mode="json")
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def render_csv(report: Report) -> str:
    """One row per finding; details stay JSON-encoded in a single cell."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_CSV_COLUMNS)
    writer.writeheader()
    generated = report.generated_at.isoformat()
    if not report.findings:
        writer.writerow(
            {
                "plugin": report.plugin,
                "target": report.target,
                "generated_at": generated,
                "category": "",
                "subject": "",
                "severity": "",
                "summary": "no findings",
                "details": "",
                "tags": "",
            }
        )
        return buffer.getvalue()
    for finding in report.findings:
        writer.writerow(
            {
                "plugin": report.plugin,
                "target": report.target,
                "generated_at": generated,
                "category": finding.category,
                "subject": finding.subject,
                "severity": finding.severity.value,
                "summary": finding.summary,
                "details": json.dumps(finding.details, sort_keys=True, ensure_ascii=False),
                "tags": ",".join(finding.tags),
            }
        )
    return buffer.getvalue()


def render_report(report: Report, fmt: str) -> str:
    """Dispatch by format name; raises ``ValueError`` for unknown formats."""
    if fmt == "json":
        return render_json(report)
    if fmt == "csv":
        return render_csv(report)
    if fmt == "md":
        return render_markdown(report)
    if fmt == "table":
        return render_table(report)
    raise ValueError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}")


def write_report(
    report: Report,
    *,
    fmt: str,
    output: Path | None = None,
    stdout: TextIO = sys.stdout,
) -> str:
    """Render and write a report, returning the rendered text."""
    text = render_report(report, fmt)
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
    else:
        payload = text if text.endswith("\n") else text + "\n"
        try:
            stdout.write(payload)
        except UnicodeEncodeError:
            # Legacy Windows consoles default to cp1252; never lose the report.
            encoding = getattr(stdout, "encoding", None) or "utf-8"
            stdout.write(payload.encode(encoding, errors="replace").decode(encoding))
    return text


__all__ = [
    "FORMATS",
    "render_csv",
    "render_json",
    "render_markdown",
    "render_report",
    "render_table",
    "write_report",
]
