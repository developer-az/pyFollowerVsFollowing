"""Markdown rendering for reports."""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from osint_kit.core.models import Finding, Report


def _escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _details(finding: Finding) -> str:
    if not finding.details:
        return ""
    compact = json.dumps(finding.details, sort_keys=True, ensure_ascii=False, default=str)
    if len(compact) > 160:
        compact = compact[:157] + "..."
    return f"`{compact}`"


def render_markdown(report: Report) -> str:
    """Render a report as GitHub-flavoured Markdown."""
    lines: list[str] = []
    lines.append(f"# osint-kit report: {report.plugin}")
    lines.append("")
    lines.append(f"- **Target:** {report.target}")
    lines.append(f"- **Generated:** {report.generated_at.isoformat()}")
    for key, value in sorted(report.metadata.items()):
        lines.append(f"- **{_escape(key)}:** {_escape(str(value))}")
    lines.append("")

    if report.stats:
        lines.append("## Summary")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("| --- | ---: |")
        for key, value in report.stats.items():
            lines.append(f"| {_escape(key)} | {value} |")
        lines.append("")

    lines.append(f"## Findings ({len(report.findings)})")
    lines.append("")
    if not report.findings:
        lines.append("_No findings._")
        lines.append("")
        return "\n".join(lines)

    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in report.findings:
        grouped[finding.category].append(finding)

    for category in sorted(grouped):
        findings = grouped[category]
        lines.append(f"### {category} ({len(findings)})")
        lines.append("")
        lines.append("| Subject | Severity | Summary | Details |")
        lines.append("| --- | --- | --- | --- |")
        for finding in findings:
            lines.append(
                f"| {_escape(finding.subject)} | {finding.severity.value} | {_escape(finding.summary)} | {_details(finding)} |"
            )
        lines.append("")
    return "\n".join(lines)


def to_plain(value: Any) -> Any:
    """Best-effort JSON-safe conversion for report metadata."""
    if isinstance(value, dict):
        return {str(key): to_plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_plain(item) for item in value]
    return value
