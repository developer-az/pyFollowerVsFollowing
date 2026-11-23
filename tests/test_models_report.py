"""Report model tests."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from osint_kit.core.models import Finding, Report, Severity
from osint_kit.report import render_csv, render_json, render_markdown, render_table


def make_report() -> Report:
    report = Report(plugin="demo", target="fixture", stats={"items": 2})
    report.add(
        category="alpha",
        subject="first",
        summary="First finding.",
        severity=Severity.HIGH,
        details={"n": 1},
        tags=("tag",),
    )
    report.add(category="beta", subject="second", summary="Second finding.")
    return report


def test_finding_rejects_empty_fields() -> None:
    with pytest.raises(ValidationError):
        Finding(category="", subject="x", summary="y")


def test_report_add_and_severity_counts() -> None:
    report = make_report()
    assert len(report.findings) == 2
    assert report.severity_counts() == {"info": 1, "low": 0, "medium": 0, "high": 1}
    assert report.findings[0].tags == ("tag",)


def test_severity_rank_orders_as_expected() -> None:
    assert Severity.HIGH.rank > Severity.MEDIUM.rank > Severity.LOW.rank > Severity.INFO.rank


def test_report_json_roundtrip_and_markdown() -> None:
    report = make_report()
    payload = json.loads(render_json(report))
    assert payload["plugin"] == "demo"
    assert payload["findings"][0]["severity"] == "high"
    assert "generated_at" in payload

    markdown = render_markdown(report)
    assert "# osint-kit report: demo" in markdown
    assert "| items | 2 |" in markdown
    assert "### alpha (1)" in markdown


def test_empty_report_renders() -> None:
    report = Report(plugin="empty", target="nothing")
    assert "_No findings._" in render_markdown(report)
    rows = render_csv(report).strip().splitlines()
    assert len(rows) == 2
    assert "no findings" in rows[1]
    assert "osint-kit - empty" in render_table(report)


def test_csv_escapes_details_into_one_cell() -> None:
    report = make_report()
    csv_text = render_csv(report)
    lines = csv_text.strip().splitlines()
    assert lines[0].startswith("plugin,target,generated_at")
    assert len(lines) == 3
    assert '""n"": 1' in lines[1]


def test_extend_and_unknown_format() -> None:
    report = Report(plugin="demo", target="x")
    report.extend(make_report().findings)
    assert len(report.findings) == 2
    from osint_kit.report import render_report

    with pytest.raises(ValueError, match="unknown format"):
        render_report(report, "yaml")
