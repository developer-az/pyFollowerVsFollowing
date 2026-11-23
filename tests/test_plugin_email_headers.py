"""email_headers: hop parsing, latency, auth results, and flags."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from osint_kit.plugins.email_headers import (
    EmailHeadersPlugin,
    analyze_headers,
    domain_of,
    parse_auth_results,
    parse_headers,
    parse_received,
    spf_from_received_spf,
)
from tests.conftest import read_text


def test_parse_received_full(sample_received: dict[str, str]) -> None:
    hop = parse_received(sample_received["newest"], position=0)
    assert hop.from_host == "mx.example.org"
    assert hop.by_host == "inbox.example.com"
    assert hop.protocol == "ESMTPS"
    assert hop.ip == "203.0.113.20"
    assert hop.timestamp == datetime(2025, 11, 1, 12, 0, 3, tzinfo=UTC)
    assert hop.raw.startswith("from mx.example.org")


def test_parse_received_without_date_or_by() -> None:
    hop = parse_received("from unknown (unknown [192.0.2.1])", position=3)
    assert hop.from_host == "unknown"
    assert hop.by_host is None
    assert hop.timestamp is None
    assert hop.ip == "192.0.2.1"
    assert hop.position == 3


def test_parse_headers_preserves_multiple_values() -> None:
    headers = parse_headers("Received: a\nReceived: b\nFrom: x@y\n\nbody")
    assert headers.received == ("a", "b")
    assert headers.from_value == "x@y"
    assert "Received" in headers.raw_header_names


def test_clean_headers_analysis() -> None:
    analysis = analyze_headers(read_text("emails/clean_headers.eml"))
    assert len(analysis.hops) == 3
    assert analysis.latencies == (None, 2.0, 1.0)
    assert analysis.auth == (
        ("spf", "pass"),
        ("dkim", "pass"),
        ("dmarc", "pass"),
    )
    assert analysis.from_domain == "news.example.org"
    assert analysis.return_path_domain == "esp.example.net"
    assert analysis.from_mismatch is True
    assert analysis.order_suspicious is False
    assert analysis.chain_breaks == ()
    assert analysis.missing == ()


def test_suspicious_headers_analysis() -> None:
    analysis = analyze_headers(read_text("emails/suspicious_headers.eml"))
    assert analysis.order_suspicious is True
    assert analysis.chain_breaks == (
        "hop 1 was received by mx.third.example, but hop 2 claims to come from sender.example.net",
    )
    assert ("spf", "fail") in analysis.auth
    assert ("dkim", "none") in analysis.auth
    assert ("dmarc", "fail") in analysis.auth


def test_missing_headers_are_reported() -> None:
    analysis = analyze_headers("From: a@example.com\nSubject: hi\n\nbody")
    assert set(analysis.missing) == {"Date", "Message-ID", "Return-Path"}


def test_parse_auth_results_multiple_headers() -> None:
    results = parse_auth_results(
        ["mx.example; spf=Pass smtp.mailfrom=x; dkim=fail", "other; dmarc=bestguesspass"]
    )
    assert results == (("spf", "pass"), ("dkim", "fail"), ("dmarc", "bestguesspass"))


def test_spf_from_received_spf() -> None:
    assert spf_from_received_spf(["Pass (domain of x)", "fail"]) == "pass"
    assert spf_from_received_spf(["   "]) is None
    assert spf_from_received_spf([]) is None


def test_domain_of_variants() -> None:
    assert domain_of('"Name" <user@Example.COM>') == "example.com"
    assert domain_of("user@example.com") == "example.com"
    assert domain_of("<>") is None
    assert domain_of(None) is None
    assert domain_of("no-at-sign") is None


def test_plugin_reports_hops_and_flags(context_factory: Any) -> None:
    ctx = context_factory()
    options = argparse.Namespace(
        headers=Path("tests/fixtures/emails/clean_headers.eml"),
        no_hop_findings=False,
    )
    report = EmailHeadersPlugin().run(options, ctx)
    assert report.stats["hops"] == 3
    hop_findings = [finding for finding in report.findings if finding.category == "hop"]
    assert len(hop_findings) == 3
    assert hop_findings[0].details["latency_seconds"] is None
    assert report.metadata["subject"] == "Synthetic header fixture"
    auth = {
        finding.subject: finding.summary
        for finding in report.findings
        if finding.category == "authentication"
    }
    assert auth["spf"].endswith("pass")
    assert any(finding.category == "identity" for finding in report.findings)


def test_plugin_suspicious_and_no_hop_findings(context_factory: Any) -> None:
    ctx = context_factory()
    options = argparse.Namespace(
        headers=Path("tests/fixtures/emails/suspicious_headers.eml"),
        no_hop_findings=True,
    )
    report = EmailHeadersPlugin().run(options, ctx)
    assert not any(finding.category == "hop" for finding in report.findings)
    routing = [finding for finding in report.findings if finding.category == "routing"]
    assert any("contradict" in finding.summary for finding in routing)
    high = [finding for finding in report.findings if finding.severity.value == "high"]
    assert high, "failed SPF/DMARC should be high severity"


def test_plugin_without_auth_headers(context_factory: Any, tmp_path: Any) -> None:
    headers_file = tmp_path / "plain.eml"
    headers_file.write_text(
        "From: a@example.com\nReturn-Path: <a@example.com>\nDate: Tue, 1 Nov 2025 12:00:00 +0000\n"
        "Message-ID: <x@example.com>\n\nbody",
        encoding="utf-8",
    )
    ctx = context_factory()
    report = EmailHeadersPlugin().run(
        argparse.Namespace(headers=headers_file, no_hop_findings=False), ctx
    )
    assert any(
        finding.category == "authentication" and "No Authentication-Results" in finding.summary
        for finding in report.findings
    )


def test_plugin_missing_file(context_factory: Any, tmp_path: Any) -> None:
    from osint_kit.core.errors import InputError

    ctx = context_factory()
    with pytest.raises(InputError, match="not found"):
        EmailHeadersPlugin().run(
            argparse.Namespace(headers=tmp_path / "nope.eml", no_hop_findings=False), ctx
        )
