"""log_analyzer: parsers, streaming, bursts, scans, and agent flags."""

from __future__ import annotations

import argparse
import io
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from osint_kit.core.errors import InputError, UsageError
from osint_kit.plugins.log_analyzer import (
    LogAnalyzerPlugin,
    LogEvent,
    ParseStats,
    analyze_events,
    detect_format,
    iter_events,
    parse_sshd_line,
    parse_web_line,
    read_log_events,
)


def line(name: str) -> str:
    return (Path("tests/fixtures/logs") / name).read_text(encoding="utf-8")


def test_parse_web_line() -> None:
    event = parse_web_line(
        '203.0.113.9 - - [01/Nov/2025:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
        line_number=7,
    )
    assert event is not None
    assert event.kind == "web"
    assert event.source_ip == "203.0.113.9"
    assert event.method == "GET"
    assert event.path == "/index.html"
    assert event.status == 200
    assert event.user_agent == "Mozilla/5.0"
    assert event.timestamp == datetime(2025, 11, 1, 12, 0, tzinfo=UTC)
    assert event.line_number == 7


def test_parse_web_line_minimal_and_invalid() -> None:
    event = parse_web_line('1.2.3.4 - - [01/Nov/2025:12:00:00 +0000] "-" 400 0')
    assert event is not None
    assert event.path is None
    assert event.user_agent is None
    assert parse_web_line("garbage") is None
    assert parse_web_line('1.2.3.4 - - [bad-time] "GET / HTTP/1.1" 200 1') is not None


def test_parse_sshd_lines() -> None:
    failed = parse_sshd_line(
        "Nov  1 12:00:11 host sshd[102]: Failed password for root from 192.0.2.44 port 50124 ssh2"
    )
    assert failed is not None
    assert failed.kind == "auth_failed"
    assert failed.source_ip == "192.0.2.44"
    assert failed.user == "root"
    assert failed.timestamp == datetime(1900, 11, 1, 12, 0, 11, tzinfo=UTC)

    invalid = parse_sshd_line("Nov  1 12:02:05 host sshd[108]: Invalid user bob from 198.51.100.23")
    assert invalid is not None and invalid.kind == "invalid_user" and invalid.user == "bob"

    accepted = parse_sshd_line(
        "Nov  1 12:02:00 host sshd[107]: Accepted publickey for alice from 203.0.113.50 port 41000 ssh2"
    )
    assert accepted is not None and accepted.kind == "auth_accepted"

    assert parse_sshd_line("Nov  1 12:05:00 host systemd[1]: Started daily apt.") is None
    assert parse_sshd_line("garbage") is None


def test_detect_format() -> None:
    assert detect_format(line("access.log").splitlines()) == "combined"
    assert detect_format(line("auth.log").splitlines()) == "sshd"
    assert detect_format(["nonsense", "more nonsense"]) == "unknown"


def test_iter_events_rejects_unknown_format() -> None:
    with pytest.raises(InputError, match="could not recognise"):
        list(iter_events(["nonsense\n", "still nonsense\n"]))


def test_iter_events_rejects_bad_explicit_format() -> None:
    with pytest.raises(InputError, match="unknown log format"):
        list(iter_events([], fmt="apache"))


def test_streaming_is_lazy() -> None:
    class CountingStream:
        def __init__(self, lines: list[str]) -> None:
            self.lines = lines
            self.read = 0

        def __iter__(self) -> Any:
            for item in self.lines:
                self.read += 1
                yield item

    sample_line = (
        '1.2.3.4 - - [01/Nov/2025:12:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "Mozilla/5.0"\n'
    )
    stream = CountingStream([sample_line] * 5000)
    events = iter_events(stream)
    next(events)
    assert stream.read <= 201


def test_analyze_access_log_scans_and_agents() -> None:
    events = list(iter_events(io.StringIO(line("access.log"))))
    analysis = analyze_events(events, scan_threshold=10)
    assert analysis.events == 14
    assert analysis.failed_logins == 0
    assert analysis.top_sources[0] == ("198.51.100.7", 11)
    assert any("sqlmap" in agent for agent, _count in analysis.suspicious_agents)
    assert analysis.scanners
    source, distinct, samples = analysis.scanners[0]
    assert source == "198.51.100.7"
    assert distinct >= 10
    assert any(path.startswith("/.") or "admin" in path for path in samples)
    assert not analysis.failed_bursts


def test_analyze_auth_log_bursts() -> None:
    events = list(iter_events(io.StringIO(line("auth.log"))))
    analysis = analyze_events(events, window_seconds=60, burst_threshold=5)
    assert analysis.failed_logins == 8
    burst = analysis.failed_bursts[0]
    assert burst.source_ip == "192.0.2.44"
    assert burst.failures == 7
    assert burst.window_end >= burst.window_start
    assert ("admin", 2) in analysis.invalid_users


def test_window_boundary_prevents_false_burst() -> None:
    base = datetime(2025, 11, 1, 12, 0, tzinfo=UTC)
    events = [
        LogEvent(
            kind="auth_failed",
            line_number=index,
            raw="x",
            source_ip="192.0.2.1",
            timestamp=base.replace(minute=index * 2),
        )
        for index in range(3)
    ]
    analysis = analyze_events(events, window_seconds=60, burst_threshold=2)
    assert analysis.failed_bursts == ()


def test_burst_threshold_met_exactly() -> None:
    base = datetime(2025, 11, 1, 12, 0, tzinfo=UTC)
    events = [
        LogEvent(
            kind="auth_failed",
            line_number=index,
            raw="x",
            source_ip="192.0.2.1",
            timestamp=base.replace(second=index * 5),
        )
        for index in range(2)
    ]
    analysis = analyze_events(events, window_seconds=60, burst_threshold=2)
    assert analysis.failed_bursts[0].failures == 2


def test_sensitive_path_flags_scanner_below_threshold() -> None:
    event = LogEvent(
        kind="web", line_number=1, raw="x", source_ip="1.2.3.4", path="/.env", status=404
    )
    analysis = analyze_events([event], scan_threshold=99)
    assert analysis.scanners and analysis.scanners[0][0] == "1.2.3.4"


def test_plugin_end_to_end(context_factory: Any, fixtures: Path) -> None:
    ctx = context_factory()
    options = argparse.Namespace(
        logs=[fixtures / "logs" / "access.log"],
        log_format="auto",
        window=60.0,
        burst_threshold=5,
        scan_threshold=10,
        top=5,
    )
    report = LogAnalyzerPlugin().run(options, ctx)
    assert report.stats["lines"] == 15
    assert report.stats["unparsed"] == 1
    assert report.stats["scanners"] >= 1
    categories = {finding.category for finding in report.findings}
    assert {"top_source", "suspicious_agent", "path_scan"} <= categories
    scan = next(finding for finding in report.findings if finding.category == "path_scan")
    assert scan.severity.value == "high"


def test_plugin_auth_and_bad_thresholds(context_factory: Any, fixtures: Path) -> None:
    ctx = context_factory()
    options = argparse.Namespace(
        logs=[fixtures / "logs" / "auth.log"],
        log_format="sshd",
        window=60.0,
        burst_threshold=5,
        scan_threshold=10,
        top=5,
    )
    report = LogAnalyzerPlugin().run(options, ctx)
    assert report.stats["failed_bursts"] >= 1
    assert any(finding.category == "failed_login_burst" for finding in report.findings)

    with pytest.raises(UsageError):
        LogAnalyzerPlugin().run(
            argparse.Namespace(
                logs=[], log_format="auto", window=0, burst_threshold=5, scan_threshold=1, top=5
            ),
            ctx,
        )


def test_plugin_missing_file(context_factory: Any, tmp_path: Path) -> None:
    ctx = context_factory()
    options = argparse.Namespace(
        logs=[tmp_path / "nope.log"],
        log_format="auto",
        window=60.0,
        burst_threshold=5,
        scan_threshold=10,
        top=5,
    )
    with pytest.raises(InputError, match="not found"):
        LogAnalyzerPlugin().run(options, ctx)


def test_read_log_events_stdin_and_stats() -> None:
    stats = ParseStats()
    events = list(read_log_events([Path("-")], stdin=io.StringIO(line("access.log")), stats=stats))
    assert len(events) == 14
    assert stats.skipped == 1


@given(
    st.ip_addresses(v=4),
    st.sampled_from(["GET", "POST", "HEAD", "PATCH"]),
    st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789/._-", min_size=1, max_size=40),
    st.integers(min_value=100, max_value=599),
    st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789 ./-", min_size=0, max_size=40),
)
def test_web_line_roundtrip(address: Any, method: str, path: str, status: int, agent: str) -> None:
    if not path.startswith("/"):
        path = "/" + path
    raw = (
        f'{address} - - [01/Nov/2025:12:00:00 +0000] "{method} {path} HTTP/1.1" '
        f'{status} 123 "-" "{agent}"'
    )
    event = parse_web_line(raw)
    assert event is not None
    assert event.source_ip == str(address)
    assert event.method == method
    assert event.path == path
    assert event.status == status
