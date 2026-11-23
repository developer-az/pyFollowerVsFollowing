"""Web (combined log format) and sshd auth-log analysis.

Parsing is a generator so a multi-gigabyte log never becomes a list. Analysis
keeps bounded counters and a per-IP sliding window, then emits findings.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter, defaultdict, deque
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

from osint_kit.core.errors import InputError, UsageError
from osint_kit.core.models import Report, Severity
from osint_kit.core.plugin import BasePlugin, PluginContext

COMBINED_RE = re.compile(
    r"^(?P<source>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?'
)
SSHD_TS_RE = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})")
SSHD_FAILED_RE = re.compile(
    r"(?:Failed password|authentication failure)(?: for(?: invalid user)? (?P<user>\S+))?"
    r".*?from (?P<source>\S+)(?: port \d+)?"
)
SSHD_INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<source>\S+)")
SSHD_ACCEPTED_RE = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<source>\S+)")

SUSPICIOUS_AGENTS: tuple[str, ...] = (
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "zgrab",
    "gobuster",
    "dirbuster",
    "wpscan",
    "hydra",
    "nuclei",
    "ffuf",
    "python-requests",
    "go-http-client",
    "libwww-perl",
    "censys",
    "shodan",
    "scrapy",
    "curl/",
    "wget/",
)

SENSITIVE_PATH_RE = re.compile(
    r"(?i)(?:\.env|\.git|\.svn|\.aws|wp-admin|wp-login|xmlrpc\.php|phpmyadmin|"
    r"/admin\b|/config|\.\./|cgi-bin|actuator|server-status|backup|\.sql\b)"
)

MAX_PATHS_PER_SOURCE = 200
MAX_BURSTS = 50


@dataclass
class ParseStats:
    """Line counts filled in while streaming, for honest coverage numbers."""

    lines: int = 0
    skipped: int = 0


@dataclass(frozen=True)
class LogEvent:
    """One parsed line."""

    kind: str  # "web" | "auth_failed" | "invalid_user" | "auth_accepted"
    line_number: int
    raw: str
    source_ip: str | None = None
    timestamp: datetime | None = None
    method: str | None = None
    path: str | None = None
    status: int | None = None
    user_agent: str | None = None
    user: str | None = None


@dataclass(frozen=True)
class Burst:
    """A dense run of failed logins from one source."""

    source_ip: str
    failures: int
    window_start: datetime
    window_end: datetime


@dataclass(frozen=True)
class LogAnalysis:
    """Aggregated, bounded view of a log."""

    events: int
    failed_logins: int
    top_sources: tuple[tuple[str, int], ...]
    top_paths: tuple[tuple[str, int], ...]
    failed_bursts: tuple[Burst, ...]
    suspicious_agents: tuple[tuple[str, int], ...]
    scanners: tuple[tuple[str, int, tuple[str, ...]], ...]
    invalid_users: tuple[tuple[str, int], ...]

    @property
    def counts(self) -> dict[str, int]:
        return {
            "events": self.events,
            "failed_logins": self.failed_logins,
            "sources": len(self.top_sources),
            "failed_bursts": len(self.failed_bursts),
            "suspicious_agents": len(self.suspicious_agents),
            "scanners": len(self.scanners),
        }


def _parse_web_time(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None


def _parse_sshd_time(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return None


def parse_web_line(line: str, *, line_number: int = 1) -> LogEvent | None:
    """Parse one Apache/Nginx combined line, or return ``None``."""
    match = COMBINED_RE.match(line)
    if match is None:
        return None
    request = match.group("request")
    method: str | None = None
    path: str | None = None
    if request and request != "-":
        parts = request.split()
        if len(parts) >= 2:
            method, path = parts[0], parts[1]
        else:
            path = request
    try:
        status = int(match.group("status"))
    except ValueError:
        return None
    return LogEvent(
        kind="web",
        line_number=line_number,
        raw=line.rstrip("\n"),
        source_ip=match.group("source"),
        timestamp=_parse_web_time(match.group("time")),
        method=method,
        path=path,
        status=status,
        user_agent=match.group("agent"),
    )


def parse_sshd_line(line: str, *, line_number: int = 1) -> LogEvent | None:
    """Parse one sshd line, classifying failed / invalid-user / accepted."""
    timestamp_match = SSHD_TS_RE.match(line)
    timestamp = _parse_sshd_time(timestamp_match.group("ts")) if timestamp_match else None

    invalid = SSHD_INVALID_RE.search(line)
    if invalid is not None:
        return LogEvent(
            kind="invalid_user",
            line_number=line_number,
            raw=line.rstrip("\n"),
            source_ip=invalid.group("source"),
            timestamp=timestamp,
            user=invalid.group("user"),
        )
    failed = SSHD_FAILED_RE.search(line)
    if failed is not None:
        return LogEvent(
            kind="auth_failed",
            line_number=line_number,
            raw=line.rstrip("\n"),
            source_ip=failed.group("source"),
            timestamp=timestamp,
            user=failed.group("user"),
        )
    accepted = SSHD_ACCEPTED_RE.search(line)
    if accepted is not None:
        return LogEvent(
            kind="auth_accepted",
            line_number=line_number,
            raw=line.rstrip("\n"),
            source_ip=accepted.group("source"),
            timestamp=timestamp,
            user=accepted.group("user"),
        )
    return None


def detect_format(lines: Sequence[str]) -> str:
    """Return ``combined``, ``sshd``, or ``unknown`` from a sample."""
    web = sum(1 for line in lines if parse_web_line(line) is not None)
    sshd = sum(1 for line in lines if parse_sshd_line(line) is not None)
    if web == 0 and sshd == 0:
        return "unknown"
    return "combined" if web >= sshd else "sshd"


def iter_events(
    stream: Iterable[str],
    *,
    fmt: str = "auto",
    sample_size: int = 200,
    stats: ParseStats | None = None,
) -> Iterator[LogEvent]:
    """Yield events lazily; ``fmt='auto'`` sniffs the first lines."""
    iterator = iter(stream)
    if fmt == "auto":
        sample: list[str] = []
        for line in iterator:
            if line.strip():
                sample.append(line)
            if len(sample) >= sample_size:
                break
        fmt = detect_format(sample)
        if fmt == "unknown":
            raise InputError(
                "could not recognise the log format; supported formats are "
                "Apache/Nginx combined and sshd auth logs"
            )
        lines: Iterable[str] = _chain(sample, iterator)
    else:
        lines = iterator
        if fmt not in {"combined", "sshd"}:
            raise InputError(f"unknown log format {fmt!r}; choose combined or sshd")

    parser = parse_web_line if fmt == "combined" else parse_sshd_line
    for line_number, line in enumerate(lines, start=1):
        if stats is not None:
            stats.lines += 1
        event = parser(line, line_number=line_number)
        if event is not None:
            yield event
        elif stats is not None and line.strip():
            stats.skipped += 1


def _chain(first: Sequence[str], rest: Iterator[str]) -> Iterator[str]:
    yield from first
    yield from rest


def analyze_events(
    events: Iterable[LogEvent],
    *,
    window_seconds: float = 60.0,
    burst_threshold: int = 5,
    scan_threshold: int = 10,
    top_n: int = 5,
) -> LogAnalysis:
    """Aggregate events with bounded memory."""
    sources: Counter[str] = Counter()
    paths: Counter[str] = Counter()
    agents: Counter[str] = Counter()
    invalid_users: Counter[str] = Counter()
    windows: dict[str, deque[datetime]] = defaultdict(deque)
    best_burst: dict[str, Burst] = {}
    scanned: dict[str, set[str]] = defaultdict(set)
    total = 0
    failed_total = 0

    for event in events:
        total += 1
        if event.source_ip:
            sources[event.source_ip] += 1
        if event.kind == "web":
            if event.path:
                paths[event.path] += 1
                if event.status is not None and event.status in {401, 403, 404}:
                    source = event.source_ip or "unknown"
                    seen = scanned[source]
                    if len(seen) < MAX_PATHS_PER_SOURCE:
                        seen.add(event.path)
            if event.user_agent:
                lowered = event.user_agent.casefold()
                for pattern in SUSPICIOUS_AGENTS:
                    if pattern in lowered:
                        agents[event.user_agent] += 1
                        break
        elif event.kind in {"auth_failed", "invalid_user"}:
            failed_total += 1
            if event.user:
                invalid_users[event.user] += 1
            if event.source_ip and event.timestamp is not None:
                queue = windows[event.source_ip]
                queue.append(event.timestamp)
                cutoff = event.timestamp.timestamp() - window_seconds
                while queue and queue[0].timestamp() < cutoff:
                    queue.popleft()
                if len(queue) >= burst_threshold:
                    candidate = Burst(
                        source_ip=event.source_ip,
                        failures=len(queue),
                        window_start=queue[0],
                        window_end=queue[-1],
                    )
                    previous = best_burst.get(event.source_ip)
                    if previous is None or candidate.failures > previous.failures:
                        best_burst[event.source_ip] = candidate

    scanners: list[tuple[str, int, tuple[str, ...]]] = []
    for source, seen in scanned.items():
        sensitive = sorted(path for path in seen if SENSITIVE_PATH_RE.search(path))
        if len(seen) >= scan_threshold or sensitive:
            samples = tuple((sensitive or sorted(seen))[:5])
            scanners.append((source, len(seen), samples))

    return LogAnalysis(
        events=total,
        failed_logins=failed_total,
        top_sources=tuple(sources.most_common(top_n)),
        top_paths=tuple(paths.most_common(top_n)),
        failed_bursts=tuple(
            sorted(best_burst.values(), key=lambda burst: burst.failures, reverse=True)[:MAX_BURSTS]
        ),
        suspicious_agents=tuple(agents.most_common(top_n)),
        scanners=tuple(sorted(scanners, key=lambda item: item[1], reverse=True)[:MAX_BURSTS]),
        invalid_users=tuple(invalid_users.most_common(top_n)),
    )


def read_log_events(
    paths: Sequence[Path],
    *,
    fmt: str = "auto",
    stdin: TextIO | None = None,
    stats: ParseStats | None = None,
) -> Iterator[LogEvent]:
    """Yield events from files (or ``-`` for stdin), one file at a time."""
    for path in paths:
        if str(path) == "-":
            source = stdin if stdin is not None else sys.stdin
            yield from iter_events(source, fmt=fmt, stats=stats)
            continue
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                yield from iter_events(handle, fmt=fmt, stats=stats)
        except FileNotFoundError as exc:
            raise InputError(f"log file not found: {path}") from exc
        except OSError as exc:
            raise InputError(f"could not read {path}: {exc}") from exc


class LogAnalyzerPlugin(BasePlugin):
    """Top talkers, failed-login bursts, scanners, and suspicious agents."""

    NAME = "log_analyzer"
    SUMMARY = "Analyze web (combined) and sshd logs: top sources, bursts, scans."
    NETWORK = False

    def configure_parser(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "logs", nargs="+", type=Path, metavar="LOG", help="log file(s), - for stdin"
        )
        parser.add_argument(
            "--log-format",
            choices=("auto", "combined", "sshd"),
            default="auto",
            help="input format (default: auto-detect)",
        )
        parser.add_argument("--window", type=float, default=60.0, metavar="SECONDS")
        parser.add_argument("--burst-threshold", type=int, default=5, metavar="N")
        parser.add_argument("--scan-threshold", type=int, default=10, metavar="N")
        parser.add_argument("--top", type=int, default=5, metavar="N")

    def run(self, options: argparse.Namespace, ctx: PluginContext) -> Report:
        if options.window <= 0 or options.burst_threshold < 1 or options.scan_threshold < 1:
            raise UsageError("window and thresholds must be positive")
        stats = ParseStats()
        analysis = analyze_events(
            read_log_events(options.logs, fmt=options.log_format, stats=stats),
            window_seconds=options.window,
            burst_threshold=options.burst_threshold,
            scan_threshold=options.scan_threshold,
            top_n=options.top,
        )
        report = Report(
            plugin=self.name,
            target=", ".join(str(path) for path in options.logs),
            metadata={"log_format": options.log_format},
        )
        report.stats.update(analysis.counts)
        report.stats["lines"] = stats.lines
        report.stats["unparsed"] = stats.skipped

        for source, count in analysis.top_sources:
            report.add(
                category="top_source",
                subject=source,
                summary=f"{count} request(s)/event(s) from this source.",
                details={"source_ip": source, "count": count},
            )
        for burst in analysis.failed_bursts:
            report.add(
                category="failed_login_burst",
                subject=burst.source_ip,
                summary=f"{burst.failures} failed logins within the sliding window.",
                severity=Severity.HIGH,
                details={
                    "source_ip": burst.source_ip,
                    "failures": burst.failures,
                    "window_start": burst.window_start.isoformat(),
                    "window_end": burst.window_end.isoformat(),
                },
            )
        for agent, count in analysis.suspicious_agents:
            report.add(
                category="suspicious_agent",
                subject=agent[:120],
                summary=f"User agent matched a known scanner/tool pattern ({count} hits).",
                severity=Severity.MEDIUM,
                details={"user_agent": agent, "count": count},
            )
        for source, distinct, samples in analysis.scanners:
            report.add(
                category="path_scan",
                subject=source,
                summary=f"{distinct} distinct error paths requested (possible scanning).",
                severity=Severity.HIGH if distinct >= options.scan_threshold else Severity.MEDIUM,
                details={"source_ip": source, "distinct_paths": distinct, "samples": list(samples)},
            )
        for user, count in analysis.invalid_users:
            report.add(
                category="invalid_user",
                subject=user,
                summary=f"{count} failed/invalid login attempt(s) for this username.",
                severity=Severity.MEDIUM,
                details={"username": user, "count": count},
            )
        return report
