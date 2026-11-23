"""Email header forensics: hop chain, hop latency, authentication verdicts.

Everything here operates on the raw header block as text. File reading and
stdin handling happen in the plugin's ``run``.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from email import message_from_string
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path

from osint_kit.core.errors import InputError
from osint_kit.core.models import Report, Severity
from osint_kit.core.plugin import BasePlugin, PluginContext

RECEIVED_TS_TOLERANCE = 120.0  # seconds of clock skew before order is "suspicious"
SLOW_HOP_SECONDS = 300.0

_FROM_RE = re.compile(r"\bfrom\s+(?P<host>[^\s;()]+)", re.IGNORECASE)
_BY_RE = re.compile(r"\bby\s+(?P<host>[^\s;()]+)", re.IGNORECASE)
_WITH_RE = re.compile(r"\bwith\s+(?P<proto>[^\s;()]+)", re.IGNORECASE)
_IP_RE = re.compile(r"[\[(](?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{6,})[\])]")
_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)")


@dataclass(frozen=True)
class ReceivedHop:
    """One parsed ``Received:`` header (as listed, newest first)."""

    position: int
    from_host: str | None
    by_host: str | None
    protocol: str | None
    ip: str | None
    timestamp: datetime | None
    raw: str


@dataclass(frozen=True)
class ParsedHeaders:
    """Header fields we care about, with duplicates preserved."""

    received: tuple[str, ...]
    from_value: str | None
    return_path: str | None
    reply_to: str | None
    date: str | None
    message_id: str | None
    subject: str | None
    auth_results: tuple[str, ...]
    received_spf: tuple[str, ...]
    raw_header_names: tuple[str, ...]


@dataclass(frozen=True)
class HeaderAnalysis:
    """Result of analysing a header block."""

    hops: tuple[ReceivedHop, ...]  # newest-first, as listed
    chronological: tuple[ReceivedHop, ...]
    latencies: tuple[float | None, ...]  # one per chronological hop; first is None
    auth: tuple[tuple[str, str], ...]  # (mechanism, result) for every occurrence
    from_domain: str | None
    return_path_domain: str | None
    from_mismatch: bool
    order_suspicious: bool
    chain_breaks: tuple[str, ...]
    missing: tuple[str, ...]


def split_header_block(text: str) -> str:
    """Return only the header block (before the first blank line)."""
    normalised = text.replace("\r\n", "\n").replace("\r", "\n")
    head, _, _ = normalised.partition("\n\n")
    return head


def parse_headers(text: str) -> ParsedHeaders:
    """Parse a raw header block without touching the body."""
    head = split_header_block(text)
    message: Message = message_from_string(head + "\n\n")

    def values(name: str) -> tuple[str, ...]:
        return tuple(str(value) for value in message.get_all(name, []))

    names = tuple(key for key, _ in message.items())
    return ParsedHeaders(
        received=values("Received"),
        from_value=_first(values("From")),
        return_path=_first(values("Return-Path")),
        reply_to=_first(values("Reply-To")),
        date=_first(values("Date")),
        message_id=_first(values("Message-ID")),
        subject=_first(values("Subject")),
        auth_results=values("Authentication-Results"),
        received_spf=values("Received-SPF"),
        raw_header_names=names,
    )


def _first(values: Sequence[str]) -> str | None:
    return values[0] if values else None


def parse_received(value: str, *, position: int = 0) -> ReceivedHop:
    """Parse one ``Received:`` value. Missing pieces become ``None``."""
    prefix, separator, date_part = value.rpartition(";")
    if separator:
        timestamp = _parse_date(date_part)
    else:
        prefix = value
        timestamp = None

    from_match = _FROM_RE.search(prefix)
    by_match = _BY_RE.search(prefix)
    with_match = _WITH_RE.search(prefix)
    ip_match = _IP_RE.search(prefix)
    return ReceivedHop(
        position=position,
        from_host=_clean_host(from_match.group("host")) if from_match else None,
        by_host=_clean_host(by_match.group("host")) if by_match else None,
        protocol=with_match.group("proto") if with_match else None,
        ip=ip_match.group("ip") if ip_match else None,
        timestamp=timestamp,
        raw=value.strip(),
    )


def _clean_host(value: str) -> str:
    host = value.strip().strip("[]()").rstrip(".,")
    if host.lower().startswith("unknown"):
        return "unknown"
    return host.lower()


def _parse_date(value: str) -> datetime | None:
    try:
        parsed = parsedate_to_datetime(value.strip())
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def parse_auth_results(values: Iterable[str]) -> tuple[tuple[str, str], ...]:
    """Extract ``spf=``, ``dkim=``, ``dmarc=`` results in order of appearance."""
    results: list[tuple[str, str]] = []
    for value in values:
        for mechanism, result in _AUTH_RE.findall(value):
            results.append((mechanism.lower(), result.lower()))
    return tuple(results)


def domain_of(address: str | None) -> str | None:
    """Domain from ``Display Name <user@example.com>`` or ``<>``."""
    if not address:
        return None
    parsed = getaddresses([address])
    if not parsed:
        return None
    _, addr = parsed[0]
    if not addr or "@" not in addr:
        return None
    return addr.rsplit("@", 1)[1].strip().lower().rstrip(">") or None


def analyze_headers(text: str) -> HeaderAnalysis:
    """Build the hop chain and all header-level judgements."""
    headers = parse_headers(text)
    hops = tuple(
        parse_received(value, position=index) for index, value in enumerate(headers.received)
    )

    ordered = tuple(
        sorted(
            (hop for hop in hops if hop.timestamp is not None),
            key=lambda hop: hop.timestamp or datetime.min.replace(tzinfo=UTC),
        )
    )
    latencies: list[float | None] = []
    previous: datetime | None = None
    for hop in ordered:
        if previous is None or hop.timestamp is None:
            latencies.append(None)
        else:
            latencies.append((hop.timestamp - previous).total_seconds())
        previous = hop.timestamp or previous

    order_suspicious = False
    for index in range(len(hops) - 1):
        current = hops[index].timestamp
        older = hops[index + 1].timestamp
        if current is None or older is None:
            continue
        if older.timestamp() > current.timestamp() + RECEIVED_TS_TOLERANCE:
            order_suspicious = True
            break

    chain_breaks: list[str] = []
    for index in range(len(ordered) - 1):
        hop = ordered[index]
        next_hop = ordered[index + 1]
        if (
            hop.by_host
            and next_hop.from_host
            and hop.by_host != next_hop.from_host
            and next_hop.from_host != "unknown"
        ):
            chain_breaks.append(
                f"hop {index + 1} was received by {hop.by_host}, "
                f"but hop {index + 2} claims to come from {next_hop.from_host}"
            )

    missing = tuple(
        name
        for name in ("From", "Date", "Message-ID", "Return-Path")
        if not headers.raw_header_names
        or name.lower() not in {n.lower() for n in headers.raw_header_names}
    )

    from_domain = domain_of(headers.from_value)
    return_domain = domain_of(headers.return_path)
    return HeaderAnalysis(
        hops=hops,
        chronological=ordered,
        latencies=tuple(latencies),
        auth=parse_auth_results(headers.auth_results),
        from_domain=from_domain,
        return_path_domain=return_domain,
        from_mismatch=bool(from_domain and return_domain and from_domain != return_domain),
        order_suspicious=order_suspicious,
        chain_breaks=tuple(chain_breaks),
        missing=missing,
    )


def spf_from_received_spf(values: Iterable[str]) -> str | None:
    """First token of the topmost ``Received-SPF`` header, if any."""
    for value in values:
        tokens = value.strip().split(None, 1)
        if tokens:
            return tokens[0].lower()
    return None


class EmailHeadersPlugin(BasePlugin):
    """Parse raw email headers into a hop chain and auth verdicts."""

    NAME = "email_headers"
    SUMMARY = "Hop chain, per-hop latency, SPF/DKIM/DMARC, and From/Return-Path checks."
    NETWORK = False

    def configure_parser(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "headers", type=Path, metavar="FILE", help="raw headers file, or - for stdin"
        )
        parser.add_argument(
            "--no-hop-findings",
            action="store_true",
            help="summarise the hop chain in stats instead of one finding per hop",
        )

    def run(self, options: argparse.Namespace, ctx: PluginContext) -> Report:
        text = _read_input(options.headers)
        analysis = analyze_headers(text)
        headers = parse_headers(text)
        received_spf = spf_from_received_spf(headers.received_spf)

        report = Report(
            plugin=self.name,
            target=str(options.headers),
            metadata={
                "subject": headers.subject,
                "message_id": headers.message_id,
                "from_domain": analysis.from_domain,
                "return_path_domain": analysis.return_path_domain,
                "received_spf": received_spf,
            },
        )
        report.stats.update(
            {
                "hops": len(analysis.hops),
                "authenticated_hops": len(analysis.chronological),
                "chain_breaks": len(analysis.chain_breaks),
                "header_missing": len(analysis.missing),
            }
        )

        if not options.no_hop_findings:
            ordered = analysis.chronological
            latency_by_position = {
                hop.position: analysis.latencies[index] for index, hop in enumerate(ordered)
            }
            for index, hop in enumerate(ordered, start=1):
                latency = latency_by_position.get(hop.position)
                report.add(
                    category="hop",
                    subject=f"hop {index}",
                    summary=(
                        f"{hop.from_host or '?'} → {hop.by_host or '?'}"
                        f" via {hop.protocol or 'unknown protocol'}"
                    ),
                    details={
                        "from": hop.from_host,
                        "by": hop.by_host,
                        "protocol": hop.protocol,
                        "ip": hop.ip,
                        "timestamp": hop.timestamp.isoformat() if hop.timestamp else None,
                        "latency_seconds": latency,
                    },
                )

        results = list(analysis.auth)
        if not results and received_spf:
            results.append(("spf", received_spf))
        for mechanism, result in results:
            severity = Severity.INFO
            if result in {"fail", "hardfail", "permerror"}:
                severity = Severity.HIGH
            elif result in {"softfail", "temperror"} or result in {"none", "neutral"}:
                severity = Severity.MEDIUM
            report.add(
                category="authentication",
                subject=mechanism,
                summary=f"{mechanism.upper()} result: {result}",
                severity=severity,
                details={"mechanism": mechanism, "result": result},
            )
        if not results:
            report.add(
                category="authentication",
                subject="spf/dkim/dmarc",
                summary="No Authentication-Results or Received-SPF header found.",
                severity=Severity.MEDIUM,
            )

        if analysis.from_mismatch:
            report.add(
                category="identity",
                subject=analysis.from_domain or "unknown",
                summary=(
                    "From domain differs from Return-Path domain "
                    f"({analysis.from_domain} vs {analysis.return_path_domain})."
                ),
                severity=Severity.LOW,
                details={
                    "from_domain": analysis.from_domain,
                    "return_path_domain": analysis.return_path_domain,
                    "note": "Common for mailing lists and ESPs; investigate only with context.",
                },
            )
        if analysis.order_suspicious:
            report.add(
                category="routing",
                subject="received-order",
                summary="Received timestamps contradict header order (possible injection).",
                severity=Severity.MEDIUM,
            )
        for breakage in analysis.chain_breaks:
            report.add(
                category="routing",
                subject="chain-break",
                summary=breakage,
                severity=Severity.LOW,
            )
        for name in analysis.missing:
            report.add(
                category="header_missing",
                subject=name,
                summary=f"Expected header {name} is absent.",
                severity=Severity.MEDIUM,
            )
        slow = [
            (hop, latency)
            for hop, latency in zip(analysis.chronological, analysis.latencies, strict=False)
            if latency is not None and latency >= SLOW_HOP_SECONDS
        ]
        for hop, latency in slow:
            report.add(
                category="routing",
                subject=f"{hop.from_host or '?'}→{hop.by_host or '?'}",
                summary=f"Hop took {latency:.0f}s (possible queueing or delay).",
                severity=Severity.LOW,
                details={"latency_seconds": latency},
            )
        return report


def _read_input(path: Path) -> str:
    if str(path) == "-":
        return sys.stdin.read()
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError as exc:
        raise InputError(f"headers file not found: {path}") from exc
    except OSError as exc:
        raise InputError(f"could not read {path}: {exc}") from exc
