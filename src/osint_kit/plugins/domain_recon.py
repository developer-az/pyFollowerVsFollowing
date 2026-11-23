"""Domain recon through public DNS-over-HTTPS and certificate transparency.

No DNS packets are sent directly: queries go to Google's public DoH endpoint
over HTTPS, and subdomains come from crt.sh's public JSON endpoint. Both are
read-only, unauthenticated services.
"""

from __future__ import annotations

import argparse
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from osint_kit.core.errors import HttpError, UsageError
from osint_kit.core.models import Report, Severity
from osint_kit.core.plugin import BasePlugin, PluginContext

DOH_URL = "https://dns.google/resolve"
CRTSH_URL = "https://crt.sh/"
DNS_TYPES: dict[str, int] = {
    "A": 1,
    "NS": 2,
    "SOA": 6,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "DS": 43,
    "DNSKEY": 48,
}
_TYPE_NAMES = {value: key for key, value in DNS_TYPES.items()}
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


@dataclass(frozen=True)
class DnsRecord:
    name: str
    record_type: str
    ttl: int
    data: str


@dataclass(frozen=True)
class DohResponse:
    status: int
    authenticated: bool
    records: tuple[DnsRecord, ...]

    @property
    def found(self) -> bool:
        return self.status == 0

    def of_type(self, record_type: str) -> tuple[DnsRecord, ...]:
        return tuple(record for record in self.records if record.record_type == record_type)


@dataclass(frozen=True)
class SpfSummary:
    record: str
    all_qualifier: str | None
    includes: tuple[str, ...]


@dataclass(frozen=True)
class PostureFlag:
    key: str
    summary: str
    severity: Severity
    details: dict[str, Any] = field(default_factory=dict)


def normalise_domain(value: str) -> str:
    """Lower-case, trim a trailing dot, and IDNA-encode."""
    candidate = value.strip().strip(".").lower()
    if not candidate:
        raise UsageError("domain is empty")
    try:
        ascii_domain = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise UsageError(f"invalid domain {value!r}: {exc}") from exc
    if not _DOMAIN_RE.match(ascii_domain):
        raise UsageError(f"invalid domain: {value!r}")
    return ascii_domain


def parse_doh(payload: Mapping[str, Any]) -> DohResponse:
    """Parse the JSON returned by dns.google."""
    try:
        status = int(payload.get("Status", 0))
    except (TypeError, ValueError):
        status = 2
    records: list[DnsRecord] = []
    for answer in payload.get("Answer") or []:
        if not isinstance(answer, Mapping):
            continue
        record_type = _TYPE_NAMES.get(_as_int(answer.get("type")))
        if record_type is None:
            continue
        data = str(answer.get("data", ""))
        if not data:
            continue
        records.append(
            DnsRecord(
                name=str(answer.get("name", "")).rstrip("."),
                record_type=record_type,
                ttl=_as_int(answer.get("TTL")),
                data=data,
            )
        )
    return DohResponse(
        status=status,
        authenticated=bool(payload.get("AD", False)),
        records=tuple(records),
    )


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def unquote_txt(data: str) -> str:
    """Join the quoted chunks of a TXT record into one string."""
    chunks = re.findall(r'"([^"]*)"', data)
    if chunks:
        return "".join(chunks)
    return data.strip()


def parse_spf(txt_records: Iterable[str]) -> SpfSummary | None:
    """Find and summarise an SPF record, or return ``None``."""
    for raw in txt_records:
        record = unquote_txt(raw)
        if not record.lower().startswith("v=spf1"):
            continue
        tokens = record.split()[1:]
        includes = tuple(token.split(":", 1)[1] for token in tokens if token.startswith("include:"))
        qualifier: str | None = None
        for token in tokens:
            match = re.fullmatch(r"([+\-~?]?)all", token, re.IGNORECASE)
            if match:
                qualifier = match.group(1) or "+"
                break
        return SpfSummary(record=record, all_qualifier=qualifier, includes=includes)
    return None


def parse_dmarc(txt_records: Iterable[str]) -> str | None:
    """Return the first DMARC record among TXT values, if present."""
    for raw in txt_records:
        record = unquote_txt(raw)
        if record.lower().startswith("v=dmarc1"):
            return record
    return None


def dmarc_policy(record: str) -> str | None:
    match = re.search(r"(?:^|;)\s*p\s*=\s*(\w+)", record, re.IGNORECASE)
    return match.group(1).lower() if match else None


def dmarc_has_rua(record: str) -> bool:
    return re.search(r"(?:^|;)\s*rua\s*=", record, re.IGNORECASE) is not None


def evaluate_posture(
    spf: SpfSummary | None,
    dmarc: str | None,
    *,
    dnssec_enabled: bool,
) -> tuple[PostureFlag, ...]:
    """Turn records into explainable flags."""
    flags: list[PostureFlag] = []
    if spf is None:
        flags.append(
            PostureFlag(
                key="spf_missing",
                summary="No SPF record: any host may send mail as this domain.",
                severity=Severity.HIGH,
            )
        )
    else:
        qualifier = spf.all_qualifier
        if qualifier == "+":
            flags.append(
                PostureFlag(
                    key="spf_permissive",
                    summary="SPF ends in '+all', which authorises every sender.",
                    severity=Severity.HIGH,
                    details={"record": spf.record},
                )
            )
        elif qualifier == "?":
            flags.append(
                PostureFlag(
                    key="spf_neutral",
                    summary="SPF ends in '?all' (neutral), so it provides no enforcement.",
                    severity=Severity.LOW,
                    details={"record": spf.record},
                )
            )
        elif qualifier == "~":
            flags.append(
                PostureFlag(
                    key="spf_softfail",
                    summary="SPF ends in '~all' (softfail); strict receivers may still accept.",
                    severity=Severity.LOW,
                    details={"record": spf.record},
                )
            )
        elif qualifier is None:
            flags.append(
                PostureFlag(
                    key="spf_no_all",
                    summary="SPF has no 'all' mechanism; the default result is neutral.",
                    severity=Severity.LOW,
                    details={"record": spf.record},
                )
            )

    if dmarc is None:
        flags.append(
            PostureFlag(
                key="dmarc_missing",
                summary="No DMARC record at _dmarc: no policy for failed authentication.",
                severity=Severity.MEDIUM,
            )
        )
    else:
        policy = dmarc_policy(dmarc)
        if policy == "none":
            flags.append(
                PostureFlag(
                    key="dmarc_policy_none",
                    summary="DMARC policy is 'none' (monitor only, no enforcement).",
                    severity=Severity.LOW,
                    details={"record": dmarc},
                )
            )
        if not dmarc_has_rua(dmarc):
            flags.append(
                PostureFlag(
                    key="dmarc_no_rua",
                    summary="DMARC has no rua= reporting address.",
                    severity=Severity.INFO,
                    details={"record": dmarc},
                )
            )
    if not dnssec_enabled:
        flags.append(
            PostureFlag(
                key="dnssec_missing",
                summary="No DNSSEC chain observed (no DS records and AD bit unset).",
                severity=Severity.LOW,
            )
        )
    return tuple(flags)


def extract_subdomains(rows: Iterable[Mapping[str, Any]], domain: str) -> tuple[str, ...]:
    """Collect unique, valid, non-wildcard names ending in ``domain``."""
    apex = domain.lower().rstrip(".")
    found: set[str] = set()
    for row in rows:
        values: list[str] = []
        common_name = row.get("common_name")
        if isinstance(common_name, str):
            values.append(common_name)
        name_value = row.get("name_value")
        if isinstance(name_value, str):
            values.extend(name_value.splitlines())
        for value in values:
            name = value.strip().lower().rstrip(".")
            if name.startswith("*."):
                name = name[2:]
            if name == apex or not name.endswith("." + apex):
                continue
            labels = name.split(".")
            if len(labels) < 3 or not all(_LABEL_RE.match(label) for label in labels):
                continue
            found.add(name)
    return tuple(sorted(found))


def _first_data(records: Iterable[DnsRecord]) -> tuple[str, ...]:
    return tuple(record.data for record in records)


def _query(ctx: PluginContext, domain: str, record_type: str) -> DohResponse:
    client = ctx.http()
    payload = client.get_json(
        DOH_URL,
        params={"name": domain, "type": record_type, "do": "1"},
    )
    if not isinstance(payload, Mapping):
        raise HttpError("DNS-over-HTTPS returned an unexpected JSON shape", url=DOH_URL)
    return parse_doh(payload)


class DomainReconPlugin(BasePlugin):
    """DNS records, certificate-transparency subdomains, and email posture."""

    NAME = "domain_recon"
    SUMMARY = "DNS A/AAAA/MX/NS/TXT via DoH, CT subdomains, SPF/DMARC/DNSSEC flags."
    NETWORK = True

    def configure_parser(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("domain", metavar="DOMAIN")
        parser.add_argument("--no-ct", action="store_true", help="skip the crt.sh lookup")
        parser.add_argument("--no-dnssec", action="store_true", help="skip DS/DNSKEY queries")
        parser.add_argument(
            "--max-subdomains",
            type=int,
            default=200,
            metavar="N",
            help="maximum subdomain findings to emit (default: 200)",
        )

    def run(self, options: argparse.Namespace, ctx: PluginContext) -> Report:
        domain = normalise_domain(options.domain)
        report = Report(plugin=self.name, target=domain)
        responses: dict[str, DohResponse] = {}

        for record_type in ("A", "AAAA", "MX", "NS", "TXT"):
            response = _query(ctx, domain, record_type)
            responses[record_type] = response
            if response.status == 3:
                report.add(
                    category="dns",
                    subject=domain,
                    summary="NXDOMAIN: the domain does not exist.",
                    severity=Severity.HIGH,
                )
                report.stats["nxdomain"] = 1
                return report
            if response.status != 0:
                report.add(
                    category="dns_error",
                    subject=f"{domain} {record_type}",
                    summary=f"DoH status {response.status} for {record_type} query.",
                    severity=Severity.LOW,
                )
                continue
            records = response.of_type(record_type)
            report.stats[f"dns_{record_type.lower()}"] = len(records)
            if records:
                report.add(
                    category="dns",
                    subject=f"{domain} {record_type}",
                    summary=f"{len(records)} {record_type} record(s): "
                    + ", ".join(record.data for record in records[:5]),
                    details={
                        "record_type": record_type,
                        "records": [record.data for record in records],
                        "ttl": records[0].ttl,
                    },
                )

        txt_values = _first_data(responses["TXT"].of_type("TXT"))
        spf = parse_spf(txt_values)

        dmarc_response = _query(ctx, f"_dmarc.{domain}", "TXT")
        dmarc_values = _first_data(dmarc_response.of_type("TXT"))
        dmarc = parse_dmarc(dmarc_values)
        if dmarc:
            report.add(
                category="email_auth",
                subject=f"_dmarc.{domain}",
                summary="DMARC record present.",
                details={"record": dmarc, "policy": dmarc_policy(dmarc)},
            )

        dnssec_enabled = False
        if not options.no_dnssec:
            ds_response = _query(ctx, domain, "DS")
            dnskey_response = _query(ctx, domain, "DNSKEY")
            dnssec_enabled = bool(ds_response.records or dnskey_response.records) or (
                ds_response.authenticated or dnskey_response.authenticated
            )
            report.stats["dnssec"] = int(dnssec_enabled)
            report.add(
                category="dnssec",
                subject=domain,
                summary="DNSSEC appears enabled."
                if dnssec_enabled
                else "No DNSSEC chain observed.",
                severity=Severity.INFO if dnssec_enabled else Severity.LOW,
                details={
                    "ds_records": len(ds_response.records),
                    "dnskey_records": len(dnskey_response.records),
                    "authenticated_data": ds_response.authenticated,
                },
            )

        for flag in evaluate_posture(spf, dmarc, dnssec_enabled=dnssec_enabled):
            report.add(
                category="email_posture",
                subject=flag.key,
                summary=flag.summary,
                severity=flag.severity,
                details=flag.details,
            )

        if not options.no_ct:
            self._collect_subdomains(ctx, report, domain, options.max_subdomains)
        return report

    def _collect_subdomains(
        self, ctx: PluginContext, report: Report, domain: str, maximum: int
    ) -> None:
        try:
            payload = ctx.http().get_json(CRTSH_URL, params={"q": f"%.{domain}", "output": "json"})
        except HttpError as exc:
            report.add(
                category="subdomains",
                subject=domain,
                summary=f"crt.sh lookup failed: {exc}",
                severity=Severity.LOW,
            )
            return
        if not isinstance(payload, list):
            report.add(
                category="subdomains",
                subject=domain,
                summary="crt.sh returned an unexpected response shape.",
                severity=Severity.LOW,
            )
            return
        rows = [row for row in payload if isinstance(row, Mapping)]
        subdomains = extract_subdomains(rows, domain)
        report.stats["subdomains"] = len(subdomains)
        for name in subdomains[:maximum]:
            report.add(
                category="subdomain",
                subject=name,
                summary="Subdomain observed in certificate transparency logs.",
                details={"source": "crt.sh"},
            )
        if len(subdomains) > maximum:
            report.metadata["subdomains_truncated"] = len(subdomains) - maximum
