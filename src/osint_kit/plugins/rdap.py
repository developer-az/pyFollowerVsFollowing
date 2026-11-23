"""RDAP registration lookups for domains and IP addresses.

RDAP is the structured successor to WHOIS. We query the public rdap.org
bootstrap, parse the JSON, and (for IPs) enrich the ASN through Team Cymru's
public DNS service over DoH.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from osint_kit.core.errors import HttpError, UsageError
from osint_kit.core.models import Report, Severity
from osint_kit.core.plugin import BasePlugin, PluginContext
from osint_kit.plugins.domain_recon import DOH_URL, normalise_domain, parse_doh, unquote_txt

RDAP_BASE = "https://rdap.org"
_ASN_RE = re.compile(r"^(?:AS)?(\d{1,10})$", re.IGNORECASE)


@dataclass(frozen=True)
class RdapEvent:
    action: str
    date: str | None


@dataclass(frozen=True)
class RdapDomain:
    handle: str | None
    name: str | None
    statuses: tuple[str, ...]
    events: tuple[RdapEvent, ...]
    registrar: str | None
    nameservers: tuple[str, ...]


@dataclass(frozen=True)
class RdapIp:
    handle: str | None
    name: str | None
    start_address: str | None
    end_address: str | None
    ip_version: str | None
    country: str | None
    cidrs: tuple[str, ...]
    asn: int | None
    as_name: str | None
    events: tuple[RdapEvent, ...]


@dataclass(frozen=True)
class AsnInfo:
    asn: int | None
    prefix: str | None
    country: str | None
    registry: str | None
    as_name: str | None = None


def _entities(payload: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    entities = payload.get("entities")
    if not isinstance(entities, list):
        return []
    result: list[Mapping[str, Any]] = []
    for entity in entities:
        if isinstance(entity, Mapping):
            result.append(entity)
            nested = entity.get("entities")
            if isinstance(nested, list):
                for child in nested:
                    if isinstance(child, Mapping):
                        result.append(child)
    return result


def vcard_name(entity: Mapping[str, Any]) -> str | None:
    """Extract the ``fn`` value from an RDAP jCard."""
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) != 2:
        return None
    fields = vcard[1]
    if not isinstance(fields, list):
        return None
    for field in fields:
        if not isinstance(field, list) or len(field) < 4:
            continue
        if field[0] == "fn" and isinstance(field[3], str):
            return field[3]
    return None


def _events(payload: Mapping[str, Any]) -> tuple[RdapEvent, ...]:
    events = payload.get("events")
    if not isinstance(events, list):
        return ()
    parsed: list[RdapEvent] = []
    for event in events:
        if not isinstance(event, Mapping):
            continue
        action = event.get("eventAction")
        date = event.get("eventDate")
        if isinstance(action, str):
            parsed.append(RdapEvent(action=action, date=date if isinstance(date, str) else None))
    return tuple(parsed)


def _find_asn(entities: Iterable[Mapping[str, Any]]) -> tuple[int | None, str | None]:
    for entity in entities:
        handle = entity.get("handle")
        if isinstance(handle, str):
            match = _ASN_RE.match(handle.strip())
            if match:
                return int(match.group(1)), vcard_name(entity)
    return None, None


def parse_domain_rdap(payload: Mapping[str, Any]) -> RdapDomain:
    """Parse a domain RDAP response."""
    statuses = payload.get("status")
    nameservers = payload.get("nameservers")
    registrar: str | None = None
    for entity in _entities(payload):
        roles = entity.get("roles")
        if isinstance(roles, list) and "registrar" in roles:
            registrar = vcard_name(entity)
            if registrar:
                break
    ns_names: list[str] = []
    if isinstance(nameservers, list):
        for server in nameservers:
            if isinstance(server, Mapping):
                name = server.get("ldhName")
                if isinstance(name, str):
                    ns_names.append(name.lower())
    return RdapDomain(
        handle=_str_or_none(payload.get("handle")),
        name=_str_or_none(payload.get("ldhName")),
        statuses=tuple(str(item) for item in statuses) if isinstance(statuses, list) else (),
        events=_events(payload),
        registrar=registrar,
        nameservers=tuple(ns_names),
    )


def parse_ip_rdap(payload: Mapping[str, Any]) -> RdapIp:
    """Parse an IP network RDAP response, including ASN when present."""
    cidrs: list[str] = []
    raw_cidrs = payload.get("cidr0_cidrs")
    if isinstance(raw_cidrs, list):
        for entry in raw_cidrs:
            if not isinstance(entry, Mapping):
                continue
            prefix = entry.get("v4prefix") or entry.get("v6prefix")
            length = entry.get("length")
            if isinstance(prefix, str) and isinstance(length, int):
                cidrs.append(f"{prefix}/{length}")
    entities = _entities(payload)
    asn, as_name = _find_asn(entities)
    return RdapIp(
        handle=_str_or_none(payload.get("handle")),
        name=_str_or_none(payload.get("name")),
        start_address=_str_or_none(payload.get("startAddress")),
        end_address=_str_or_none(payload.get("endAddress")),
        ip_version=_str_or_none(payload.get("ipVersion")),
        country=_str_or_none(payload.get("country")),
        cidrs=tuple(cidrs),
        asn=asn,
        as_name=as_name,
        events=_events(payload),
    )


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def parse_cymru_origin(txt_data: str) -> AsnInfo:
    """Parse Team Cymru's origin TXT: ``asn | prefix | cc | registry | date``."""
    fields = [field.strip() for field in unquote_txt(txt_data).split("|")]
    asn: int | None = None
    if fields and fields[0].isdigit():
        asn = int(fields[0])
    return AsnInfo(
        asn=asn,
        prefix=fields[1] if len(fields) > 1 and fields[1] else None,
        country=fields[2] if len(fields) > 2 and fields[2] else None,
        registry=fields[3] if len(fields) > 3 and fields[3] else None,
    )


def parse_cymru_asn(txt_data: str) -> str | None:
    """Parse Team Cymru's ASN-name TXT and return the description."""
    fields = [field.strip() for field in unquote_txt(txt_data).split("|")]
    if len(fields) >= 5 and fields[4]:
        return fields[4]
    return None


def classify_target(value: str) -> tuple[str, str]:
    """Return ``("ip", canonical)`` or ``("domain", normalised)``."""
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return "domain", normalise_domain(value)
    return "ip", str(address)


def reverse_origin_name(address: str) -> str:
    """Build ``<reversed octets>.origin.asn.cymru.com`` for an IP."""
    parsed = ipaddress.ip_address(address)
    if parsed.version == 4:
        reversed_octets = ".".join(reversed(str(parsed).split(".")))
        return f"{reversed_octets}.origin.asn.cymru.com"
    nibbles = parsed.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def _query_txt(ctx: PluginContext, name: str) -> str | None:
    payload = ctx.http().get_json(DOH_URL, params={"name": name, "type": "TXT"})
    if not isinstance(payload, Mapping):
        return None
    response = parse_doh(payload)
    for record in response.of_type("TXT"):
        return record.data
    return None


class RdapPlugin(BasePlugin):
    """Domain or IP registration data, with ASN and netblock where available."""

    NAME = "rdap"
    SUMMARY = "Domain/IP registration via RDAP, with ASN and netblock enrichment."
    NETWORK = True

    def configure_parser(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("target", metavar="DOMAIN_OR_IP")
        parser.add_argument("--no-asn", action="store_true", help="skip Team Cymru ASN lookup")
        parser.add_argument("--max-nameservers", type=int, default=50, metavar="N")

    def run(self, options: argparse.Namespace, ctx: PluginContext) -> Report:
        kind, target = classify_target(options.target)
        url = f"{RDAP_BASE}/{kind}/{target}"
        report = Report(
            plugin=self.name,
            target=target,
            metadata={"rdap_url": url, "target_type": kind},
        )
        try:
            payload = ctx.http().get_json(url, headers={"Accept": "application/rdap+json"})
        except HttpError as exc:
            if exc.status == 404:
                report.add(
                    category="rdap",
                    subject=target,
                    summary="No RDAP object found for this target.",
                    severity=Severity.MEDIUM,
                )
                return report
            raise
        if not isinstance(payload, Mapping):
            raise HttpError("RDAP returned an unexpected JSON shape", url=url)

        report.add(
            category="rdap_object",
            subject=target,
            summary=f"RDAP {kind} object returned.",
            details={"handle": payload.get("handle"), "type": kind},
        )
        if kind == "domain":
            self._report_domain(report, target, payload, options.max_nameservers)
        else:
            self._report_ip(ctx, report, target, payload, skip_asn=options.no_asn)
        return report

    def _report_domain(
        self,
        report: Report,
        target: str,
        payload: Mapping[str, Any],
        max_nameservers: int,
    ) -> None:
        domain = parse_domain_rdap(payload)
        report.stats["nameservers"] = len(domain.nameservers)
        report.stats["events"] = len(domain.events)
        if domain.registrar:
            report.add(
                category="registrar",
                subject=target,
                summary=f"Registrar: {domain.registrar}",
                details={"registrar": domain.registrar},
            )
        for event in domain.events:
            report.add(
                category="registration_event",
                subject=target,
                summary=f"{event.action}: {event.date or 'unknown date'}",
                details={"action": event.action, "date": event.date},
            )
        for status in domain.statuses:
            report.add(
                category="domain_status",
                subject=target,
                summary=f"Status: {status}",
                details={"status": status},
            )
        for nameserver in domain.nameservers[:max_nameservers]:
            report.add(
                category="nameserver",
                subject=nameserver,
                summary="Nameserver from RDAP.",
                details={"nameserver": nameserver},
            )
        if domain.name:
            report.metadata["ldh_name"] = domain.name

    def _report_ip(
        self,
        ctx: PluginContext,
        report: Report,
        target: str,
        payload: Mapping[str, Any],
        *,
        skip_asn: bool,
    ) -> None:
        network = parse_ip_rdap(payload)
        netblock = (
            f"{network.start_address} - {network.end_address}"
            if network.start_address and network.end_address
            else None
        )
        report.stats["cidrs"] = len(network.cidrs)
        report.add(
            category="netblock",
            subject=target,
            summary=netblock or "Netblock range not present in the response.",
            details={
                "start": network.start_address,
                "end": network.end_address,
                "cidrs": list(network.cidrs),
                "name": network.name,
                "country": network.country,
                "ip_version": network.ip_version,
            },
        )
        asn = network.asn
        as_name = network.as_name
        if not skip_asn:
            enriched = self._lookup_asn(ctx, report, target)
            asn = asn or enriched.asn
            as_name = as_name or enriched.as_name
            if enriched.prefix and not network.cidrs:
                report.stats["cymru_prefix"] = 1
                report.metadata["cymru_prefix"] = enriched.prefix
        if asn is not None:
            report.add(
                category="asn",
                subject=f"AS{asn}",
                summary=f"AS{asn}" + (f" ({as_name})" if as_name else ""),
                details={"asn": asn, "name": as_name},
            )
        else:
            report.add(
                category="asn",
                subject=target,
                summary="ASN could not be determined from RDAP or Team Cymru.",
                severity=Severity.LOW,
            )
        for event in network.events:
            report.add(
                category="registration_event",
                subject=target,
                summary=f"{event.action}: {event.date or 'unknown date'}",
                details={"action": event.action, "date": event.date},
            )

    def _lookup_asn(self, ctx: PluginContext, report: Report, target: str) -> AsnInfo:
        try:
            origin_txt = _query_txt(ctx, reverse_origin_name(target))
        except HttpError as exc:
            report.add(
                category="asn",
                subject=target,
                summary=f"Team Cymru lookup failed: {exc}",
                severity=Severity.LOW,
            )
            return AsnInfo(asn=None, prefix=None, country=None, registry=None)
        if origin_txt is None:
            return AsnInfo(asn=None, prefix=None, country=None, registry=None)
        info = parse_cymru_origin(origin_txt)
        if info.asn is None:
            return info
        try:
            asn_txt = _query_txt(ctx, f"AS{info.asn}.asn.cymru.com")
        except HttpError:
            asn_txt = None
        name = parse_cymru_asn(asn_txt) if asn_txt else None
        return AsnInfo(
            asn=info.asn,
            prefix=info.prefix,
            country=info.country,
            registry=info.registry,
            as_name=name,
        )


def requires_target(value: str) -> None:
    """Validation helper used by tests to document accepted inputs."""
    if not value.strip():
        raise UsageError("target cannot be empty")
