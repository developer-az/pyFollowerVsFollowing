"""domain_recon: DoH parsing, SPF/DMARC posture, CT subdomains, plugin flow."""

from __future__ import annotations

import argparse
from typing import Any, cast

import httpx
import pytest

from osint_kit.core.errors import UsageError
from osint_kit.plugins.domain_recon import (
    DOH_URL,
    DomainReconPlugin,
    dmarc_has_rua,
    dmarc_policy,
    evaluate_posture,
    extract_subdomains,
    normalise_domain,
    parse_dmarc,
    parse_doh,
    parse_spf,
    unquote_txt,
)
from tests.conftest import load_json

SPF_RECORD = '"v=spf1 include:_spf.example.net ip4:198.51.100.0/24 -all"'
DMARC_RECORD = '"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"'


def test_parse_doh_fixture() -> None:
    response = parse_doh(load_json("network/doh_a.json"))
    assert response.found
    assert response.authenticated is False
    assert len(response.of_type("A")) == 2
    assert response.of_type("A")[0].data == "203.0.113.10"
    assert response.of_type("MX") == ()


def test_parse_doh_survives_bad_fields() -> None:
    response = parse_doh(
        {"Status": "weird", "Answer": [{"type": 1}, "junk", {"type": 15, "data": "x"}]}
    )
    assert response.status == 2
    assert len(response.records) == 1


def test_domain_normalisation() -> None:
    assert normalise_domain(" Example.COM. ") == "example.com"
    assert normalise_domain("bücher.example") == "xn--bcher-kva.example"
    for bad in ("", "no-dot", "-bad.example", "space here.example"):
        with pytest.raises(UsageError):
            normalise_domain(bad)


def test_unquote_and_spf_parsing() -> None:
    assert unquote_txt(SPF_RECORD) == "v=spf1 include:_spf.example.net ip4:198.51.100.0/24 -all"
    assert unquote_txt("bare-record") == "bare-record"

    summary = parse_spf([SPF_RECORD, '"v=spf1 -all"'])
    assert summary is not None
    assert summary.all_qualifier == "-"
    assert summary.includes == ("_spf.example.net",)
    assert parse_spf(['"unrelated"']) is None
    assert parse_spf(['"v=spf1 a mx"']).all_qualifier is None  # type: ignore[union-attr]
    assert parse_spf(['"v=spf1 ?all"']).all_qualifier == "?"  # type: ignore[union-attr]


def test_dmarc_parsing() -> None:
    record = parse_dmarc(['"v=DMARC1; p=quarantine"', DMARC_RECORD])
    assert record == "v=DMARC1; p=quarantine"
    assert dmarc_policy(DMARC_RECORD) == "reject"
    assert dmarc_has_rua(DMARC_RECORD) is True
    assert dmarc_has_rua("v=DMARC1; p=none") is False
    assert parse_dmarc(['"nothing"']) is None


def test_posture_flags_cover_common_misconfigurations() -> None:
    flags = {flag.key for flag in evaluate_posture(None, None, dnssec_enabled=False)}
    assert flags == {"spf_missing", "dmarc_missing", "dnssec_missing"}

    permissive = parse_spf(['"v=spf1 +all"'])
    good_dmarc = "v=DMARC1; p=reject; rua=mailto:x@example.com"
    flags = {flag.key for flag in evaluate_posture(permissive, good_dmarc, dnssec_enabled=True)}
    assert flags == {"spf_permissive"}

    soft = parse_spf(['"v=spf1 ~all"'])
    flags = {flag.key for flag in evaluate_posture(soft, good_dmarc, dnssec_enabled=True)}
    assert flags == {"spf_softfail"}

    neutral = parse_spf(['"v=spf1 ?all"'])
    flags = {flag.key for flag in evaluate_posture(neutral, good_dmarc, dnssec_enabled=True)}
    assert flags == {"spf_neutral"}

    no_all = parse_spf(['"v=spf1 a"'])
    flags = {flag.key for flag in evaluate_posture(no_all, good_dmarc, dnssec_enabled=True)}
    assert flags == {"spf_no_all"}

    flags = {
        flag.key
        for flag in evaluate_posture(
            parse_spf([SPF_RECORD]), "v=DMARC1; p=none", dnssec_enabled=True
        )
    }
    assert flags == {"dmarc_policy_none", "dmarc_no_rua"}


def test_extract_subdomains_filters_and_dedupes() -> None:
    subdomains = extract_subdomains(load_json("network/crt_sh.json"), "example.com")
    assert subdomains == ("api.example.com", "mail.example.com", "www.example.com")


def test_extract_subdomains_rejects_bad_labels() -> None:
    rows = [{"name_value": "bad_label.example.com\n-ok.example.com\nxn--bcher-kva.example.com"}]
    assert extract_subdomains(rows, "example.com") == ("xn--bcher-kva.example.com",)


def doh_response(record_type: str, name: str) -> dict[str, Any]:
    if record_type == "A":
        return cast(dict[str, Any], load_json("network/doh_a.json"))
    if record_type == "AAAA":
        return {
            "Status": 0,
            "Answer": [{"name": name, "type": 28, "TTL": 60, "data": "2001:db8::1"}],
        }
    if record_type == "MX":
        return {
            "Status": 0,
            "Answer": [{"name": name, "type": 15, "TTL": 60, "data": "10 mail.example.com."}],
        }
    if record_type == "NS":
        return {
            "Status": 0,
            "Answer": [{"name": name, "type": 2, "TTL": 60, "data": "ns1.example.com."}],
        }
    if record_type == "TXT":
        if name.startswith("_dmarc."):
            return {
                "Status": 0,
                "Answer": [{"name": name, "type": 16, "TTL": 60, "data": DMARC_RECORD}],
            }
        return {
            "Status": 0,
            "Answer": [{"name": name, "type": 16, "TTL": 60, "data": SPF_RECORD}],
        }
    if record_type in {"DS", "DNSKEY"}:
        return {"Status": 0, "AD": True, "Answer": []}
    return {"Status": 0, "Answer": []}


def test_plugin_end_to_end(context_factory: Any) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).startswith(DOH_URL):
            name = request.url.params.get("name", "")
            record_type = request.url.params.get("type", "")
            return httpx.Response(200, json=doh_response(record_type, name))
        if "crt.sh" in str(request.url):
            return httpx.Response(200, json=load_json("network/crt_sh.json"))
        return httpx.Response(404)

    ctx = context_factory(handler)
    options = argparse.Namespace(
        domain="example.com", no_ct=False, no_dnssec=False, max_subdomains=10
    )
    report = DomainReconPlugin().run(options, ctx)
    assert report.stats["dns_a"] == 2
    assert report.stats["dns_aaaa"] == 1
    assert report.stats["dns_mx"] == 1
    assert report.stats["dns_ns"] == 1
    assert report.stats["dnssec"] == 1
    assert report.stats["subdomains"] == 3
    categories = {finding.category for finding in report.findings}
    assert {"dns", "email_auth", "dnssec", "subdomain"} <= categories
    assert not any(finding.category == "email_posture" for finding in report.findings)


def test_plugin_nxdomain_short_circuits(context_factory: Any) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json={"Status": 3, "Answer": []})

    ctx = context_factory(handler)
    options = argparse.Namespace(
        domain="example.com", no_ct=False, no_dnssec=False, max_subdomains=10
    )
    report = DomainReconPlugin().run(options, ctx)
    assert report.stats["nxdomain"] == 1
    assert len(calls) == 1
    assert report.findings[0].severity.value == "high"


def test_plugin_skips_ct_and_dnssec(context_factory: Any) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        record_type = request.url.params.get("type", "")
        name = request.url.params.get("name", "")
        return httpx.Response(200, json=doh_response(record_type, name))

    options = argparse.Namespace(
        domain="example.com", no_ct=True, no_dnssec=True, max_subdomains=10
    )
    ctx = context_factory(handler)
    report = DomainReconPlugin().run(options, ctx)
    assert "subdomains" not in report.stats
    assert "dnssec" not in report.stats


def test_plugin_handles_crt_failure(context_factory: Any) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "crt.sh" in str(request.url):
            return httpx.Response(503, text="unavailable")
        record_type = request.url.params.get("type", "")
        name = request.url.params.get("name", "")
        return httpx.Response(200, json=doh_response(record_type, name))

    ctx = context_factory(handler)
    options = argparse.Namespace(
        domain="example.com", no_ct=False, no_dnssec=True, max_subdomains=10
    )
    report = DomainReconPlugin().run(options, ctx)
    assert any(
        finding.category == "subdomains" and "failed" in finding.summary
        for finding in report.findings
    )


def test_plugin_handles_unexpected_shapes(context_factory: Any) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "crt.sh" in str(request.url):
            return httpx.Response(200, json={"unexpected": True})
        record_type = request.url.params.get("type", "")
        name = request.url.params.get("name", "")
        return httpx.Response(200, json=doh_response(record_type, name))

    ctx = context_factory(handler)
    options = argparse.Namespace(
        domain="example.com", no_ct=False, no_dnssec=True, max_subdomains=10
    )
    report = DomainReconPlugin().run(options, ctx)
    assert any(finding.category == "subdomains" for finding in report.findings)
