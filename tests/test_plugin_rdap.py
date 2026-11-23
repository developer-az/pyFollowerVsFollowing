"""RDAP parsing and plugin flow."""

from __future__ import annotations

import argparse
from typing import Any

import httpx
import pytest

from osint_kit.core.errors import UsageError
from osint_kit.plugins.domain_recon import DOH_URL
from osint_kit.plugins.rdap import (
    RDAP_BASE,
    RdapPlugin,
    classify_target,
    parse_cymru_asn,
    parse_cymru_origin,
    parse_domain_rdap,
    parse_ip_rdap,
    requires_target,
    reverse_origin_name,
    vcard_name,
)
from tests.conftest import load_json


def test_parse_domain_rdap_fixture() -> None:
    domain = parse_domain_rdap(load_json("network/rdap_domain.json"))
    assert domain.handle == "2336799_DOMAIN_COM-VRSN"
    assert domain.registrar == "RESERVED-Internet Assigned Numbers Authority"
    assert domain.nameservers == ("a.iana-servers.net", "b.iana-servers.net")
    assert [event.action for event in domain.events] == ["registration", "expiration"]
    assert domain.statuses == ("client transfer prohibited",)


def test_parse_ip_rdap_fixture() -> None:
    network = parse_ip_rdap(load_json("network/rdap_ip.json"))
    assert network.start_address == "8.8.8.0"
    assert network.end_address == "8.8.8.255"
    assert network.cidrs == ("8.8.8.0/24",)
    assert network.country == "US"
    assert network.as_name is None
    assert network.asn is None


def test_parse_rdap_with_asn_entity() -> None:
    payload = {
        "handle": "NET",
        "entities": [
            {"handle": "AS15169", "vcardArray": ["vcard", [["fn", {}, "text", "Google"]]]}
        ],
        "cidr0_cidrs": [{"v4prefix": "1.2.3.0", "length": 24}, {"length": 24}],
    }
    network = parse_ip_rdap(payload)
    assert network.asn == 15169
    assert network.cidrs == ("1.2.3.0/24",)


def test_vcard_name_edges() -> None:
    assert vcard_name({"vcardArray": ["vcard", [["fn", {}, "text", "Name"]]]}) == "Name"
    assert vcard_name({"vcardArray": ["vcard", [["x", {}, "text", "Nope"]]]}) is None
    assert vcard_name({"vcardArray": "bad"}) is None
    assert vcard_name({}) is None


def test_cymru_parsing() -> None:
    origin = parse_cymru_origin('"15169 | 8.8.8.0/24 | US | arin | 2014-03-14"')
    assert origin.asn == 15169
    assert origin.prefix == "8.8.8.0/24"
    assert origin.country == "US"
    assert origin.registry == "arin"
    assert parse_cymru_origin('" | | | "').asn is None
    assert parse_cymru_asn('"15169 | US | arin | 2000-03-30 | GOOGLE, US"') == "GOOGLE, US"
    assert parse_cymru_asn('"15169"') is None


def test_classify_and_reverse() -> None:
    assert classify_target("8.8.8.8") == ("ip", "8.8.8.8")
    assert classify_target(" Example.COM ") == ("domain", "example.com")
    with pytest.raises(UsageError):
        classify_target("not a domain")

    assert reverse_origin_name("8.8.8.8") == "8.8.8.8.origin.asn.cymru.com"
    v6 = reverse_origin_name("2001:db8::1")
    assert v6.startswith("1.0.0.0.") and v6.endswith(".origin6.asn.cymru.com")


def test_requires_target() -> None:
    requires_target("x")
    with pytest.raises(UsageError):
        requires_target("  ")


def test_domain_plugin(context_factory: Any) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).startswith(f"{RDAP_BASE}/domain/example.com"):
            return httpx.Response(200, json=load_json("network/rdap_domain.json"))
        return httpx.Response(404)

    ctx = context_factory(handler)
    options = argparse.Namespace(target="example.com", no_asn=False, max_nameservers=50)
    report = RdapPlugin().run(options, ctx)
    categories = {finding.category for finding in report.findings}
    assert {
        "rdap_object",
        "registrar",
        "registration_event",
        "domain_status",
        "nameserver",
    } <= categories
    assert report.stats["nameservers"] == 2
    assert report.metadata["target_type"] == "domain"


def test_ip_plugin_with_asn_enrichment(context_factory: Any) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.startswith(f"{RDAP_BASE}/ip/8.8.8.8"):
            return httpx.Response(200, json=load_json("network/rdap_ip.json"))
        if url.startswith(DOH_URL):
            name = request.url.params.get("name", "")
            if name == "8.8.8.8.origin.asn.cymru.com":
                data = '"15169 | 8.8.8.0/24 | US | arin | 2014-03-14"'
            elif name == "AS15169.asn.cymru.com":
                data = '"15169 | US | arin | 2000-03-30 | GOOGLE, US"'
            else:
                data = '"15169"'
            return httpx.Response(
                200,
                json={"Status": 0, "Answer": [{"name": name, "type": 16, "TTL": 60, "data": data}]},
            )
        return httpx.Response(404)

    ctx = context_factory(handler)
    options = argparse.Namespace(target="8.8.8.8", no_asn=False, max_nameservers=50)
    report = RdapPlugin().run(options, ctx)
    asn_findings = [finding for finding in report.findings if finding.category == "asn"]
    assert asn_findings and asn_findings[0].subject == "AS15169"
    assert "GOOGLE" in asn_findings[0].summary
    netblock = next(finding for finding in report.findings if finding.category == "netblock")
    assert netblock.summary == "8.8.8.0 - 8.8.8.255"


def test_ip_plugin_without_asn(context_factory: Any) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "/ip/" in str(request.url):
            return httpx.Response(200, json=load_json("network/rdap_ip.json"))
        return httpx.Response(500)

    ctx = context_factory(handler)
    options = argparse.Namespace(target="8.8.8.8", no_asn=True, max_nameservers=50)
    report = RdapPlugin().run(options, ctx)
    assert not any(
        finding.category == "asn" and finding.subject.startswith("AS")
        for finding in report.findings
    )
    # RDAP's registrant entity has no AS handle, so the plugin reports an unknown ASN.
    assert any(finding.category == "asn" for finding in report.findings)


def test_plugin_404_and_cymru_failure(context_factory: Any) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="not found")

    ctx = context_factory(handler)
    options = argparse.Namespace(target="203.0.113.1", no_asn=False, max_nameservers=50)
    report = RdapPlugin().run(options, ctx)
    assert report.findings[0].category == "rdap"

    def failing(request: httpx.Request) -> httpx.Response:
        if "/ip/" in str(request.url):
            return httpx.Response(200, json=load_json("network/rdap_ip.json"))
        return httpx.Response(503, text="down")

    ctx = context_factory(failing)
    report = RdapPlugin().run(options, ctx)
    assert any(
        finding.category == "asn" and "Cymru" in finding.summary for finding in report.findings
    )
