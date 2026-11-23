"""username_check: allowlist, response classification, robots handling."""

from __future__ import annotations

import argparse
from typing import Any

import httpx
import pytest

from osint_kit.core.errors import UsageError
from osint_kit.plugins.username_check import (
    SITE_KEYS,
    SITES,
    Site,
    UsernameCheckPlugin,
    check_site,
    evaluate_response,
    guard_url,
    results_by_verdict,
    selected_sites,
    site_url,
    validate_username,
)


def test_site_table_is_twenty_unique_sites() -> None:
    assert len(SITES) == 20
    assert len(SITE_KEYS) == 20
    assert len(set(SITE_KEYS)) == 20
    assert all(site.url_template.startswith("https://") for site in SITES)


def test_evaluate_response_cases() -> None:
    github = next(site for site in SITES if site.key == "github")
    assert evaluate_response(github, 404, "") == ("available", "HTTP 404")
    assert evaluate_response(github, 200, "")[0] == "taken"
    assert evaluate_response(github, 403, "")[0] == "unknown"
    assert evaluate_response(github, 500, "")[0] == "unknown"

    hackernews = next(site for site in SITES if site.key == "hackernews")
    verdict, detail = evaluate_response(hackernews, 200, "No such user.")
    assert verdict == "available"
    assert "body marker" in detail


def test_username_validation_and_urls() -> None:
    assert validate_username("@octocat") == "octocat"
    with pytest.raises(UsageError):
        validate_username("bad user")
    with pytest.raises(UsageError):
        validate_username("")
    with pytest.raises(UsageError):
        validate_username("-nope")

    sourcehut = next(site for site in SITES if site.key == "sourcehut")
    assert site_url(sourcehut, "octocat") == "https://sr.ht/~octocat/"

    fake = Site("fake", "Fake", "https://allowed.example/{u}")
    guard_url(fake, "https://allowed.example/octocat")
    with pytest.raises(UsageError, match="refusing to contact"):
        guard_url(fake, "https://evil.example/octocat")


def test_selected_sites_allowlist() -> None:
    assert selected_sites(None) == SITES
    assert [site.key for site in selected_sites(["github", "github", "gitlab"])] == [
        "github",
        "gitlab",
    ]
    with pytest.raises(UsageError, match="allowed sites"):
        selected_sites(["myspace"])


def test_check_site_with_injected_fetch() -> None:
    github = next(site for site in SITES if site.key == "github")
    result = check_site(github, "octocat", lambda _url: (404, ""))
    assert result.verdict == "available"
    assert result.url == "https://github.com/octocat"
    assert results_by_verdict([result]) == {"available": ("github",)}


def profile_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/robots.txt":
        return httpx.Response(200, text="User-agent: *\nAllow: /\n")
    host = request.url.host
    if host == "github.com":
        return httpx.Response(200, text="<html>profile</html>")
    if host == "news.ycombinator.com":
        return httpx.Response(200, text="No such user.")
    return httpx.Response(404, text="missing")


def test_plugin_end_to_end(context_factory: Any) -> None:
    ctx = context_factory(profile_handler)
    options = argparse.Namespace(
        username="octocat", sites=["github", "gitlab", "hackernews"], no_robots=False
    )
    report = UsernameCheckPlugin().run(options, ctx)
    assert report.stats["sites"] == 3
    assert report.stats["taken"] == 1
    assert report.stats["available"] == 2
    assert report.stats["unknown"] == 0
    verdicts = {
        finding.subject: finding.details["verdict"]
        for finding in report.findings
        if finding.category == "username_status"
    }
    assert verdicts == {"github": "taken", "gitlab": "available", "hackernews": "available"}


def test_robots_disallow_is_respected(context_factory: Any) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nDisallow: /\n")
        return httpx.Response(200, text="should not be fetched")

    ctx = context_factory(handler)
    report = UsernameCheckPlugin().run(
        argparse.Namespace(username="octocat", sites=["reddit"], no_robots=False), ctx
    )
    assert report.stats["skipped_robots"] == 1
    assert "robots.txt" in report.findings[0].summary
    assert report.findings[0].details["verdict"] == "skipped"


def test_no_robots_opt_out(context_factory: Any) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nDisallow: /\n")
        return httpx.Response(200, text="profile")

    ctx = context_factory(handler)
    report = UsernameCheckPlugin().run(
        argparse.Namespace(username="octocat", sites=["reddit"], no_robots=True), ctx
    )
    assert report.stats["taken"] == 1
    assert "skipped_robots" not in report.stats


def test_plugin_rejects_bad_username(context_factory: Any) -> None:
    with pytest.raises(UsageError):
        UsernameCheckPlugin().run(
            argparse.Namespace(username="no spaces", sites=None, no_robots=False),
            context_factory(),
        )
