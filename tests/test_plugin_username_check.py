"""username_check: allowlist, response classification, robots handling."""

from __future__ import annotations

import argparse
from typing import Any

import httpx
import pytest

from osint_kit.core.errors import UsageError
from osint_kit.core.models import Severity
from osint_kit.plugins.username_check import (
    SITE_KEYS,
    SITES,
    Site,
    SiteResult,
    UsernameCheckPlugin,
    blocked_summary,
    check_site,
    evaluate_response,
    guard_url,
    results_by_verdict,
    selected_sites,
    site_url,
    validate_username,
)


def test_site_table_is_twenty_three_unique_sites() -> None:
    assert len(SITES) == 23
    assert len(SITE_KEYS) == 23
    assert len(set(SITE_KEYS)) == 23
    assert all(site.url_template.startswith("https://") for site in SITES)
    assert {"youtube", "bluesky", "mastodon"} <= set(SITE_KEYS)


def test_mastodon_uses_the_lookup_api_not_the_profile_page() -> None:
    mastodon = next(site for site in SITES if site.key == "mastodon")
    assert "/api/v1/accounts/lookup?acct=" in mastodon.url_template
    # the HTML profile page answers 410 to non-browser clients; the API does not
    assert site_url(mastodon, "MKBHD").endswith("acct=MKBHD")
    assert evaluate_response(mastodon, 404, '{"error":"Record not found"}')[0] == "available"
    assert evaluate_response(mastodon, 200, '{"id":"1","acct":"MKBHD"}')[0] == "taken"
    assert evaluate_response(mastodon, 410, "")[0] == "unknown"


def test_evaluate_response_cases() -> None:
    github = next(site for site in SITES if site.key == "github")
    assert evaluate_response(github, 404, "") == ("available", "HTTP 404")
    assert evaluate_response(github, 200, "")[0] == "taken"
    assert evaluate_response(github, 403, "") == ("blocked", "HTTP 403")
    assert evaluate_response(github, 429, "")[0] == "blocked"
    assert evaluate_response(github, 500, "")[0] == "unknown"

    hackernews = next(site for site in SITES if site.key == "hackernews")
    verdict, detail = evaluate_response(hackernews, 200, "No such user.")
    assert verdict == "available"
    assert "body marker" in detail


def test_youtube_judges_by_status() -> None:
    youtube = next(site for site in SITES if site.key == "youtube")
    assert site_url(youtube, "mkbhd") == "https://www.youtube.com/@mkbhd"
    assert evaluate_response(youtube, 404, "not found")[0] == "available"
    assert evaluate_response(youtube, 200, "channel")[0] == "taken"


def test_bluesky_judges_by_handle_in_the_body() -> None:
    bluesky = next(site for site in SITES if site.key == "bluesky")
    found = '{"actors":[{"did":"did:plc:x","handle":"octocat.bsky.social"}]}'
    custom = '{"actors":[{"did":"did:plc:x","handle":"octocat.dev"}]}'
    missing = '{"actors":[]}'

    verdict, detail = evaluate_response(bluesky, 200, found, username="octocat")
    assert verdict == "taken"
    assert "body marker" in detail
    assert evaluate_response(bluesky, 200, custom, username="octocat")[0] == "taken"
    assert evaluate_response(bluesky, 200, found, username="someoneelse")[0] == "available"
    assert evaluate_response(bluesky, 200, missing, username="octocat")[0] == "available"
    # a gatekeeping proxy must not turn into "available"
    assert evaluate_response(bluesky, 403, "", username="octocat")[0] == "blocked"


def test_blocked_summary_names_the_hosts() -> None:
    sites = [next(site for site in SITES if site.key == key) for key in SITE_KEYS[:6]]
    blocked = [
        SiteResult(site=site, url="https://example.test", verdict="blocked", status=403)
        for site in sites
    ]

    summary = blocked_summary(blocked, 23)

    assert summary.startswith("blocked: 6 of 23 sites refused the request")
    assert sites[0].label in summary
    assert "and 2 more" in summary
    assert "unknown" in summary


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


def test_blocked_sites_collapse_into_one_warning(context_factory: Any) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nAllow: /\n")
        if request.url.host == "github.com":
            return httpx.Response(403, text="go away")
        return httpx.Response(404, text="missing")

    report = UsernameCheckPlugin().run(
        argparse.Namespace(username="octocat", sites=["github", "gitlab"], no_robots=False),
        context_factory(handler),
    )

    assert report.stats["blocked"] == 1
    assert report.stats["available"] == 1
    blocked = [item for item in report.findings if item.details.get("verdict") == "blocked"]
    assert len(blocked) == 1
    assert blocked[0].subject == "1 site"
    assert blocked[0].severity == Severity.LOW
    assert blocked[0].details["sites"] == {"github": 403}
    assert all(item.subject != "github" for item in report.findings)
    assert "GitHub 403" in blocked[0].summary


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
