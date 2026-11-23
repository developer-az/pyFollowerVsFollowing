"""Username availability across a fixed allowlist of public profile pages.

Only GETs against the hosts listed in :data:`SITES` are possible. robots.txt is
respected per host, and the core per-host rate limiter applies. A 200 is not
proof of ownership; results are heuristic and say so.
"""

from __future__ import annotations

import argparse
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

from osint_kit.core.errors import UsageError
from osint_kit.core.models import Report, Severity
from osint_kit.core.plugin import BasePlugin, PluginContext

Verdict = Literal["taken", "available", "unknown", "blocked", "skipped"]

USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,38}$")

#: Statuses that mean "the host refused to answer", not "the account is missing".
BLOCKED_STATUSES = frozenset({401, 403, 406, 429, 451, 503})


@dataclass(frozen=True)
class Site:
    """One allowlisted public profile endpoint.

    ``missing_markers`` and ``taken_markers`` are searched case-insensitively in
    the body and may contain ``{u}``, which is replaced with the handle. Set
    ``body_decides`` for endpoints that answer 200 whatever you ask; the markers
    then decide, and a 2xx without a match means the handle is free.
    """

    key: str
    label: str
    url_template: str
    missing_status: tuple[int, ...] = (404,)
    taken_status: tuple[int, ...] = (200,)
    missing_markers: tuple[str, ...] = ()
    taken_markers: tuple[str, ...] = ()
    body_decides: bool = False
    requires_robots: bool = True
    note: str = ""


SITES: tuple[Site, ...] = (
    Site("github", "GitHub", "https://github.com/{u}"),
    Site("gitlab", "GitLab", "https://gitlab.com/{u}"),
    Site("bitbucket", "Bitbucket", "https://bitbucket.org/{u}/"),
    Site("codeberg", "Codeberg", "https://codeberg.org/{u}"),
    Site("gitea", "Gitea", "https://gitea.com/{u}"),
    Site("devto", "DEV Community", "https://dev.to/{u}"),
    Site("pypi", "PyPI", "https://pypi.org/user/{u}/"),
    Site("rubygems", "RubyGems", "https://rubygems.org/profiles/{u}"),
    Site("npm", "npm", "https://www.npmjs.com/~{u}"),
    Site("dockerhub", "Docker Hub", "https://hub.docker.com/v2/users/{u}/"),
    Site(
        "hackernews",
        "Hacker News",
        "https://news.ycombinator.com/user?id={u}",
        missing_markers=("no such user",),
        note="Returns HTTP 200 for missing users; body marker decides.",
    ),
    Site("reddit", "Reddit", "https://www.reddit.com/user/{u}/", requires_robots=True),
    Site(
        "bluesky",
        "Bluesky",
        "https://public.api.bsky.app/xrpc/app.bsky.actor.searchActorsTypeahead?q={u}&limit=10",
        taken_markers=('"handle":"{u}.', '"handle":"{u}"'),
        body_decides=True,
        note="Matched on handle prefix; confirm the profile is the one you mean.",
    ),
    Site(
        "mastodon",
        "Mastodon",
        "https://mastodon.social/api/v1/accounts/lookup?acct={u}",
        note="Checks mastodon.social only; every instance has its own handle space.",
    ),
    Site("soundcloud", "SoundCloud", "https://soundcloud.com/{u}"),
    Site("vimeo", "Vimeo", "https://vimeo.com/{u}"),
    Site("youtube", "YouTube", "https://www.youtube.com/@{u}"),
    Site("aboutme", "About.me", "https://about.me/{u}"),
    Site("letterboxd", "Letterboxd", "https://letterboxd.com/{u}/"),
    Site("lastfm", "Last.fm", "https://www.last.fm/user/{u}"),
    Site("codepen", "CodePen", "https://codepen.io/{u}"),
    Site("sourcehut", "SourceHut", "https://sr.ht/~{u}/"),
    Site("keybase", "Keybase", "https://keybase.io/{u}", note="Presence is a weak signal."),
)

SITE_KEYS: tuple[str, ...] = tuple(site.key for site in SITES)
_BY_KEY: dict[str, Site] = {site.key: site for site in SITES}


@dataclass(frozen=True)
class SiteResult:
    """Outcome for one site."""

    site: Site
    url: str
    verdict: Verdict
    status: int | None = None
    detail: str = ""


def validate_username(username: str) -> str:
    candidate = username.strip().lstrip("@")
    if not USERNAME_RE.match(candidate):
        raise UsageError(
            "username must be 1-39 characters of letters, digits, dot, underscore "
            "or hyphen, starting with a letter or digit"
        )
    return candidate


def site_url(site: Site, username: str) -> str:
    """Build a URL for an allowlisted site. The host always comes from the table."""
    safe = validate_username(username)
    return site.url_template.format(u=safe)


def guard_url(site: Site, url: str) -> None:
    """Fail closed if a URL no longer points at the site's expected host."""
    expected = urlsplit(site.url_template.format(u="placeholder")).hostname
    actual = urlsplit(url).hostname
    if expected != actual:
        raise UsageError(f"refusing to contact {actual!r}; allowlisted host is {expected!r}")


def evaluate_response(
    site: Site, status_code: int, body: str, *, username: str = ""
) -> tuple[Verdict, str]:
    """Classify one response.

    Body markers are checked before status so sites that answer 200 for everyone
    (Hacker News) and sites that answer 200 for nobody in particular (Bluesky)
    are both handled honestly. ``blocked`` is kept apart from ``unknown``: those
    hosts refused the request, so the run says nothing about the handle.
    """
    lowered = body.casefold()

    def markers(items: tuple[str, ...]) -> list[str]:
        return [item.format(u=username).casefold() for item in items if item]

    for marker in markers(site.missing_markers):
        if marker in lowered:
            return "available", f"body marker {marker!r}"
    for marker in markers(site.taken_markers):
        if marker in lowered:
            return "taken", f"body marker {marker!r}"
    if status_code in BLOCKED_STATUSES:
        return "blocked", f"HTTP {status_code}"
    if site.body_decides:
        if 200 <= status_code < 300:
            return "available", "no matching profile in the body"
        return "unknown", f"HTTP {status_code}"
    if status_code in site.missing_status:
        return "available", f"HTTP {status_code}"
    if status_code in site.taken_status:
        return "taken", f"HTTP {status_code}"
    return "unknown", f"HTTP {status_code}"


def blocked_summary(blocked: Sequence[SiteResult], total: int, *, named: int = 4) -> str:
    """One line naming the hosts that refused the request."""
    shown = ", ".join(f"{result.site.label} {result.status}" for result in blocked[:named])
    rest = len(blocked) - named
    more = f" and {rest} more" if rest > 0 else ""
    return (
        f"blocked: {len(blocked)} of {total} sites refused the request "
        f"({shown}{more}); treat those as unknown."
    )


def check_site(
    site: Site,
    username: str,
    fetch: Callable[[str], tuple[int, str]],
) -> SiteResult:
    """Check one site through an injected fetch function (pure control flow)."""
    url = site_url(site, username)
    guard_url(site, url)
    status_code, body = fetch(url)
    verdict, detail = evaluate_response(site, status_code, body, username=username)
    return SiteResult(site=site, url=url, verdict=verdict, status=status_code, detail=detail)


def selected_sites(keys: Sequence[str] | None) -> tuple[Site, ...]:
    """Resolve ``--site`` values against the allowlist."""
    if not keys:
        return SITES
    chosen: list[Site] = []
    for key in keys:
        site = _BY_KEY.get(key)
        if site is None:
            raise UsageError(f"unknown site {key!r}; allowed sites: {', '.join(SITE_KEYS)}")
        if site not in chosen:
            chosen.append(site)
    return tuple(chosen)


class UsernameCheckPlugin(BasePlugin):
    """Check a username against 23 public profile pages."""

    NAME = "username_check"
    SUMMARY = "Check username availability on 23 allowlisted public sites (robots-aware)."
    NETWORK = True

    def configure_parser(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("username", metavar="USERNAME")
        parser.add_argument(
            "--site",
            action="append",
            choices=SITE_KEYS,
            dest="sites",
            metavar="SITE",
            help=f"limit to allowlisted site(s): {', '.join(SITE_KEYS)}",
        )
        parser.add_argument(
            "--no-robots",
            action="store_true",
            help="skip the robots.txt check (not recommended)",
        )

    def run(self, options: argparse.Namespace, ctx: PluginContext) -> Report:
        username = validate_username(options.username)
        sites = selected_sites(options.sites)
        report = Report(
            plugin=self.name,
            target=username,
            metadata={
                "sites": [site.key for site in sites],
                "note": "A 200 does not prove ownership; verify manually before relying on it.",
            },
        )
        client = ctx.http()
        blocked: list[SiteResult] = []
        for site in sites:
            url = site_url(site, username)
            guard_url(site, url)
            if site.requires_robots and not options.no_robots and not ctx.robots().allowed(url):
                report.add(
                    category="username_status",
                    subject=site.key,
                    summary="Skipped: robots.txt disallows this path.",
                    severity=Severity.INFO,
                    details={"url": url, "verdict": "skipped"},
                )
                report.stats["skipped_robots"] = report.stats.get("skipped_robots", 0) + 1
                continue
            response = client.get(
                url,
                headers={
                    "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en",
                },
            )
            verdict, detail = evaluate_response(
                site, response.status_code, response.text, username=username
            )
            result = SiteResult(
                site=site, url=url, verdict=verdict, status=response.status_code, detail=detail
            )
            if verdict == "blocked":
                blocked.append(result)
                continue
            report.add(
                category="username_status",
                subject=site.key,
                summary=f"{verdict}: {detail}",
                severity=Severity.INFO,
                details={
                    "url": url,
                    "status": response.status_code,
                    "verdict": verdict,
                    "detail": detail,
                    "note": site.note,
                },
            )
            report.stats[verdict] = report.stats.get(verdict, 0) + 1
        if blocked:
            report.add(
                category="username_status",
                subject=f"{len(blocked)} site{'' if len(blocked) == 1 else 's'}",
                summary=blocked_summary(blocked, len(sites)),
                severity=Severity.LOW,
                details={
                    "verdict": "blocked",
                    "sites": {result.site.key: result.status for result in blocked},
                    "urls": {result.site.key: result.url for result in blocked},
                },
            )
            report.stats["blocked"] = len(blocked)
        report.stats["sites"] = len(sites)
        report.stats.setdefault("taken", 0)
        report.stats.setdefault("available", 0)
        report.stats.setdefault("unknown", 0)
        return report


def results_by_verdict(results: Iterable[SiteResult]) -> Mapping[str, tuple[str, ...]]:
    """Group site keys by verdict (handy for tests and callers)."""
    grouped: dict[str, list[str]] = {}
    for result in results:
        grouped.setdefault(result.verdict, []).append(result.site.key)
    return {verdict: tuple(keys) for verdict, keys in grouped.items()}
