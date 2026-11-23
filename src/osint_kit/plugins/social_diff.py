"""Follower/following analysis for an Instagram data export.

Two front ends share one pure core:

* :func:`compare` turns two account sets into non-followers, fans, and mutuals.
* :func:`snapshot_delta` compares a newer follower set with an older one.

Parsing is split by format and takes text, never a path. Path handling lives in
:func:`load_account_set` so every analysis function above it stays pure.
"""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from osint_kit.core.errors import ExportFormatError, InputError
from osint_kit.core.models import Report, Severity
from osint_kit.core.plugin import BasePlugin, PluginContext

USERNAME_RE = re.compile(r"^[A-Za-z0-9._]{1,30}$")

# Paths on instagram.com that are not profiles.
RESERVED_PATHS = frozenset(
    {
        "about",
        "accounts",
        "ads",
        "api",
        "ar",
        "business",
        "challenge",
        "creator",
        "data",
        "developer",
        "direct",
        "directory",
        "emails",
        "embed",
        "explore",
        "followers",
        "following",
        "graphql",
        "invite",
        "legal",
        "locations",
        "music",
        "nametag",
        "oauth",
        "p",
        "privacy",
        "public",
        "reel",
        "reels",
        "s",
        "session",
        "shopping",
        "static",
        "stories",
        "terms",
        "tv",
        "web",
        "your_activity",
    }
)

PROFILE_HOSTS = frozenset({"instagram.com", "www.instagram.com"})


@dataclass(frozen=True)
class FollowRecord:
    """One account entry from an export."""

    username: str
    canonical: str
    timestamp: datetime | None = None


@dataclass(frozen=True)
class AccountSet:
    """A deduplicated set of accounts plus provenance."""

    label: str
    usernames: frozenset[str]
    records: tuple[FollowRecord, ...] = ()
    sources: tuple[str, ...] = ()
    duplicates: int = 0

    def display(self, canonical: str) -> str:
        """Original spelling for a canonical username, when known."""
        for record in self.records:
            if record.canonical == canonical:
                return record.username
        return canonical


@dataclass(frozen=True)
class Comparison:
    """Set relationships between followers and following."""

    non_followers: tuple[str, ...]
    fans: tuple[str, ...]
    mutuals: tuple[str, ...]

    @property
    def counts(self) -> dict[str, int]:
        return {
            "non_followers": len(self.non_followers),
            "fans": len(self.fans),
            "mutuals": len(self.mutuals),
        }


@dataclass(frozen=True)
class SnapshotDelta:
    """Followers gained or lost between two exports."""

    new_followers: tuple[str, ...]
    lost_followers: tuple[str, ...]


class _ProfileAnchorParser(HTMLParser):
    """Collect ``(href, text)`` for every anchor in an export page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._href: str | None = None
        self._text: list[str] = []
        self.links: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        self._flush()
        for key, value in attrs:
            if key == "href" and value:
                self._href = value
                break

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a":
            self._flush()

    def close(self) -> None:
        self._flush()
        super().close()

    def _flush(self) -> None:
        if self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
        self._href = None
        self._text = []


def canonicalise(username: str) -> str:
    """Normalise a username for set comparison (Instagram is case-insensitive)."""
    return username.strip().lstrip("@").casefold()


def is_valid_username(username: str) -> bool:
    """Instagram's documented profile-name shape, plus no leading/trailing dot."""
    if not USERNAME_RE.match(username):
        return False
    if username.startswith(".") or username.endswith(".") or ".." in username:
        return False
    return username.casefold() not in RESERVED_PATHS


def username_from_href(href: str) -> str | None:
    """Extract a profile name from an instagram.com link, or ``None``."""
    parts = urlsplit(href.strip())
    host = (parts.hostname or "").lower()
    if host not in PROFILE_HOSTS:
        return None
    segments = [segment for segment in parts.path.split("/") if segment]
    if len(segments) != 1:
        return None
    candidate = segments[0]
    if not is_valid_username(candidate):
        return None
    return candidate


def parse_html_export(text: str, *, source: str = "<memory>") -> tuple[FollowRecord, ...]:
    """Parse an Instagram followers/following HTML page."""
    parser = _ProfileAnchorParser()
    try:
        parser.feed(text)
        parser.close()
    except Exception as exc:  # HTMLParser is lenient; guard pathological input.
        raise ExportFormatError(f"{source}: could not parse HTML ({exc})") from exc

    records: list[FollowRecord] = []
    for href, link_text in parser.links:
        username = username_from_href(href)
        if username is None:
            continue
        text_name = link_text.strip().lstrip("@")
        # Prefer the visible text when it is the same account as the href.
        if text_name and canonicalise(text_name) == canonicalise(username):
            username = text_name
        if not is_valid_username(username):
            continue
        records.append(FollowRecord(username=username, canonical=canonicalise(username)))

    if not records and not _looks_like_instagram_export(text):
        raise ExportFormatError(
            f"{source}: no Instagram profile links found. Expected a followers/following "
            "export page containing links such as https://www.instagram.com/<username>."
        )
    return tuple(records)


def _looks_like_instagram_export(text: str) -> bool:
    lowered = text[:200_000].casefold()
    markers = ("<title>followers", "<title>following", "instagram-logo", "www.instagram.com")
    return any(marker in lowered for marker in markers)


def parse_json_export(text: str, *, source: str = "<memory>") -> tuple[FollowRecord, ...]:
    """Parse Instagram's JSON export shapes (followers list / following object)."""
    try:
        payload = json.loads(text)
    except ValueError as exc:
        raise ExportFormatError(f"{source}: invalid JSON ({exc})") from exc

    found: list[FollowRecord] = []
    _collect_json_records(payload, found)
    if not found:
        raise ExportFormatError(
            f"{source}: JSON is valid but contains no Instagram account entries. Expected "
            "'string_list_data' records as shipped in followers_*.json / following.json."
        )
    return tuple(found)


def _collect_json_records(value: Any, out: list[FollowRecord]) -> None:
    if isinstance(value, dict):
        string_list = value.get("string_list_data")
        if isinstance(string_list, list):
            for entry in string_list:
                record = _record_from_json_entry(entry)
                if record is not None:
                    out.append(record)
        for key, child in value.items():
            if key != "string_list_data":
                _collect_json_records(child, out)
    elif isinstance(value, list):
        if value and all(isinstance(item, str) for item in value):
            for item in value:
                maybe = item.strip().lstrip("@")
                if is_valid_username(maybe):
                    out.append(FollowRecord(username=maybe, canonical=canonicalise(maybe)))
        else:
            for child in value:
                _collect_json_records(child, out)


def _record_from_json_entry(entry: Any) -> FollowRecord | None:
    if not isinstance(entry, dict):
        return None
    username = entry.get("value") or entry.get("username")
    if not isinstance(username, str):
        href = entry.get("href")
        if isinstance(href, str):
            username = username_from_href(href)
            if username is None:
                return None
        else:
            return None
    username = username.strip().lstrip("@")
    if not is_valid_username(username):
        return None
    timestamp = _timestamp(entry.get("timestamp"))
    return FollowRecord(username=username, canonical=canonicalise(username), timestamp=timestamp)


def _timestamp(value: Any) -> datetime | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(value, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def parse_export(text: str, *, source: str = "<memory>") -> tuple[FollowRecord, ...]:
    """Parse either export format, sniffing JSON versus HTML."""
    stripped = text.lstrip("\ufeff \t\r\n")
    if stripped.startswith(("{", "[")):
        return parse_json_export(text, source=source)
    return parse_html_export(text, source=source)


def read_export_text(path: Path) -> str:
    """Read an export file with BOM tolerance (I/O edge)."""
    try:
        return path.read_text(encoding="utf-8-sig")
    except FileNotFoundError as exc:
        raise InputError(f"export file not found: {path}") from exc
    except OSError as exc:
        raise InputError(f"could not read {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise InputError(f"{path} is not valid UTF-8 text: {exc}") from exc


def load_account_set(paths: Sequence[Path], *, label: str) -> AccountSet:
    """Load one or more export files or directories into an :class:`AccountSet`."""
    files = expand_export_paths(paths, label=label)
    records: list[FollowRecord] = []
    sources: list[str] = []
    for path in files:
        parsed = parse_export(read_export_text(path), source=str(path))
        records.extend(parsed)
        sources.append(str(path))
    if not files:
        raise InputError(f"no {label} export files found in: {', '.join(str(p) for p in paths)}")
    return build_account_set(label, records, sources=sources)


def expand_export_paths(paths: Sequence[Path], *, label: str) -> tuple[Path, ...]:
    """Resolve files and directories to a sorted, de-duplicated file list."""
    found: list[Path] = []
    for path in paths:
        if path.is_dir():
            for suffix in ("html", "json"):
                found.extend(sorted(path.glob(f"{label}*.{suffix}")))
            if label == "following":
                found.extend(sorted(path.glob("following.json")))
        elif path.exists():
            found.append(path)
        else:
            raise InputError(f"path does not exist: {path}")
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in found:
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique.append(path)
    return tuple(unique)


def build_account_set(
    label: str,
    records: Iterable[FollowRecord],
    *,
    sources: Sequence[str] = (),
) -> AccountSet:
    """Deduplicate records and freeze them into an :class:`AccountSet`."""
    unique: dict[str, FollowRecord] = {}
    duplicates = 0
    for record in records:
        if record.canonical in unique:
            duplicates += 1
            continue
        unique[record.canonical] = record
    ordered = tuple(unique[key] for key in sorted(unique))
    return AccountSet(
        label=label,
        usernames=frozenset(unique),
        records=ordered,
        sources=tuple(sources),
        duplicates=duplicates,
    )


def compare(followers: AccountSet, following: AccountSet) -> Comparison:
    """Compute non-followers, fans, and mutuals.

    Set algebra replaces the original nested ``in list`` scan: O(n + m)
    hash lookups instead of O(n * m) comparisons.
    """
    non_followers = following.usernames - followers.usernames
    fans = followers.usernames - following.usernames
    mutuals = followers.usernames & following.usernames
    return Comparison(
        non_followers=tuple(sorted(non_followers)),
        fans=tuple(sorted(fans)),
        mutuals=tuple(sorted(mutuals)),
    )


def snapshot_delta(previous: AccountSet, current: AccountSet) -> SnapshotDelta:
    """Followers gained and lost between two snapshots."""
    new_followers = current.usernames - previous.usernames
    lost_followers = previous.usernames - current.usernames
    return SnapshotDelta(
        new_followers=tuple(sorted(new_followers)),
        lost_followers=tuple(sorted(lost_followers)),
    )


class SocialDiffPlugin(BasePlugin):
    """Compare followers and following from an Instagram export."""

    NAME = "social_diff"
    SUMMARY = "Diff followers vs following from an Instagram export (local files only)."
    NETWORK = False

    def configure_parser(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--followers",
            nargs="+",
            action="extend",
            type=Path,
            required=True,
            metavar="PATH",
            help="followers_*.html/.json files, or a directory containing them",
        )
        parser.add_argument(
            "--following",
            nargs="+",
            action="extend",
            type=Path,
            required=True,
            metavar="PATH",
            help="following.html/.json, or a directory containing them",
        )
        parser.add_argument(
            "--previous",
            nargs="+",
            action="extend",
            type=Path,
            default=None,
            metavar="PATH",
            help="older export (followers) to compare against for gained/lost followers",
        )
        parser.add_argument(
            "--include-mutuals",
            action="store_true",
            help="emit a finding for every mutual follow (noisy on large accounts)",
        )

    def run(self, options: argparse.Namespace, ctx: PluginContext) -> Report:
        followers = load_account_set(options.followers, label="followers")
        following = load_account_set(options.following, label="following")
        comparison = compare(followers, following)

        report = Report(
            plugin=self.name,
            target=f"{len(followers.usernames)} followers / {len(following.usernames)} following",
            metadata={
                "followers_sources": list(followers.sources),
                "following_sources": list(following.sources),
                "followers_duplicates_skipped": followers.duplicates,
                "following_duplicates_skipped": following.duplicates,
            },
        )
        report.stats.update(
            {
                "followers": len(followers.usernames),
                "following": len(following.usernames),
                **comparison.counts,
            }
        )

        for name in comparison.non_followers:
            display = followers.display(name)
            report.add(
                category="non_follower",
                subject=display,
                summary="You follow this account but it does not follow you back.",
                severity=Severity.INFO,
                details={"username": display},
            )
        for name in comparison.fans:
            display = followers.display(name)
            report.add(
                category="fan",
                subject=display,
                summary="This account follows you and you do not follow it back.",
                severity=Severity.INFO,
                details={"username": display},
            )
        if options.include_mutuals:
            for name in comparison.mutuals:
                display = followers.display(name)
                report.add(
                    category="mutual",
                    subject=display,
                    summary="You and this account follow each other.",
                    details={"username": display},
                )

        if options.previous:
            previous = load_account_set(options.previous, label="followers")
            delta = snapshot_delta(previous, followers)
            report.stats["new_followers"] = len(delta.new_followers)
            report.stats["lost_followers"] = len(delta.lost_followers)
            report.metadata["previous_sources"] = list(previous.sources)
            for name in delta.new_followers:
                display = followers.display(name)
                report.add(
                    category="new_follower",
                    subject=display,
                    summary="New follower since the previous snapshot.",
                    details={"username": display},
                )
            for name in delta.lost_followers:
                display = previous.display(name)
                report.add(
                    category="lost_follower",
                    subject=display,
                    summary="Follower present in the previous snapshot, gone now.",
                    details={"username": display},
                )

        return report
