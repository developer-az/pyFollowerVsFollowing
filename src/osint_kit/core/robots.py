"""robots.txt handling for the only plugin that touches many third-party hosts.

We fetch each host's robots.txt once, parse it with the standard library, and
treat fetch failures as "allowed" (the conventional behaviour) while recording
the reason in the finding's details.
"""

from __future__ import annotations

from urllib.parse import urlsplit
from urllib.robotparser import RobotFileParser

from osint_kit.core.errors import HttpError
from osint_kit.core.http import HttpClient

DEFAULT_ROBOTS_USER_AGENT = "osint-kit"


def parse_robots(text: str) -> RobotFileParser:
    """Build a parser from robots.txt text (pure, no I/O)."""
    parser = RobotFileParser()
    parser.parse(text.splitlines())
    return parser


def path_allowed(
    parser: RobotFileParser, url: str, user_agent: str = DEFAULT_ROBOTS_USER_AGENT
) -> bool:
    """True when robots.txt permits fetching ``url``."""
    return parser.can_fetch(user_agent, url)


class RobotsCache:
    """Fetch and remember robots.txt per scheme+host."""

    def __init__(self, client: HttpClient, *, user_agent: str = DEFAULT_ROBOTS_USER_AGENT) -> None:
        self._client = client
        self._user_agent = user_agent
        self._parsed: dict[str, RobotFileParser] = {}

    def _load(self, url: str) -> RobotFileParser:
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        parser = self._parsed.get(origin)
        if parser is not None:
            return parser
        try:
            response = self._client.get(f"{origin}/robots.txt")
            text = response.text if response.status_code < 400 else ""
        except HttpError:
            text = ""
        parser = parse_robots(text)
        self._parsed[origin] = parser
        return parser

    def allowed(self, url: str) -> bool:
        return path_allowed(self._load(url), url, self._user_agent)
