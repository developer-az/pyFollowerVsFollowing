"""Typed errors shared by every plugin.

Errors are part of the CLI contract: :class:`OsintKitError` maps to exit code 2
and a single-line message on stderr, so no plugin needs to print.
"""

from __future__ import annotations


class OsintKitError(Exception):
    """Base class for errors the CLI can present to a human."""


class UsageError(OsintKitError):
    """The user asked for something impossible or contradictory."""


class InputError(OsintKitError):
    """A local input file is missing, unreadable, or malformed."""


class ExportFormatError(InputError):
    """An export file is valid HTML/JSON but not a recognisable export."""


class NetworkDisabledError(OsintKitError):
    """A network plugin was run with ``--offline``."""


class HttpError(OsintKitError):
    """A request failed after retries, or returned an unusable response."""

    def __init__(self, message: str, *, url: str | None = None, status: int | None = None) -> None:
        super().__init__(message)
        self.url = url
        self.status = status


class RobotsDenied(OsintKitError):
    """A URL is disallowed by the target host's robots.txt."""


class ParseError(InputError):
    """A structured document could not be parsed."""
