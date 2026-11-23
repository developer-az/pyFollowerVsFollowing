"""Find an Instagram export already sitting on this machine.

The common case is "I downloaded my export and I do not remember which folder
it went into", so the interactive flow looks in the obvious places and offers
whatever it finds instead of making the user type a path.
"""

from __future__ import annotations

import os
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

_FOLLOWERS_PATTERNS = ("followers_*.html", "followers_*.json", "followers.html", "followers.json")
_FOLLOWING_PATTERNS = ("following.html", "following.json")
_SKIP_DIRS = frozenset(
    {".git", ".venv", "node_modules", "__pycache__", "site-packages", "tests", "test", "fixtures"}
)


@dataclass(frozen=True)
class ExportCandidate:
    """A folder that looks like an Instagram export."""

    folder: Path
    followers: tuple[Path, ...]
    following: Path

    @property
    def label(self) -> str:
        return self.folder.name or str(self.folder)


def default_roots(home: Path | None = None, cwd: Path | None = None) -> list[Path]:
    """Places worth scanning, cheapest first."""
    home = home if home is not None else Path.home()
    roots = [cwd if cwd is not None else Path.cwd(), home / "Downloads", home / "Desktop"]
    return [root for root in roots if root.is_dir()]


def _walk_limited(root: Path, max_depth: int) -> Iterator[Path]:
    root = root.resolve()
    for current, dirs, _files in os.walk(root):
        path = Path(current)
        depth = len(path.relative_to(root).parts)
        dirs[:] = [name for name in dirs if not name.startswith(".") and name not in _SKIP_DIRS]
        if depth > max_depth:
            dirs[:] = []
            continue
        yield path


def _matches(folder: Path, patterns: Sequence[str]) -> tuple[Path, ...]:
    found: list[Path] = []
    for pattern in patterns:
        found.extend(sorted(folder.glob(pattern)))
    unique: dict[Path, None] = {}
    for path in found:
        unique.setdefault(path, None)
    return tuple(unique)


def find_exports(
    roots: Sequence[Path] | None = None, *, max_depth: int = 3, limit: int = 5
) -> list[ExportCandidate]:
    """Return up to ``limit`` export folders found under ``roots``."""
    candidates: list[ExportCandidate] = []
    seen: set[Path] = set()
    for root in roots if roots is not None else default_roots():
        if not root.is_dir():
            continue
        for folder in _walk_limited(root, max_depth):
            if folder in seen:
                continue
            followers = _matches(folder, _FOLLOWERS_PATTERNS)
            following = _matches(folder, _FOLLOWING_PATTERNS)
            if not followers or not following:
                continue
            seen.add(folder)
            candidates.append(ExportCandidate(folder, followers, following[0]))
            if len(candidates) >= limit:
                return candidates
    return candidates


__all__ = ["ExportCandidate", "default_roots", "find_exports"]
