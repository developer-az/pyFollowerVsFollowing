"""Backwards-compatible shim for the original follower/following script.

The YouTube tutorial runs ``python followerfollowing.py`` with
``followers_1.html`` and ``following.html`` in the current directory. That still
works; the real implementation now lives in ``osint_kit.plugins.social_diff``.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from osint_kit.plugins.social_diff import (
    build_account_set,
    compare,
    parse_html_export,
)

DEFAULT_FOLLOWERS = Path("followers_1.html")
DEFAULT_FOLLOWING = Path("following.html")


def extract_usernames_from_html(html_text: str) -> list[str]:
    """Legacy helper: usernames from an Instagram export page, in file order."""
    return [record.username for record in parse_html_export(html_text)]


def find_unfollowers(followers: Sequence[str], following: Sequence[str]) -> list[str]:
    """Legacy helper, now set-based instead of O(n*m) list membership."""
    follower_set = set(followers)
    return [user for user in following if user not in follower_set]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Original follower diff, now powered by osint-kit social_diff."
    )
    parser.add_argument("--followers", type=Path, default=DEFAULT_FOLLOWERS)
    parser.add_argument("--following", type=Path, default=DEFAULT_FOLLOWING)
    options = parser.parse_args(argv)

    try:
        followers_text = options.followers.read_text(encoding="utf-8")
        following_text = options.following.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: could not read export files: {exc}", file=sys.stderr)
        print(
            "Place followers_1.html and following.html in this directory, "
            "or pass --followers/--following.",
            file=sys.stderr,
        )
        return 1

    followers = build_account_set(
        "followers", parse_html_export(followers_text, source=str(options.followers))
    )
    following = build_account_set(
        "following", parse_html_export(following_text, source=str(options.following))
    )
    unfollowers = sorted(
        (following.display(name) for name in compare(followers, following).non_followers),
        key=str.casefold,
    )

    print(f"Number of people you follow who don't follow you back: {len(unfollowers)}")
    print("--------------------------------------------------------------------------")
    print("The list of people you follow who don't follow you back:")
    for username in unfollowers:
        print(username)
    return 0


if __name__ == "__main__":
    sys.exit(main())
