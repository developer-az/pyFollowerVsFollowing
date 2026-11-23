"""Benchmark the set-based diff against the original list-membership loop.

The original tutorial code was:

    [user for user in following if user not in followers]

with ``followers`` a list, which is O(n*m). ``osint_kit`` uses sets, which is
O(n+m). Run the full 100k comparison with:

    python benchmarks/bench_social_diff.py --size 100000

CI runs the same comparison at a smaller size via tests/test_benchmark.py.
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass

from osint_kit.plugins.social_diff import AccountSet, compare


@dataclass(frozen=True)
class Result:
    size: int
    original_seconds: float
    set_seconds: float
    speedup: float
    identical: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "size": self.size,
            "original_seconds": round(self.original_seconds, 3),
            "set_seconds": round(self.set_seconds, 3),
            "speedup": round(self.speedup, 1),
            "identical": self.identical,
        }


def build_lists(size: int) -> tuple[list[str], list[str]]:
    """Disjoint name spaces: worst case for the original algorithm."""
    followers = [f"follower{index:07d}" for index in range(size)]
    following = [f"following{index:07d}" for index in range(size)]
    return followers, following


def original_unfollowers(followers: list[str], following: list[str]) -> list[str]:
    """The original tutorial implementation, kept verbatim for comparison."""
    return [user for user in following if user not in followers]


def run(size: int) -> Result:
    followers, following = build_lists(size)

    started = time.perf_counter()
    original = original_unfollowers(followers, following)
    original_seconds = time.perf_counter() - started

    follower_set = AccountSet("followers", frozenset(followers))
    following_set = AccountSet("following", frozenset(following))
    started = time.perf_counter()
    comparison = compare(follower_set, following_set)
    set_seconds = time.perf_counter() - started

    identical = sorted(original) == sorted(comparison.non_followers)
    speedup = original_seconds / set_seconds if set_seconds else float("inf")
    return Result(
        size=size,
        original_seconds=original_seconds,
        set_seconds=set_seconds,
        speedup=speedup,
        identical=identical,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", type=int, default=100_000, help="usernames per list")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    options = parser.parse_args()
    if options.size <= 0:
        parser.error("--size must be positive")

    print(f"building {options.size:,} usernames per side...", flush=True)
    result = run(options.size)
    if options.json:
        print(json.dumps(result.as_dict()))
    else:
        print(f"size:               {result.size:,}")
        print(f"original (list in): {result.original_seconds:.3f}s")
        print(f"set-based compare:  {result.set_seconds:.4f}s")
        print(f"speedup:            {result.speedup:,.1f}x")
        print(f"same result:        {result.identical}")
    return 0 if result.identical else 1


if __name__ == "__main__":
    raise SystemExit(main())
