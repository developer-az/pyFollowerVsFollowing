"""Benchmark guard rail: the set diff must beat the original list scan.

The full 100k run lives in ``benchmarks/bench_social_diff.py``; this test keeps
a smaller size so the suite stays fast, while still measuring real work
(millions of string comparisons).
"""

from __future__ import annotations

import pytest
from benchmarks.bench_social_diff import run

SIZE = 3_000


@pytest.mark.benchmark
def test_set_diff_matches_and_beats_list_scan() -> None:
    result = run(SIZE)
    assert result.identical is True
    # The asymptotic gap is enormous; 2x is a conservative CI guard against noise.
    assert result.speedup > 2.0, result.as_dict()
    assert result.set_seconds < result.original_seconds
