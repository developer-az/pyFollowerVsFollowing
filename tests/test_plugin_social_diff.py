"""social_diff: HTML/JSON parsing, set algebra, snapshots, and the legacy shim."""

from __future__ import annotations

import importlib.util
import string
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from osint_kit.core.errors import ExportFormatError, InputError
from osint_kit.plugins.social_diff import (
    AccountSet,
    canonicalise,
    compare,
    expand_export_paths,
    is_valid_username,
    load_account_set,
    parse_export,
    parse_html_export,
    parse_json_export,
    snapshot_delta,
    username_from_href,
)

FIXTURE_HTML = "tests/fixtures/instagram_html"
FIXTURE_JSON = "tests/fixtures/instagram_json"

USERNAME_ALPHABET = string.ascii_letters + string.digits + "._"


def names(records: object) -> set[str]:
    return {record.canonical for record in records}  # type: ignore[attr-defined]


def test_parse_html_export_extracts_profiles_only(fixtures: Path) -> None:
    text = (fixtures / "instagram_html" / "followers_1.html").read_text(encoding="utf-8")
    records = parse_html_export(text)
    assert names(records) == {"alice", "bob", "carol"}
    assert [record.username for record in records] == ["alice", "bob", "carol"]


def test_parse_html_handles_unclosed_anchor(fixtures: Path) -> None:
    text = (fixtures / "instagram_html" / "following.html").read_text(encoding="utf-8")
    records = parse_html_export(text)
    assert names(records) == {"alice", "bob", "dave", "frank"}


def test_parse_html_rejects_non_instagram_page(fixtures: Path) -> None:
    text = (fixtures / "instagram_html" / "not_instagram.html").read_text(encoding="utf-8")
    with pytest.raises(ExportFormatError, match="no Instagram profile links"):
        parse_html_export(text, source="not_instagram.html")


def test_parse_html_empty_page_with_marker_is_empty_export() -> None:
    assert parse_html_export("<html><title>Followers</title></html>") == ()


def test_username_from_href_rules() -> None:
    assert username_from_href("https://www.instagram.com/alice") == "alice"
    assert username_from_href("https://instagram.com/bob/?hl=en") == "bob"
    assert username_from_href("https://www.instagram.com/p/abc/") is None
    assert username_from_href("https://example.com/alice") is None
    assert username_from_href("https://www.instagram.com/nested/alice") is None
    assert username_from_href("https://www.instagram.com/explore") is None


def test_username_validation() -> None:
    assert is_valid_username("a.b_c-1") is False  # hyphen is not allowed on Instagram
    assert is_valid_username("a.b_c.1")
    assert not is_valid_username(".dotstart")
    assert not is_valid_username("dotend.")
    assert not is_valid_username("two..dots")
    assert not is_valid_username("reels")
    assert canonicalise("  @Alice ") == "alice"


def test_pagination_and_duplicates(fixtures: Path) -> None:
    account_set = load_account_set([fixtures / "instagram_html"], label="followers")
    assert account_set.usernames == frozenset({"alice", "bob", "carol", "erin"})
    assert account_set.duplicates == 2
    assert len(account_set.sources) == 2


def test_load_json_exports(fixtures: Path) -> None:
    followers = load_account_set(
        [fixtures / "instagram_json" / "followers_1.json"], label="followers"
    )
    following = load_account_set(
        [fixtures / "instagram_json" / "following.json"], label="following"
    )
    assert followers.usernames == frozenset({"alice", "bob", "carol"})
    assert following.usernames == frozenset({"alice", "dave"})
    record = next(record for record in followers.records if record.canonical == "alice")
    assert record.timestamp is not None and record.timestamp.year == 2024


def test_parse_with_plain_string_list() -> None:
    records = parse_json_export('["alice", "bob"]')
    assert names(records) == {"alice", "bob"}


def test_malformed_json_exports(fixtures: Path) -> None:
    text = (fixtures / "instagram_json" / "not_an_export.json").read_text(encoding="utf-8")
    with pytest.raises(ExportFormatError, match="no Instagram account entries"):
        parse_json_export(text)
    with pytest.raises(ExportFormatError, match="invalid JSON"):
        parse_json_export("{oops")
    with pytest.raises(ExportFormatError, match="invalid JSON"):
        parse_export("{oops")


def test_parse_export_sniffs_html(fixtures: Path) -> None:
    text = (fixtures / "instagram_html" / "followers_1.html").read_text(encoding="utf-8")
    assert names(parse_export(text)) == {"alice", "bob", "carol"}


def test_expand_paths_and_errors(fixtures: Path, tmp_path: Path) -> None:
    files = expand_export_paths([fixtures / "instagram_html"], label="following")
    assert [path.name for path in files] == ["following.html"]
    with pytest.raises(InputError, match="does not exist"):
        expand_export_paths([tmp_path / "missing.html"], label="followers")
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(InputError, match="no followers export files"):
        load_account_set([empty], label="followers")


def test_read_export_text_errors(tmp_path: Path) -> None:
    from osint_kit.plugins.social_diff import read_export_text

    with pytest.raises(InputError, match="not found"):
        read_export_text(tmp_path / "nope.html")
    invalid = tmp_path / "bad.html"
    invalid.write_bytes(b"\xff\xfe\x00bad")
    with pytest.raises(InputError, match="UTF-8"):
        read_export_text(invalid)
    with pytest.raises(InputError, match="does not exist"):
        load_account_set([tmp_path / "missing.html"], label="followers")


def test_compare_and_snapshot_delta(fixtures: Path) -> None:
    followers = load_account_set([fixtures / "instagram_html"], label="followers")
    following = load_account_set(
        [fixtures / "instagram_html" / "following.html"], label="following"
    )
    result = compare(followers, following)
    assert result.non_followers == ("dave", "frank")
    assert result.fans == ("carol", "erin")
    assert result.mutuals == ("alice", "bob")
    assert result.counts == {"non_followers": 2, "fans": 2, "mutuals": 2}

    previous = load_account_set([fixtures / "instagram_html" / "previous"], label="followers")
    delta = snapshot_delta(previous, followers)
    assert delta.new_followers == ("carol", "erin")
    assert delta.lost_followers == ("grace",)


def test_display_prefers_first_seen_spelling(fixtures: Path) -> None:
    followers = load_account_set(
        [fixtures / "instagram_html" / "followers_1.html"], label="followers"
    )
    assert followers.display("alice") == "alice"
    assert followers.display("unknown") == "unknown"


def test_snapshot_identical_sets() -> None:
    account_set = AccountSet(label="followers", usernames=frozenset({"alice"}))
    delta = snapshot_delta(account_set, account_set)
    assert delta.new_followers == ()
    assert delta.lost_followers == ()


def test_legacy_shim_still_works(fixtures: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = Path(__file__).parents[1] / "followerfollowing.py"
    spec = importlib.util.spec_from_file_location("legacy_shim", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    text = (fixtures / "instagram_html" / "following.html").read_text(encoding="utf-8")
    assert module.extract_usernames_from_html(text) == ["alice", "bob", "dave", "frank"]
    assert module.find_unfollowers(["alice"], ["alice", "dave"]) == ["dave"]

    code = module.main(
        [
            "--followers",
            str(fixtures / "instagram_html" / "followers_1.html"),
            "--following",
            str(fixtures / "instagram_html" / "following.html"),
        ]
    )
    assert code == 0
    output = capsys.readouterr().out
    assert "Number of people you follow who don't follow you back: 2" in output
    assert "dave" in output and "frank" in output

    code = module.main(["--followers", str(fixtures / "missing.html")])
    assert code == 1


# ---------------------------------------------------------------------------
# Property-based tests
# ---------------------------------------------------------------------------


@given(
    st.lists(
        st.text(alphabet=USERNAME_ALPHABET, min_size=1, max_size=30).filter(is_valid_username),
        min_size=0,
        max_size=25,
    )
)
def test_html_parser_roundtrip(usernames: list[str]) -> None:
    body = "".join(
        f'<div><a href="https://www.instagram.com/{name}">{name}</a></div>' for name in usernames
    )
    html = f"<html><head><title>Followers</title></head><body>{body}</body></html>"
    parsed = parse_html_export(html)
    assert {record.canonical for record in parsed} == {canonicalise(name) for name in usernames}


@given(
    st.sets(st.text(alphabet=USERNAME_ALPHABET, min_size=1, max_size=12), max_size=30),
    st.sets(st.text(alphabet=USERNAME_ALPHABET, min_size=1, max_size=12), max_size=30),
)
def test_compare_partitions_sets(left: set[str], right: set[str]) -> None:
    followers = AccountSet(label="followers", usernames=frozenset(left))
    following = AccountSet(label="following", usernames=frozenset(right))
    result = compare(followers, following)
    assert set(result.non_followers) == right - left
    assert set(result.fans) == left - right
    assert set(result.mutuals) == left & right
    assert not (set(result.non_followers) & set(result.mutuals))


@given(
    st.sets(st.text(min_size=1, max_size=20), max_size=20),
    st.sets(st.text(min_size=1, max_size=20), max_size=20),
)
def test_snapshot_delta_is_antisymmetric(old: set[str], current: set[str]) -> None:
    previous = AccountSet(label="followers", usernames=frozenset(old))
    latest = AccountSet(label="followers", usernames=frozenset(current))
    delta = snapshot_delta(previous, latest)
    assert set(delta.new_followers) == current - old
    assert set(delta.lost_followers) == old - current
