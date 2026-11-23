"""The Browse pickers: which questions get one, and what they list."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from osint_kit.tui import picker
from osint_kit.tui.fields import Field
from osint_kit.tui.picker import Target, entries, parent_of, start_directory, target_for


def make_field(dest: str, kind: str = "path") -> Field:
    return Field(
        dest=dest,
        flag=None,
        label=dest,
        kind=kind,  # type: ignore[arg-type]
        required=False,
        default=None,
        help="",
    )


def test_target_matches_case_insensitively() -> None:
    target = Target(title="Images", patterns=("*.jpg", "*.png"))
    assert target.matches("Photo.JPG")
    assert not target.matches("notes.txt")


def test_only_questions_that_read_files_get_a_picker() -> None:
    assert target_for("social_diff", make_field("followers", "paths")) is not None
    assert target_for("hashing", make_field("file")) is not None
    assert target_for("hashing", make_field("text", "text")) is None
    assert target_for("exif", make_field("dest")) is None


def test_folder_capable_questions_allow_a_folder() -> None:
    followed = target_for("social_diff", make_field("followers", "paths"))
    assert followed is not None
    assert followed.folder_ok is True
    assert followed.title  # the question wording, not the metavar

    image = target_for("exif", make_field("images", "paths"))
    assert image is not None
    assert image.folder_ok is False


def test_entries_lists_folders_then_matching_files(tmp_path: Path) -> None:
    (tmp_path / "b_folder").mkdir()
    (tmp_path / "a_folder").mkdir()
    (tmp_path / "b.html").write_text("x", encoding="utf-8")
    (tmp_path / "a.html").write_text("x", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("x", encoding="utf-8")
    (tmp_path / ".hidden.html").write_text("x", encoding="utf-8")

    listed = entries(tmp_path, Target(title="Export", patterns=("*.html",)))

    assert [entry.path.name for entry in listed] == [
        "a_folder",
        "b_folder",
        "a.html",
        "b.html",
    ]
    assert [entry.is_dir for entry in listed] == [True, True, False, False]


def test_entries_accepts_everything_for_a_wildcard_target(tmp_path: Path) -> None:
    (tmp_path / "one.bin").write_text("x", encoding="utf-8")

    listed = entries(tmp_path, Target(title="Any file"))

    assert [entry.path.name for entry in listed] == ["one.bin"]


def test_entries_survives_an_unreadable_folder(tmp_path: Path) -> None:
    assert entries(tmp_path / "missing", Target(title="Any")) == []


def test_entries_can_show_hidden_files(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("x", encoding="utf-8")

    assert entries(tmp_path, Target(title="Any")) == []
    assert [
        entry.path.name for entry in entries(tmp_path, Target(title="Any"), show_hidden=True)
    ] == [".env"]


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        (None, "cwd"),
        ("missing-file", "cwd"),
        ("folder", "folder"),
        ("folder/file.html", "folder"),
    ],
)
def test_start_directory_opens_next_to_what_was_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, given: str | None, expected: str
) -> None:
    (tmp_path / "folder").mkdir()
    (tmp_path / "folder" / "file.html").write_text("x", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    start = None if given is None else tmp_path / given
    expected_path = tmp_path if expected == "cwd" else tmp_path / expected

    assert start_directory(start) == expected_path


def test_parent_of_stops_at_a_root() -> None:
    root = Path(Path.cwd().anchor)

    assert parent_of(root / "work") == root
    assert parent_of(root) is None


def test_native_dialog_is_off_outside_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    picker._importable.cache_clear()

    assert picker.native_available() is False

    picker._importable.cache_clear()
