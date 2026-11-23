"""Discovering an Instagram export already on disk."""

from __future__ import annotations

from pathlib import Path

from osint_kit.tui.detect import ExportCandidate, default_roots, find_exports


def make_export(folder: Path, *, json_format: bool = False) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    if json_format:
        (folder / "followers_1.json").write_text("[]", encoding="utf-8")
        (folder / "following.json").write_text("[]", encoding="utf-8")
    else:
        (folder / "followers_1.html").write_text("<html></html>", encoding="utf-8")
        (folder / "following.html").write_text("<html></html>", encoding="utf-8")
    return folder


def test_finds_html_export(tmp_path: Path) -> None:
    make_export(tmp_path / "instagram-export")
    found = find_exports([tmp_path])
    assert len(found) == 1
    assert found[0].folder.name == "instagram-export"
    assert found[0].following.name == "following.html"
    assert len(found[0].followers) == 1


def test_finds_json_export(tmp_path: Path) -> None:
    make_export(tmp_path / "export", json_format=True)
    found = find_exports([tmp_path])
    assert len(found) == 1
    assert found[0].followers[0].suffix == ".json"


def test_ignores_folders_without_a_pair(tmp_path: Path) -> None:
    lonely = tmp_path / "half"
    lonely.mkdir()
    (lonely / "followers_1.html").write_text("<html></html>", encoding="utf-8")
    assert find_exports([tmp_path]) == []


def test_respects_depth_limit(tmp_path: Path) -> None:
    deep = tmp_path / "a" / "b" / "c" / "d" / "export"
    make_export(deep)
    assert find_exports([tmp_path], max_depth=1) == []
    assert len(find_exports([tmp_path], max_depth=5)) == 1


def test_respects_limit(tmp_path: Path) -> None:
    for index in range(3):
        make_export(tmp_path / f"export{index}")
    assert len(find_exports([tmp_path], limit=2)) == 2


def test_skips_hidden_and_noisy_directories(tmp_path: Path) -> None:
    make_export(tmp_path / ".cache" / "export")
    make_export(tmp_path / "node_modules" / "export")
    assert find_exports([tmp_path]) == []


def test_missing_root_is_ignored(tmp_path: Path) -> None:
    assert find_exports([tmp_path / "nope"]) == []


def test_export_candidate_label(tmp_path: Path) -> None:
    folder = make_export(tmp_path / "my-export")
    candidate = find_exports([tmp_path])[0]
    assert candidate.folder == folder
    assert candidate.label == "my-export"
    assert isinstance(candidate, ExportCandidate)


def test_default_roots_are_existing_directories(tmp_path: Path) -> None:
    roots = default_roots(home=tmp_path, cwd=tmp_path)
    assert roots == [] or all(root.is_dir() for root in roots)
