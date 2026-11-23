"""Form generation from a plugin's argparse declaration."""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from osint_kit.plugins.hashing import HashingPlugin
from osint_kit.plugins.log_analyzer import LogAnalyzerPlugin
from osint_kit.plugins.social_diff import SocialDiffPlugin
from osint_kit.tui.fields import Answer, Field, iter_fields, to_argv


def parser_for(
    plugin: SocialDiffPlugin | HashingPlugin | LogAnalyzerPlugin,
) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    plugin.configure_parser(parser)
    return parser


def by_dest(fields: tuple[Field, ...]) -> dict[str, Field]:
    return {item.dest: item for item in fields}


def test_social_diff_fields_are_required_paths() -> None:
    fields = by_dest(iter_fields(parser_for(SocialDiffPlugin())))
    assert fields["followers"].kind == "paths"
    assert fields["followers"].required
    assert fields["followers"].flag == "--followers"
    assert fields["following"].required
    assert fields["previous"].required is False
    assert fields["include_mutuals"].kind == "flag"


def test_hashing_mutually_exclusive_groups_are_grouped() -> None:
    fields = by_dest(iter_fields(parser_for(HashingPlugin())))
    assert fields["text"].group == "file|text"
    assert fields["file"].group == "file|text"
    assert fields["encode"].group == "decode|encode"
    assert fields["decode"].group == "decode|encode"
    assert fields["algorithms"].group is None


def test_choice_and_number_kinds() -> None:
    fields = by_dest(iter_fields(parser_for(LogAnalyzerPlugin())))
    assert fields["log_format"].kind == "choice"
    assert fields["log_format"].choices == ("auto", "combined", "sshd")
    assert fields["log_format"].default == "auto"
    assert fields["top"].kind == "number"
    assert fields["top"].default == "5"
    assert fields["logs"].kind == "paths"
    assert fields["logs"].positional


@pytest.mark.parametrize(
    ("answers", "expected"),
    [
        (
            {"followers": ["a.html"], "following": ["b.html"]},
            ["--followers", "a.html", "--following", "b.html"],
        ),
        (
            {"followers": ["a.html", "b.html"], "following": ["c.html"]},
            ["--followers", "a.html", "b.html", "--following", "c.html"],
        ),
        ({"include_mutuals": True}, ["--include-mutuals"]),
        ({"include_mutuals": False}, []),
        ({"previous": ""}, []),
        ({"previous": None}, []),
        ({"top": 5}, ["--top", "5"]),
    ],
)
def test_to_argv(answers: dict[str, Answer], expected: list[str]) -> None:
    plugin = LogAnalyzerPlugin() if "top" in answers else SocialDiffPlugin()
    fields = iter_fields(parser_for(plugin))
    assert to_argv(fields, answers) == expected


def test_positionals_come_first() -> None:
    fields = iter_fields(parser_for(LogAnalyzerPlugin()))
    argv = to_argv(fields, {"logs": ["one.log"], "top": 3})
    assert argv == ["one.log", "--top", "3"]


def test_answers_round_trip_through_the_plugin_parser(tmp_path: Path) -> None:
    parser = parser_for(SocialDiffPlugin())
    fields = iter_fields(parser)
    argv = to_argv(
        fields,
        {
            "followers": [str(tmp_path / "f.html")],
            "following": [str(tmp_path / "g.html")],
            "previous": "",
        },
    )
    options = parser.parse_args(argv)
    assert options.followers == [tmp_path / "f.html"]
    assert options.previous is None
    assert options.include_mutuals is False


def test_plugin_parser_has_no_help_action() -> None:
    fields = iter_fields(parser_for(SocialDiffPlugin()))
    assert all(item.dest != "help" for item in fields)
