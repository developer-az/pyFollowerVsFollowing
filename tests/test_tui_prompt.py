"""The rich-backed prompter, with keyboard input faked."""

from __future__ import annotations

import io
from collections.abc import Sequence

import pytest
from rich.console import Console

from osint_kit.tui.prompt import Choice, RichPrompter


class FakeKeyboard:
    def __init__(self, console: Console, answers: Sequence[str]) -> None:
        self.console = console
        self.answers = list(answers)

    def feed(self, answers: Sequence[str]) -> None:
        self.answers = list(answers)


@pytest.fixture
def prompt() -> tuple[RichPrompter, FakeKeyboard, io.StringIO]:
    buffer = io.StringIO()
    console = Console(file=buffer, width=100, force_terminal=False, no_color=True)
    keyboard = FakeKeyboard(console, [])

    def fake_input(prompt: str = "", **_kwargs: object) -> str:
        del prompt
        if not keyboard.answers:
            raise AssertionError("ran out of scripted keystrokes")
        return keyboard.answers.pop(0)

    console.input = fake_input  # type: ignore[assignment]
    return RichPrompter(console), keyboard, buffer


def test_text_returns_what_was_typed(
    prompt: tuple[RichPrompter, FakeKeyboard, io.StringIO],
) -> None:
    prompter, keyboard, output = prompt
    keyboard.feed(["hello"])
    assert prompter.text("Which file?", hint="a hint") == "hello"
    assert "Which file?" in output.getvalue()
    assert "a hint" in output.getvalue()


def test_text_falls_back_to_the_default(
    prompt: tuple[RichPrompter, FakeKeyboard, io.StringIO],
) -> None:
    prompter, keyboard, _output = prompt
    keyboard.feed([""])
    assert prompter.text("Save to", default="out.md") == "out.md"


def test_text_asks_again_when_empty(
    prompt: tuple[RichPrompter, FakeKeyboard, io.StringIO],
) -> None:
    prompter, keyboard, output = prompt
    keyboard.feed(["", "value"])
    assert prompter.text("Which file?") == "value"
    assert "Please enter a value." in output.getvalue()


def test_text_can_be_left_empty(prompt: tuple[RichPrompter, FakeKeyboard, io.StringIO]) -> None:
    prompter, keyboard, _output = prompt
    keyboard.feed([""])
    assert prompter.text("Older export?", allow_empty=True) == ""


def test_choice_by_number(prompt: tuple[RichPrompter, FakeKeyboard, io.StringIO]) -> None:
    prompter, keyboard, output = prompt
    keyboard.feed(["2"])
    key = prompter.choice("Pick", [Choice("a", "First", "detail"), Choice("b", "Second")])
    assert key == "b"
    assert "First" in output.getvalue()


def test_choice_by_key(prompt: tuple[RichPrompter, FakeKeyboard, io.StringIO]) -> None:
    prompter, keyboard, _output = prompt
    keyboard.feed(["A"])
    assert prompter.choice("Pick", [Choice("a", "First"), Choice("b", "Second")]) == "a"


def test_choice_asks_again_on_nonsense(
    prompt: tuple[RichPrompter, FakeKeyboard, io.StringIO],
) -> None:
    prompter, keyboard, output = prompt
    keyboard.feed(["nope", "99", "1"])
    assert prompter.choice("Pick", [Choice("a", "First")]) == "a"
    assert "Choose one of: a." in output.getvalue()


def test_choice_default_on_empty(prompt: tuple[RichPrompter, FakeKeyboard, io.StringIO]) -> None:
    prompter, keyboard, output = prompt
    keyboard.feed([""])
    assert prompter.choice("Pick", [Choice("a", "First"), Choice("q", "Quit")], default="q") == "q"
    assert "Enter accepts q." in output.getvalue()


@pytest.mark.parametrize(
    ("typed", "expected"),
    [("y", True), ("yes", True), ("Y", True), ("n", False), ("", False), ("maybe", False)],
)
def test_confirm(
    prompt: tuple[RichPrompter, FakeKeyboard, io.StringIO], typed: str, expected: bool
) -> None:
    prompter, keyboard, _output = prompt
    keyboard.feed([typed])
    assert prompter.confirm("Continue?") is expected


def test_confirm_default_yes(prompt: tuple[RichPrompter, FakeKeyboard, io.StringIO]) -> None:
    prompter, keyboard, output = prompt
    keyboard.feed([""])
    assert prompter.confirm("Continue?", default=True) is True
    assert "[Y/n]" in output.getvalue()
