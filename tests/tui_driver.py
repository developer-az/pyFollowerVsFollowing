"""A scripted :class:`~osint_kit.tui.prompt.Prompter` for driving the TUI in tests."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from osint_kit.tui.prompt import Choice


@dataclass
class ScriptedPrompter:
    """Answers prompts from a queue and fails loudly if the flow asks too much.

    Each queued item is ``(kind, value)`` where kind is ``text``, ``choice`` or
    ``confirm``. The kind check catches a flow that starts asking a different
    question than the test expects.
    """

    queue: list[tuple[str, str]]
    asked: list[str] = field(default_factory=list)

    def _pop(self, kind: str, label: str) -> str:
        if not self.queue:
            raise AssertionError(f"unexpected {kind} prompt with nothing queued: {label!r}")
        expected, value = self.queue.pop(0)
        if expected != kind:
            raise AssertionError(
                f"expected a {expected} answer for {label!r}, got {kind} ({value!r})"
            )
        self.asked.append(label)
        return value

    def text(
        self,
        label: str,
        *,
        hint: str | None = None,
        default: str | None = None,
        allow_empty: bool = False,
    ) -> str:
        del hint, default, allow_empty
        return self._pop("text", label)

    def choice(self, label: str, choices: Sequence[Choice], *, default: str | None = None) -> str:
        del default
        value = self._pop("choice", label)
        keys = [option.key for option in choices]
        if value not in keys:
            raise AssertionError(f"{value!r} is not one of {keys} for {label!r}")
        return value

    def confirm(self, label: str, *, default: bool = False) -> bool:
        del default
        return self._pop("confirm", label) == "y"


__all__ = ["ScriptedPrompter"]
