"""Turn a plugin's argparse parser into an interactive form.

Every plugin already declares its inputs once, in ``configure_parser``. The
interactive flow reads that declaration instead of keeping a second list of
questions in sync with it: a new plugin gets a working form for free, and the
answers are handed back through the plugin's own parser so argparse still does
type conversion and validation.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, TypeAlias

Kind: TypeAlias = Literal["text", "path", "paths", "texts", "number", "flag", "choice"]
Answer: TypeAlias = str | bool | int | float | Sequence[str] | None

_PATH_METAVARS = ("FILE", "PATH", "IMAGE", "DIR", "FOLDER", "LOG")


@dataclass(frozen=True)
class Field:
    """One input a plugin expects."""

    dest: str
    flag: str | None
    label: str
    kind: Kind
    required: bool
    default: str | None
    help: str
    choices: tuple[str, ...] = ()
    group: str | None = None

    @property
    def many(self) -> bool:
        return self.kind in {"paths", "texts"}

    @property
    def positional(self) -> bool:
        return self.flag is None


def _first_flag(action: argparse.Action) -> str | None:
    for option in action.option_strings:
        if option.startswith("--"):
            return option
    return action.option_strings[0] if action.option_strings else None


def _kind(action: argparse.Action) -> Kind:
    if action.nargs == 0:  # store_true / store_false
        return "flag"
    if action.choices:
        return "choice"
    many = action.nargs in {"+", "*"}
    metavar = action.metavar if isinstance(action.metavar, str) else ""
    if action.type is Path or any(token in metavar.upper() for token in _PATH_METAVARS):
        return "paths" if many else "path"
    if action.type in {int, float}:
        return "number"
    return "texts" if many else "text"


def _default_text(action: argparse.Action) -> str | None:
    default = action.default
    if default is None or default is argparse.SUPPRESS:
        return None
    if isinstance(default, bool) or not isinstance(default, str | int | float):
        return None
    return str(default)


def _label(action: argparse.Action) -> str:
    if isinstance(action.metavar, str):
        return action.metavar
    return action.dest.replace("_", " ")


def _exclusive_groups(parser: argparse.ArgumentParser) -> dict[str, str]:
    """Map each dest to a stable key naming its mutually exclusive group.

    ``action.container`` is the parser's "optional arguments" group, not the
    exclusive group it belongs to, so the groups are read from the parser.
    """
    mapping: dict[str, str] = {}
    groups = getattr(parser, "_mutually_exclusive_groups", ())
    for group in groups:
        members = getattr(group, "_group_actions", ())
        key = "|".join(sorted(action.dest for action in members))
        for action in members:
            mapping[action.dest] = key
    return mapping


def iter_fields(parser: argparse.ArgumentParser) -> tuple[Field, ...]:
    """Describe every plugin argument except help as a :class:`Field`."""
    groups = _exclusive_groups(parser)
    fields: list[Field] = []
    for action in parser._actions:
        if action.dest in {"help", argparse.SUPPRESS}:
            continue
        fields.append(
            Field(
                dest=action.dest,
                flag=_first_flag(action),
                label=_label(action),
                kind=_kind(action),
                required=bool(action.required),
                default=_default_text(action),
                help=action.help or "",
                choices=tuple(str(choice) for choice in action.choices or ()),
                group=groups.get(action.dest),
            )
        )
    return tuple(fields)


def to_argv(fields: Sequence[Field], answers: Mapping[str, Answer]) -> list[str]:
    """Render answers as an argv list the plugin's own parser understands."""
    positional: list[str] = []
    options: list[str] = []
    for field in fields:
        if field.dest not in answers:
            continue
        value = answers[field.dest]
        if field.kind == "flag":
            if value is True and field.flag is not None:
                options.append(field.flag)
            continue
        if value is None:
            continue
        if field.many:
            if isinstance(value, str):
                values = [value]
            elif isinstance(value, Sequence):
                values = [str(item) for item in value]
            else:
                values = [str(value)]
            values = [item for item in values if item]
            if not values:
                continue
            if field.positional:
                positional.extend(values)
            else:
                options.append(field.flag or "")
                options.extend(values)
            continue
        text = str(value)
        if not text:
            continue
        if field.positional:
            positional.append(text)
        else:
            options.extend([field.flag or "", text])
    return positional + options


__all__ = ["Answer", "Field", "Kind", "iter_fields", "to_argv"]
