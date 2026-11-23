"""Choosing a file or folder instead of typing its path.

Typing a long path is the least pleasant part of the interactive mode, so every
question that reads from disk gets a Browse button. On Windows the button opens
the operating system's own dialog; elsewhere, and whenever tkinter is missing or
broken, it opens the small in-app list below. Two back ends, one answer: a tuple
of paths, which the form writes into the input.

Nothing here reads file contents; it only lists names.
"""

from __future__ import annotations

import fnmatch
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, ClassVar

from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, OptionList, Static
from textual.widgets.option_list import Option

from osint_kit.tui.copy import field_copy
from osint_kit.tui.fields import Field

IMAGE_TYPES = ("*.jpg", "*.jpeg", "*.png", "*.heic", "*.tif", "*.tiff", "*.webp")
LOG_TYPES = ("*.log", "*.txt", "*.json", "*.log.gz")
EXPORT_TYPES = ("*.html", "*.json")
MAIL_TYPES = ("*.eml", "*.txt", "*.msg")

#: Patterns and whether a folder is a valid answer, per ``plugin:dest``.
SPECS: Mapping[str, tuple[tuple[str, ...], bool]] = {
    "social_diff:followers": (EXPORT_TYPES, True),
    "social_diff:following": (EXPORT_TYPES, True),
    "social_diff:previous": (EXPORT_TYPES, True),
    "email_headers:headers": (MAIL_TYPES, False),
    "exif:images": (IMAGE_TYPES, False),
    "log_analyzer:logs": (LOG_TYPES, False),
    "hashing:file": (("*",), False),
}


@dataclass(frozen=True)
class Target:
    """What one question will accept."""

    title: str
    patterns: tuple[str, ...] = ("*",)
    folder_ok: bool = False

    def matches(self, name: str) -> bool:
        lowered = name.lower()
        return any(fnmatch.fnmatchcase(lowered, pattern.lower()) for pattern in self.patterns)


def target_for(plugin: str, field: Field) -> Target | None:
    """The picker settings for one question, or None when there is no picker."""
    spec = SPECS.get(f"{plugin}:{field.dest}")
    if spec is None or field.kind not in {"path", "paths"}:
        return None
    patterns, folder_ok = spec
    return Target(
        title=field_copy(plugin, field.dest).label, patterns=patterns, folder_ok=folder_ok
    )


@dataclass(frozen=True)
class Entry:
    """One row of the in-app list."""

    path: Path
    is_dir: bool


def entries(directory: Path, target: Target, *, show_hidden: bool = False) -> list[Entry]:
    """Folders first, then the files this target accepts, each sorted by name."""
    try:
        children = list(directory.iterdir())
    except OSError:
        return []
    folders: list[Entry] = []
    files: list[Entry] = []
    for child in children:
        if not show_hidden and child.name.startswith("."):
            continue
        if child.is_dir():
            folders.append(Entry(child, True))
        elif child.is_file() and target.matches(child.name):
            files.append(Entry(child, False))
    key = lambda entry: entry.path.name.lower()  # noqa: E731 - one-line sort key
    return sorted(folders, key=key) + sorted(files, key=key)


def parent_of(directory: Path) -> Path | None:
    """The folder above ``directory``, or None at a drive root."""
    parent = directory.parent
    return None if parent == directory else parent


def start_directory(start: Path | None) -> Path:
    """Where the picker should open, given whatever the field already holds."""
    if start is not None:
        candidate = start.expanduser()
        if candidate.is_dir():
            return candidate
        if candidate.parent.is_dir():
            return candidate.parent
    return Path.cwd()


# --------------------------------------------------------------------- native

_broken = False


def _on_windows() -> bool:
    return sys.platform == "win32"


@lru_cache(maxsize=1)
def _importable() -> bool:
    # The platform check lives in its own function so mypy on Linux does not
    # narrow it to a constant and call the Windows branch unreachable.
    if not _on_windows():
        return False
    try:
        import tkinter  # noqa: F401
    except Exception:
        return False
    return True


def native_available() -> bool:
    """True when the OS dialog can be tried on this machine."""
    return _importable() and not _broken


def pick_native(  # pragma: no cover - needs a desktop session
    target: Target,
    *,
    folder: bool,
    multiple: bool,
    start: Path | None = None,
) -> tuple[Path, ...]:
    """Show the OS dialog and return what was chosen. Blocks; call it in a worker."""
    global _broken

    import tkinter
    from tkinter import filedialog

    try:
        root = tkinter.Tk()
    except Exception:
        _broken = True
        raise
    try:
        root.withdraw()
        root.attributes("-topmost", True)
        initial = str(start) if start is not None and start.is_dir() else None
        if folder:
            chosen_dir = filedialog.askdirectory(
                parent=root, title=target.title, initialdir=initial, mustexist=True
            )
            return (Path(chosen_dir),) if chosen_dir else ()
        filetypes = [("Matching files", " ".join(target.patterns))]
        if target.patterns != ("*",):
            filetypes.append(("All files", "*.*"))
        common: dict[str, Any] = {"parent": root, "title": target.title}
        if initial is not None:
            common["initialdir"] = initial
        if multiple:
            names = filedialog.askopenfilenames(filetypes=filetypes, **common)
            return tuple(Path(name) for name in names)
        name = filedialog.askopenfilename(filetypes=filetypes, **common)
        return (Path(name),) if name else ()
    finally:
        root.destroy()


# ------------------------------------------------------------------ in-app UI


class FilePickerScreen(ModalScreen[tuple[Path, ...] | None]):
    """A folder listing, for machines without a usable OS dialog."""

    BINDINGS: ClassVar[list[BindingType]] = [
        ("escape", "cancel", "Cancel"),
        ("backspace", "up", "Up"),
    ]

    def __init__(self, target: Target, *, start: Path | None = None) -> None:
        super().__init__()
        self.target = target
        self.directory = start_directory(start)
        self._rows: list[Entry] = []

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog picker"):
            yield Static(self.target.title, classes="picker-title")
            yield Static(str(self.directory), id="picker-path", classes="hint")
            yield OptionList(id="picker-entries")
            with Horizontal(classes="dialog-actions"):
                if self.target.folder_ok:
                    yield Button("Use this folder", id="use-folder", variant="primary")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self._refresh()
        self.query_one("#picker-entries", OptionList).focus()

    def _refresh(self) -> None:
        self.query_one("#picker-path", Static).update(str(self.directory))
        listing = self.query_one("#picker-entries", OptionList)
        listing.clear_options()
        up = parent_of(self.directory)
        if up is not None:
            listing.add_option(Option("..  go up", id="up"))
        self._rows = entries(self.directory, self.target)
        for index, entry in enumerate(self._rows):
            label = f"{entry.path.name}/" if entry.is_dir else entry.path.name
            listing.add_option(Option(label, id=f"row-{index}"))
        if listing.option_count:
            listing.highlighted = 0

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        option_id = event.option_id or ""
        if option_id == "up":
            self.action_up()
            return
        if not option_id.startswith("row-"):
            return
        entry = self._rows[int(option_id.removeprefix("row-"))]
        if entry.is_dir:
            self.directory = entry.path
            self._refresh()
            return
        self.dismiss((entry.path,))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "use-folder":
            self.dismiss((self.directory,))
        elif event.button.id == "cancel":
            self.dismiss(None)

    def action_up(self) -> None:
        up = parent_of(self.directory)
        if up is not None:
            self.directory = up
            self._refresh()

    def action_cancel(self) -> None:
        self.dismiss(None)


__all__ = [
    "Entry",
    "FilePickerScreen",
    "Target",
    "entries",
    "native_available",
    "parent_of",
    "pick_native",
    "start_directory",
    "target_for",
]
