"""Regenerate the README screenshots from the real app.

Run from the repository root:

    python docs/screenshots/capture.py --chrome "C:/Program Files/Google/Chrome/Application/chrome.exe"

Textual exports each screen as an SVG; Chrome turns it into a crisp PNG at 2x
because it is the one renderer on this machine that has the font the SVG asks
for (Fira Code) and draws box borders as lines instead of dashes.
"""

from __future__ import annotations

import argparse
import asyncio
import shutil
import subprocess
import time
from pathlib import Path

from textual.widgets import Button, Input

from osint_kit.core.registry import load_plugins
from osint_kit.tui import textual_app
from osint_kit.tui.textual_app import ResultScreen

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
FIXTURES = ROOT / "tests" / "fixtures" / "instagram_html"
SIZE = (120, 40)
HERO_SIZE = (120, 26)
CHROME_CANDIDATES = (
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
)


def chrome_binary(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit)
    for candidate in CHROME_CANDIDATES:
        if Path(candidate).is_file():
            return Path(candidate)
    found = shutil.which("chrome") or shutil.which("msedge") or shutil.which("chromium")
    if found:
        return Path(found)
    raise SystemExit("no Chromium-family browser found; pass --chrome PATH")


def svg_to_png(browser: Path, svg: Path, png: Path, width: int, height: int) -> None:
    subprocess.run(
        [
            str(browser),
            "--headless=new",
            "--disable-gpu",
            "--hide-scrollbars",
            "--no-first-run",
            f"--user-data-dir={OUT / '.chrome-profile'}",
            "--default-background-color=00000000",
            "--force-device-scale-factor=2",
            f"--window-size={width},{height}",
            f"--screenshot={png}",
            svg.as_uri(),
        ],
        check=True,
        capture_output=True,
        timeout=120,
    )


def svg_size(svg: Path) -> tuple[int, int]:
    head = svg.read_text(encoding="utf-8")[:400]
    view_box = head.split('viewBox="', 1)[1].split('"', 1)[0]
    _, _, width, height = view_box.split()
    return int(float(width)), int(float(height))


async def capture() -> None:
    textual_app.native_available = lambda: False  # force the in-app picker
    shots: dict[str, str] = {}

    # The hero is a shorter window so the menu fills the frame instead of
    # floating in empty space; the flow below keeps one height throughout.
    hero = textual_app.OsintKitApp(load_plugins(), exports=[])
    async with hero.run_test(size=HERO_SIZE) as pilot:
        await pilot.pause()
        shots["01-choose-a-tool"] = hero.export_screenshot()

    app = textual_app.OsintKitApp(load_plugins(), exports=[])
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()

        await pilot.press("1")
        await pilot.pause()
        form = app.screen
        # Relative paths keep the machine's home directory out of the pictures.
        form.query_one(
            "#field-followers", Input
        ).value = "tests\\fixtures\\instagram_html\\followers_1.html"
        form.query_one(
            "#field-following", Input
        ).value = "tests\\fixtures\\instagram_html\\following.html"
        await pilot.pause()
        shots["02-fill-in-the-form"] = app.export_screenshot()

        form.query_one("#browse-followers", Button).press()
        await pilot.pause()
        await pilot.pause()
        shots["03-pick-a-file"] = app.export_screenshot()
        await pilot.press("escape")
        await pilot.pause()

        await pilot.click("#run")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            await pilot.pause()
            if isinstance(app.screen, ResultScreen):
                break
        await pilot.pause()
        await pilot.pause()
        shots["04-read-the-result"] = app.export_screenshot()

        await pilot.press("s")
        await pilot.pause()
        shots["05-save-it"] = app.export_screenshot()

    for name, svg_text in shots.items():
        (OUT / f"{name}.svg").write_text(svg_text, encoding="utf-8")
        print(f"svg  {name}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chrome", help="path to a Chromium-family browser")
    parser.add_argument("--keep-svg", action="store_true", help="leave the SVG sources in place")
    args = parser.parse_args()

    asyncio.run(capture())

    browser = chrome_binary(args.chrome)
    for svg in sorted(OUT.glob("*.svg")):
        png = svg.with_suffix(".png")
        width, height = svg_size(svg)
        svg_to_png(browser, svg, png, width, height)
        print(f"png  {png.name} {width}x{height}")
        if not args.keep_svg:
            svg.unlink()

    shutil.rmtree(OUT / ".chrome-profile", ignore_errors=True)


if __name__ == "__main__":
    main()
