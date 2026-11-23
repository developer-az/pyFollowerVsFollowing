"""EXIF reading and metadata stripping."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import pytest

from osint_kit.core.errors import ParseError, UsageError
from osint_kit.plugins.exif import (
    ExifPlugin,
    GpsPosition,
    detect_image_format,
    read_metadata,
    strip_metadata,
)


def fixture_bytes(fixtures: Path, name: str) -> bytes:
    return (fixtures / "images" / name).read_bytes()


def test_read_jpeg_metadata(fixtures: Path) -> None:
    metadata = read_metadata(fixture_bytes(fixtures, "sample.jpg"))
    assert metadata.image_format == "jpeg"
    assert metadata.exif_present is True
    assert metadata.device == {
        "Make": "TestCam",
        "Model": "TestCam X100",
        "LensModel": "TestLens 24mm",
    }
    assert metadata.timestamps["DateTimeOriginal"] == "2025:11:01 12:00:00"
    assert metadata.gps is not None
    assert metadata.gps.latitude == pytest.approx(37.775)
    assert metadata.gps.longitude == pytest.approx(-122.4166667)
    assert metadata.gps.altitude == pytest.approx(15.0)
    assert metadata.gps.maps_url.startswith("https://www.openstreetmap.org/")


def test_read_png_metadata(fixtures: Path) -> None:
    metadata = read_metadata(fixture_bytes(fixtures, "sample.png"))
    assert metadata.image_format == "png"
    assert metadata.exif_present is True
    assert metadata.tags["PixelXDimension"] == 4000
    assert metadata.gps is not None


def test_strip_jpeg_removes_metadata(fixtures: Path) -> None:
    data = fixture_bytes(fixtures, "sample.jpg")
    stripped = strip_metadata(data)
    assert stripped.startswith(b"\xff\xd8")
    assert b"Exif" not in stripped
    assert b"Photoshop" not in stripped
    assert b"metadata that should be stripped" not in stripped
    assert b"JFIF" in stripped
    assert stripped.endswith(b"\xff\xd9")
    assert len(stripped) < len(data)
    assert read_metadata(stripped).exif_present is False


def test_strip_png_removes_metadata(fixtures: Path) -> None:
    data = fixture_bytes(fixtures, "sample.png")
    stripped = strip_metadata(data)
    assert b"eXIf" not in stripped
    assert b"tEXt" not in stripped
    assert read_metadata(stripped).exif_present is False
    assert stripped.startswith(b"\x89PNG")


def test_unsupported_format_errors() -> None:
    assert detect_image_format(b"not an image") == "unknown"
    with pytest.raises(ParseError, match="unsupported"):
        read_metadata(b"not an image")
    with pytest.raises(ParseError, match="unsupported"):
        strip_metadata(b"not an image")


def test_bad_tiff_errors(fixtures: Path) -> None:
    data = bytearray(fixture_bytes(fixtures, "sample.jpg"))
    # Break the TIFF magic inside the EXIF payload (search for 'Exif\0\0').
    index = data.find(b"Exif\x00\x00")
    data[index + 8 : index + 10] = b"XX"
    with pytest.raises(ParseError):
        read_metadata(bytes(data))


def test_gps_position_url() -> None:
    gps = GpsPosition(latitude=1.5, longitude=-2.25)
    assert "mlat=1.5" in gps.maps_url
    assert "mlon=-2.25" in gps.maps_url


def test_plugin_analyze(context_factory: Any, fixtures: Path) -> None:
    ctx = context_factory()
    options = argparse.Namespace(
        images=[fixtures / "images" / "sample.jpg"], strip=False, dest=None
    )
    report = ExifPlugin().run(options, ctx)
    assert report.stats == {"images": 1, "with_exif": 1, "with_gps": 1}
    categories = {finding.category for finding in report.findings}
    assert {"metadata", "gps", "device", "timestamp"} <= categories
    gps = next(finding for finding in report.findings if finding.category == "gps")
    assert gps.severity.value == "medium"
    assert gps.details["map_url"].startswith("https://")


def test_plugin_no_exif(context_factory: Any, fixtures: Path, tmp_path: Path) -> None:
    cleaned = tmp_path / "clean.png"
    cleaned.write_bytes(strip_metadata(fixture_bytes(fixtures, "sample.png")))
    ctx = context_factory()
    report = ExifPlugin().run(argparse.Namespace(images=[cleaned], strip=False, dest=None), ctx)
    assert report.stats["with_exif"] == 0
    assert any(finding.category == "no_exif" for finding in report.findings)


def test_plugin_strip_to_file(context_factory: Any, fixtures: Path, tmp_path: Path) -> None:
    destination = tmp_path / "out" / "clean.jpg"
    ctx = context_factory()
    report = ExifPlugin().run(
        argparse.Namespace(
            images=[fixtures / "images" / "sample.jpg"], strip=True, dest=destination
        ),
        ctx,
    )
    assert destination.exists()
    assert b"Exif" not in destination.read_bytes()
    finding = report.findings[0]
    assert finding.category == "strip"
    assert finding.details["destination"] == str(destination)


def test_plugin_strip_default_destination_and_multiple(
    context_factory: Any, fixtures: Path, tmp_path: Path
) -> None:
    source = tmp_path / "copy.jpg"
    source.write_bytes(fixture_bytes(fixtures, "sample.jpg"))
    ctx = context_factory()
    ExifPlugin().run(argparse.Namespace(images=[source], strip=True, dest=None), ctx)
    assert (tmp_path / "copy.clean.jpg").exists()

    second = tmp_path / "second.jpg"
    second.write_bytes(fixture_bytes(fixtures, "sample.jpg"))
    with pytest.raises(UsageError, match="--dest"):
        ExifPlugin().run(argparse.Namespace(images=[source, second], strip=True, dest=None), ctx)

    directory = tmp_path / "many"
    ExifPlugin().run(argparse.Namespace(images=[source, second], strip=True, dest=directory), ctx)
    assert (directory / "copy.clean.jpg").exists()
    assert (directory / "second.clean.jpg").exists()


def test_plugin_missing_image(context_factory: Any, tmp_path: Path) -> None:
    from osint_kit.core.errors import InputError

    ctx = context_factory()
    with pytest.raises(InputError, match="not found"):
        ExifPlugin().run(
            argparse.Namespace(images=[tmp_path / "nope.jpg"], strip=False, dest=None), ctx
        )
