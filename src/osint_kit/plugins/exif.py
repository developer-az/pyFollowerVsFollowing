"""EXIF/PNG metadata reader and stripper — standard library only.

The TIFF/EXIF reader is intentionally small: it understands the IFD structure,
the common IFD0/Exif/GPS tags, and both endiannesses. It does not pretend to be
ExifTool; unknown tags are skipped rather than guessed.
"""

from __future__ import annotations

import argparse
import struct
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from osint_kit.core.errors import InputError, ParseError, UsageError
from osint_kit.core.models import Report, Severity
from osint_kit.core.plugin import BasePlugin, PluginContext

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

# TIFF field type -> (struct format, byte size)
_TIFF_TYPES: dict[int, tuple[str, int]] = {
    1: ("B", 1),
    2: ("s", 1),
    3: ("H", 2),
    4: ("I", 4),
    5: ("II", 8),
    6: ("b", 1),
    7: ("B", 1),
    8: ("h", 2),
    9: ("i", 4),
    10: ("ii", 8),
    11: ("f", 4),
    12: ("d", 8),
    13: ("I", 4),
}

_TAG_NAMES: dict[int, str] = {
    0x0100: "ImageWidth",
    0x0101: "ImageHeight",
    0x010E: "ImageDescription",
    0x010F: "Make",
    0x0110: "Model",
    0x0112: "Orientation",
    0x011A: "XResolution",
    0x011B: "YResolution",
    0x0128: "ResolutionUnit",
    0x0131: "Software",
    0x0132: "DateTime",
    0x013B: "Artist",
    0x8298: "Copyright",
    0x829A: "ExposureTime",
    0x829D: "FNumber",
    0x8827: "ISOSpeedRatings",
    0x9003: "DateTimeOriginal",
    0x9004: "DateTimeDigitized",
    0x9010: "OffsetTime",
    0x9207: "MeteringMode",
    0x9209: "Flash",
    0x920A: "FocalLength",
    0xA002: "PixelXDimension",
    0xA003: "PixelYDimension",
    0xA405: "FocalLengthIn35mmFilm",
    0xA430: "OwnerName",
    0xA431: "BodySerialNumber",
    0xA434: "LensModel",
    0x9286: "UserComment",
    0x9291: "SubSecTimeOriginal",
    0x8769: "ExifIFDPointer",
    0x8825: "GPSIFDPointer",
}

_GPS_NAMES: dict[int, str] = {
    0: "GPSVersionID",
    1: "GPSLatitudeRef",
    2: "GPSLatitude",
    3: "GPSLongitudeRef",
    4: "GPSLongitude",
    5: "GPSAltitudeRef",
    6: "GPSAltitude",
    7: "GPSTimeStamp",
    12: "GPSSpeedRef",
    13: "GPSSpeed",
    16: "GPSImgDirectionRef",
    17: "GPSImgDirection",
    29: "GPSDateStamp",
}


@dataclass(frozen=True)
class GpsPosition:
    """Decimal degrees plus optional altitude and GPS timestamp."""

    latitude: float
    longitude: float
    altitude: float | None = None
    timestamp: str | None = None

    @property
    def maps_url(self) -> str:
        return f"https://www.openstreetmap.org/?mlat={self.latitude}&mlon={self.longitude}#map=16"


@dataclass(frozen=True)
class ImageMetadata:
    """Everything the reader could establish about one image."""

    image_format: str
    byte_size: int
    exif_present: bool
    tags: dict[str, Any]
    gps: GpsPosition | None
    device: dict[str, str]
    timestamps: dict[str, str]


def detect_image_format(data: bytes) -> str:
    """Return ``jpeg``, ``png``, or ``unknown``."""
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data.startswith(PNG_SIGNATURE):
        return "png"
    return "unknown"


def _tiff_header(data: bytes) -> tuple[str, int]:
    if len(data) < 8:
        raise ParseError("EXIF block is too short to contain a TIFF header")
    if data[:2] == b"II":
        endian = "<"
    elif data[:2] == b"MM":
        endian = ">"
    else:
        raise ParseError("EXIF block has an invalid byte-order marker")
    magic, offset = struct.unpack(endian + "HI", data[2:8])
    if magic == 43:
        raise ParseError("BigTIFF EXIF is not supported")
    if magic != 42:
        raise ParseError(f"unexpected TIFF magic number {magic}")
    return endian, offset


def _read_ifd(data: bytes, offset: int, endian: str) -> dict[int, Any]:
    if offset < 8 or offset + 2 > len(data):
        raise ParseError("EXIF IFD offset is out of range")
    (count,) = struct.unpack(endian + "H", data[offset : offset + 2])
    if count > 1000:
        raise ParseError(f"implausible EXIF tag count {count}")
    tags: dict[int, Any] = {}
    cursor = offset + 2
    for _ in range(count):
        if cursor + 12 > len(data):
            break
        tag, field_type, value_count = struct.unpack(endian + "HHI", data[cursor : cursor + 8])
        value_bytes = data[cursor + 8 : cursor + 12]
        cursor += 12
        decoded = _decode_value(data, endian, field_type, value_count, value_bytes)
        if decoded is not None:
            tags[tag] = decoded
    return tags


def _decode_value(data: bytes, endian: str, field_type: int, count: int, value_bytes: bytes) -> Any:
    spec = _TIFF_TYPES.get(field_type)
    if spec is None:
        return None
    code, size = spec
    if count == 0 or count > 100_000:
        return None
    total = size * count
    if total > 8_000_000:
        return None
    if total <= 4:
        payload = value_bytes[:total]
    else:
        (offset,) = struct.unpack(endian + "I", value_bytes)
        if offset + total > len(data):
            return None
        payload = data[offset : offset + total]

    if field_type == 2:  # ASCII
        return payload.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()
    if field_type == 7:  # UNDEFINED
        return payload
    if field_type in (5, 10):  # RATIONAL / SRATIONAL
        values = struct.unpack(endian + code * count, payload)
        numbers = []
        for index in range(0, len(values), 2):
            denominator = values[index + 1]
            numbers.append(values[index] / denominator if denominator else 0.0)
    else:
        values = struct.unpack(endian + code * count, payload)
        numbers = list(values)
    if len(numbers) == 1:
        return numbers[0]
    return tuple(numbers)


def _decode_tiff(tiff: bytes) -> tuple[dict[int, Any], dict[int, Any]]:
    endian, offset = _tiff_header(tiff)
    main = _read_ifd(tiff, offset, endian)
    exif_pointer = main.get(0x8769)
    if isinstance(exif_pointer, int):
        main.update(_read_ifd(tiff, exif_pointer, endian))
    gps: dict[int, Any] = {}
    gps_pointer = main.get(0x8825)
    if isinstance(gps_pointer, int):
        gps = _read_ifd(tiff, gps_pointer, endian)
    return main, gps


def _iter_jpeg_segments(data: bytes) -> Iterator[tuple[int, int, int]]:
    """Yield ``(marker, start, end)`` for JPEG metadata segments, stopping at SOS."""
    if not data.startswith(b"\xff\xd8"):
        return
    position = 2
    while position + 1 < len(data):
        if data[position] != 0xFF:
            # Resynchronise on the next marker byte.
            next_marker = data.find(b"\xff", position)
            if next_marker < 0:
                return
            position = next_marker
            continue
        marker = data[position + 1]
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            position += 2
            continue
        if marker == 0xDA:  # start of scan: metadata is over
            return
        if position + 4 > len(data):
            return
        length = int.from_bytes(data[position + 2 : position + 4], "big")
        if length < 2:
            return
        end = position + 2 + length
        if end > len(data):
            return
        yield marker, position, end
        position = end


def _jpeg_exif(data: bytes) -> bytes | None:
    for marker, start, end in _iter_jpeg_segments(data):
        if marker == 0xE1 and data[start + 4 : start + 10] == b"Exif\x00\x00":
            return data[start + 10 : end]
    return None


def _png_exif(data: bytes) -> bytes | None:
    position = len(PNG_SIGNATURE)
    while position + 8 <= len(data):
        length = int.from_bytes(data[position : position + 4], "big")
        chunk_type = data[position + 4 : position + 8]
        payload_start = position + 8
        payload_end = payload_start + length
        if payload_end + 4 > len(data):
            return None
        if chunk_type == b"eXIf":
            return data[payload_start:payload_end]
        position = payload_end + 4
    return None


def _gps_position(gps: dict[int, Any]) -> GpsPosition | None:
    latitude = _dms(gps.get(2), gps.get(1))
    longitude = _dms(gps.get(4), gps.get(3))
    if latitude is None or longitude is None:
        return None
    altitude: float | None = None
    raw_altitude = gps.get(6)
    if isinstance(raw_altitude, (int, float)):
        altitude = float(raw_altitude)
        if gps.get(5) == 1:
            altitude = -altitude
    timestamp: str | None = None
    date_stamp = gps.get(29)
    time_stamp = gps.get(7)
    parts: list[str] = []
    if isinstance(date_stamp, str):
        parts.append(date_stamp.replace(":", "-"))
    if isinstance(time_stamp, tuple) and len(time_stamp) == 3:
        hour, minute, second = time_stamp
        parts.append(f"{int(hour):02d}:{int(minute):02d}:{second:04.1f}Z")
    if parts:
        timestamp = "T".join(parts)
    return GpsPosition(
        latitude=latitude, longitude=longitude, altitude=altitude, timestamp=timestamp
    )


def _dms(values: Any, reference: Any) -> float | None:
    if not isinstance(values, tuple) or len(values) != 3:
        return None
    degrees, minutes, seconds = (float(value) for value in values)
    result = degrees + minutes / 60.0 + seconds / 3600.0
    if isinstance(reference, str) and reference.strip().upper() in {"S", "W"}:
        result = -result
    return result


def read_metadata(data: bytes) -> ImageMetadata:
    """Parse metadata from JPEG or PNG bytes."""
    image_format = detect_image_format(data)
    if image_format == "unknown":
        raise ParseError("unsupported image format: expected JPEG or PNG")
    tiff = _jpeg_exif(data) if image_format == "jpeg" else _png_exif(data)
    if not tiff:
        return ImageMetadata(
            image_format=image_format,
            byte_size=len(data),
            exif_present=False,
            tags={},
            gps=None,
            device={},
            timestamps={},
        )

    main, gps_tags = _decode_tiff(tiff)
    tags: dict[str, Any] = {}
    for tag, value in main.items():
        name = _TAG_NAMES.get(tag)
        if name is not None and name not in {"ExifIFDPointer", "GPSIFDPointer"}:
            tags[name] = _json_safe(value)
    for tag, value in gps_tags.items():
        name = _GPS_NAMES.get(tag)
        if name is not None:
            tags[f"GPS:{name}"] = _json_safe(value)

    device_tags = ("Make", "Model", "Software", "LensModel", "OwnerName", "BodySerialNumber")
    device = {
        name: str(tags[name])
        for name in device_tags
        if name in tags and tags[name] not in ("", None)
    }
    timestamp_tags = (
        "DateTime",
        "DateTimeOriginal",
        "DateTimeDigitized",
        "OffsetTime",
        "SubSecTimeOriginal",
    )
    timestamps = {
        name: str(tags[name])
        for name in timestamp_tags
        if name in tags and tags[name] not in ("", None)
    }
    return ImageMetadata(
        image_format=image_format,
        byte_size=len(data),
        exif_present=True,
        tags=tags,
        gps=_gps_position(gps_tags),
        device=device,
        timestamps=timestamps,
    )


def _json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    return value


def strip_metadata(data: bytes) -> bytes:
    """Remove EXIF/XMP/IPTC/comment metadata while keeping image data intact."""
    image_format = detect_image_format(data)
    if image_format == "jpeg":
        return _strip_jpeg(data)
    if image_format == "png":
        return _strip_png(data)
    raise ParseError("unsupported image format: expected JPEG or PNG")


def _strip_jpeg(data: bytes) -> bytes:
    kept: list[bytes] = [data[:2]]
    scan_start: int | None = None
    for marker, start, end in _iter_jpeg_segments(data):
        # Keep JFIF (E0), ICC profile (E2), and Adobe colour transform (EE).
        if marker in {0xE0, 0xE2, 0xEE}:
            kept.append(data[start:end])
    for position in range(2, len(data) - 1):
        if data[position] == 0xFF and data[position + 1] == 0xDA:
            scan_start = position
            break
    if scan_start is None:
        raise ParseError("JPEG is missing a start-of-scan segment")
    kept.append(data[scan_start:])
    return b"".join(kept)


def _strip_png(data: bytes) -> bytes:
    kept: list[bytes] = [PNG_SIGNATURE]
    position = len(PNG_SIGNATURE)
    dropped = {b"eXIf", b"tEXt", b"iTXt", b"zTXt", b"tIME"}
    while position + 8 <= len(data):
        length = int.from_bytes(data[position : position + 4], "big")
        chunk_type = data[position + 4 : position + 8]
        chunk_end = position + 12 + length
        if chunk_end > len(data):
            raise ParseError("truncated PNG chunk")
        if chunk_type not in dropped:
            kept.append(data[position:chunk_end])
        position = chunk_end
    return b"".join(kept)


def _read_image(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except FileNotFoundError as exc:
        raise InputError(f"image not found: {path}") from exc
    except OSError as exc:
        raise InputError(f"could not read {path}: {exc}") from exc


class ExifPlugin(BasePlugin):
    """Read GPS/device/timestamp metadata, or strip it from copies."""

    NAME = "exif"
    SUMMARY = "Read or strip image metadata (GPS, device, timestamps)."
    NETWORK = False

    def configure_parser(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("images", nargs="+", type=Path, metavar="IMAGE")
        parser.add_argument(
            "--strip",
            action="store_true",
            help="write metadata-stripped copies instead of reporting metadata",
        )
        parser.add_argument(
            "--dest",
            type=Path,
            metavar="PATH",
            help="destination file (single image) or directory (multiple images)",
        )

    def run(self, options: argparse.Namespace, ctx: PluginContext) -> Report:
        if options.strip:
            return self._strip(options)
        report = Report(
            plugin=self.name,
            target=", ".join(path.name for path in options.images),
        )
        report.stats["images"] = len(options.images)
        report.stats["with_exif"] = 0
        report.stats["with_gps"] = 0
        for path in options.images:
            metadata = read_metadata(_read_image(path))
            if metadata.exif_present:
                report.stats["with_exif"] += 1
            if metadata.gps is not None:
                report.stats["with_gps"] += 1
            self._report_image(report, path, metadata)
        if not report.findings:
            report.add(
                category="metadata",
                subject=".",
                summary="No EXIF metadata found in the supplied image(s).",
            )
        return report

    def _report_image(self, report: Report, path: Path, metadata: ImageMetadata) -> None:
        base = {"file": str(path), "format": metadata.image_format, "bytes": metadata.byte_size}
        if not metadata.exif_present:
            report.add(
                category="no_exif",
                subject=path.name,
                summary="No EXIF block present.",
                details=base,
            )
            return
        report.add(
            category="metadata",
            subject=path.name,
            summary=f"EXIF present with {len(metadata.tags)} known tag(s).",
            details={**base, "tags": metadata.tags},
        )
        if metadata.gps is not None:
            gps = metadata.gps
            report.add(
                category="gps",
                subject=path.name,
                summary=(
                    f"GPS coordinates: {gps.latitude:.6f}, {gps.longitude:.6f}"
                    + (f" at {gps.altitude:.1f}m" if gps.altitude is not None else "")
                ),
                severity=Severity.MEDIUM,
                details={
                    **base,
                    "latitude": gps.latitude,
                    "longitude": gps.longitude,
                    "altitude_m": gps.altitude,
                    "gps_time": gps.timestamp,
                    "map_url": gps.maps_url,
                },
                tags=("privacy",),
            )
        if metadata.device:
            report.add(
                category="device",
                subject=path.name,
                summary=", ".join(f"{key}: {value}" for key, value in metadata.device.items()),
                severity=Severity.LOW,
                details={**base, "device": metadata.device},
            )
        if metadata.timestamps:
            report.add(
                category="timestamp",
                subject=path.name,
                summary=" · ".join(f"{key}={value}" for key, value in metadata.timestamps.items()),
                details={**base, "timestamps": metadata.timestamps},
            )

    def _strip(self, options: argparse.Namespace) -> Report:
        destinations = _resolve_destinations(options.images, options.dest)
        report = Report(plugin=self.name, target="strip metadata")
        report.stats["images"] = len(options.images)
        for source, destination in zip(options.images, destinations, strict=True):
            data = _read_image(source)
            cleaned = strip_metadata(data)
            try:
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(cleaned)
            except OSError as exc:
                raise InputError(f"could not write {destination}: {exc}") from exc
            removed = len(data) - len(cleaned)
            report.add(
                category="strip",
                subject=source.name,
                summary=f"Wrote {destination.name} without metadata ({removed} bytes removed).",
                details={
                    "source": str(source),
                    "destination": str(destination),
                    "original_bytes": len(data),
                    "cleaned_bytes": len(cleaned),
                },
            )
        return report


def _resolve_destinations(images: Sequence[Path], dest: Path | None) -> tuple[Path, ...]:
    if dest is None:
        if len(images) > 1:
            raise UsageError("--dest is required when stripping more than one image")
        source = images[0]
        return (source.with_name(_clean_name(source)),)
    if len(images) > 1:
        return tuple(dest / _clean_name(image) for image in images)
    if dest.suffix:
        return (dest,)
    return (dest / _clean_name(images[0]),)


def _clean_name(image: Path) -> str:
    return f"{image.stem}.clean{image.suffix or '.jpg'}"
