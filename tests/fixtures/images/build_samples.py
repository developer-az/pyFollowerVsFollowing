"""Build the synthetic image fixtures used by the EXIF tests.

Run from the repository root:

    python tests/fixtures/images/build_samples.py

The output is deterministic and contains no real personal data: the camera is
"TestCam", the lens is "TestLens", and the GPS point is a public San Francisco
coordinate chosen only to exercise the parser.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

HERE = Path(__file__).parent


def _rational(numerator: int, denominator: int = 1) -> bytes:
    return struct.pack("<II", numerator, denominator)


def build_tiff() -> bytes:
    """Little-endian TIFF with IFD0, Exif, and GPS IFDs."""
    make = b"TestCam\x00"
    model = b"TestCam X100\x00"
    timestamp = b"2025:11:01 12:00:00\x00"
    lens = b"TestLens 24mm\x00"
    gps_date = b"2025:11:01\x00"

    buf = bytearray(b"II*\x00" + struct.pack("<I", 8))

    def write_ifd(entries: list[tuple[int, int, int, bytes]]) -> int:
        offset = len(buf)
        buf.extend(struct.pack("<H", len(entries)))
        table_start = len(buf)
        buf.extend(b"\x00" * (12 * len(entries)))
        buf.extend(b"\x00\x00\x00\x00")
        for index, (tag, field_type, count, payload) in enumerate(entries):
            if len(payload) <= 4:
                value = payload.ljust(4, b"\x00")
            else:
                data_offset = len(buf)
                buf.extend(payload)
                value = struct.pack("<I", data_offset)
            position = table_start + index * 12
            buf[position : position + 12] = struct.pack("<HHI", tag, field_type, count) + value
        return offset

    ifd0 = write_ifd(
        [
            (0x010F, 2, len(make), make),
            (0x0110, 2, len(model), model),
            (0x0132, 2, len(timestamp), timestamp),
            (0x8769, 4, 1, struct.pack("<I", 0)),
            (0x8825, 4, 1, struct.pack("<I", 0)),
        ]
    )
    exif_ifd = write_ifd(
        [
            (0x9003, 2, len(timestamp), timestamp),
            (0xA002, 4, 1, struct.pack("<I", 4000)),
            (0xA434, 2, len(lens), lens),
        ]
    )
    gps_ifd = write_ifd(
        [
            (0x0001, 2, 2, b"N\x00"),
            (0x0002, 5, 3, _rational(37) + _rational(46) + _rational(30)),
            (0x0003, 2, 2, b"W\x00"),
            (0x0004, 5, 3, _rational(122) + _rational(25) + _rational(0)),
            (0x0005, 1, 1, b"\x00"),
            (0x0006, 5, 1, _rational(15)),
            (0x001D, 2, len(gps_date), gps_date),
        ]
    )

    if ifd0 != 8:
        raise AssertionError("IFD0 must start immediately after the TIFF header")
    # Patch the ExifIFDPointer and GPSIFDPointer values in IFD0's entry table.
    entries_start = ifd0 + 2
    buf[entries_start + 3 * 12 + 8 : entries_start + 3 * 12 + 12] = struct.pack("<I", exif_ifd)
    buf[entries_start + 4 * 12 + 8 : entries_start + 4 * 12 + 12] = struct.pack("<I", gps_ifd)
    return bytes(buf)


def build_jpeg(tiff: bytes) -> bytes:
    jfif = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    app0 = b"\xff\xe0" + struct.pack(">H", len(jfif) + 2) + jfif
    exif_payload = b"Exif\x00\x00" + tiff
    app1 = b"\xff\xe1" + struct.pack(">H", len(exif_payload) + 2) + exif_payload
    photoshop = b"Photoshop 3.0\x00" + b"8BIM" + b"secret-iptc"
    app13 = b"\xff\xed" + struct.pack(">H", len(photoshop) + 2) + photoshop
    comment = b"metadata that should be stripped"
    com = b"\xff\xfe" + struct.pack(">H", len(comment) + 2) + comment
    sos_header = b"\x01\x01\x00\x00\x3f\x00"
    sos = b"\xff\xda" + struct.pack(">H", len(sos_header) + 2) + sos_header
    return b"\xff\xd8" + app0 + app1 + app13 + com + sos + b"\x00\x01\x02\x03" + b"\xff\xd9"


def _chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def build_png(tiff: bytes) -> bytes:
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", ihdr)
        + _chunk(b"eXIf", tiff)
        + _chunk(b"tEXt", b"Author\x00Synthetic")
        + _chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00"))
        + _chunk(b"IEND", b"")
    )


def main() -> None:
    tiff = build_tiff()
    (HERE / "sample.jpg").write_bytes(build_jpeg(tiff))
    (HERE / "sample.png").write_bytes(build_png(tiff))
    print(f"wrote sample.jpg and sample.png under {HERE}")


if __name__ == "__main__":
    main()
