"""Hashing, encoding, and hash identification.

All transforms are pure functions over str/bytes; the only I/O is
:func:`hash_file`, which streams the file in chunks.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import quote, unquote_to_bytes

from osint_kit.core.errors import InputError, UsageError
from osint_kit.core.models import Report, Severity
from osint_kit.core.plugin import BasePlugin, PluginContext

ALGORITHMS: tuple[str, ...] = (
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha3_256",
    "blake2b",
    "blake2s",
)
SCHEMES: tuple[str, ...] = ("hex", "base64", "url")
CHUNK_SIZE = 1024 * 1024


class _Hasher(Protocol):
    def update(self, data: bytes) -> None: ...

    def hexdigest(self) -> str: ...


def hash_bytes(data: bytes, algorithms: Iterable[str] = ("sha256",)) -> dict[str, str]:
    """Hex digests for each requested algorithm."""
    digests: dict[str, str] = {}
    for name in algorithms:
        try:
            digests[name] = hashlib.new(name, data).hexdigest()
        except ValueError as exc:
            raise UsageError(f"unknown hash algorithm: {name}") from exc
    return digests


def hash_text(text: str, algorithms: Iterable[str] = ("sha256",)) -> dict[str, str]:
    return hash_bytes(text.encode("utf-8"), algorithms)


def hash_file(path: Path, algorithms: Iterable[str] = ("sha256",)) -> dict[str, str]:
    """Stream a file so large inputs do not load into memory."""
    hashers: dict[str, _Hasher] = {}
    for name in algorithms:
        try:
            hashers[name] = hashlib.new(name)
        except ValueError as exc:
            raise UsageError(f"unknown hash algorithm: {name}") from exc
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(CHUNK_SIZE):
                for hasher in hashers.values():
                    hasher.update(chunk)
    except FileNotFoundError as exc:
        raise InputError(f"file not found: {path}") from exc
    except OSError as exc:
        raise InputError(f"could not read {path}: {exc}") from exc
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}


def encode_text(text: str, scheme: str = "base64") -> str:
    """Encode UTF-8 text as hex, base64, or percent-encoding."""
    data = text.encode("utf-8")
    if scheme == "hex":
        return data.hex()
    if scheme == "base64":
        return base64.b64encode(data).decode("ascii")
    if scheme == "url":
        return quote(text, safe="")
    raise UsageError(f"unknown encoding {scheme!r}; choose from {', '.join(SCHEMES)}")


def decode_text(value: str, scheme: str = "base64") -> bytes:
    """Decode hex/base64/percent-encoded text back to bytes."""
    stripped = "".join(value.split())
    try:
        if scheme == "hex":
            return bytes.fromhex(stripped)
        if scheme == "base64":
            return base64.b64decode(stripped, validate=True)
        if scheme == "url":
            return unquote_to_bytes(value)
    except (ValueError, binascii.Error) as exc:
        raise UsageError(f"invalid {scheme} input: {exc}") from exc
    raise UsageError(f"unknown encoding {scheme!r}; choose from {', '.join(SCHEMES)}")


@dataclass(frozen=True)
class HashCandidate:
    """One plausible interpretation of a digest."""

    name: str
    confidence: str  # "likely" | "possible"
    reason: str


_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_HEX_LENGTHS: dict[int, tuple[tuple[str, str], ...]] = {
    8: (("crc32", "likely"), ("adler32", "possible")),
    16: (("mysql323", "possible"), ("des", "possible")),
    32: (("md5", "likely"), ("ntlm", "possible"), ("md5crypt-body", "possible")),
    40: (("sha1", "likely"), ("ripemd160", "possible"), ("mysql5", "possible")),
    56: (("sha224", "likely"), ("sha3-224", "possible")),
    64: (("sha256", "likely"), ("sha3-256", "possible"), ("blake2s-256", "possible")),
    96: (("sha384", "likely"), ("sha3-384", "possible")),
    128: (("sha512", "likely"), ("sha3-512", "possible"), ("whirlpool", "possible")),
}

_PREFIXES: tuple[tuple[str, str, str], ...] = (
    ("$2a$", "bcrypt", "bcrypt cost variant 2a"),
    ("$2b$", "bcrypt", "bcrypt cost variant 2b"),
    ("$2y$", "bcrypt", "bcrypt cost variant 2y"),
    ("$argon2id$", "argon2id", "Argon2id PHC string"),
    ("$argon2i$", "argon2i", "Argon2i PHC string"),
    ("$argon2d$", "argon2d", "Argon2d PHC string"),
    ("$y$", "yescrypt", "yescrypt PHC string"),
    ("$7$", "scrypt", "scrypt crypt format"),
    ("$6$", "sha512crypt", "SHA-512 crypt format"),
    ("$5$", "sha256crypt", "SHA-256 crypt format"),
    ("$1$", "md5crypt", "MD5 crypt format"),
    ("$pbkdf2-sha256$", "pbkdf2-sha256", "PBKDF2-SHA256 crypt format"),
    ("{SSHA}", "ssha", "LDAP salted SHA-1"),
    ("{SHA}", "sha1-base64", "LDAP SHA-1"),
)


def identify_hash(value: str) -> tuple[HashCandidate, ...]:
    """Guess digest types from prefixes, length, and character set.

    Identification is heuristic; callers should treat it as a starting point.
    """
    candidate = value.strip()
    if not candidate:
        return ()
    for prefix, name, reason in _PREFIXES:
        if candidate.startswith(prefix):
            return (HashCandidate(name=name, confidence="likely", reason=reason),)
    if _HEX_RE.match(candidate):
        matches = _HEX_LENGTHS.get(len(candidate), ())
        return tuple(
            HashCandidate(name=name, confidence=confidence, reason=f"{len(candidate)} hex chars")
            for name, confidence in matches
        )
    if candidate.startswith("$"):
        return ()
    return ()


class HashingPlugin(BasePlugin):
    """Hash strings and files, encode/decode, and identify digest formats."""

    NAME = "hashing"
    SUMMARY = "Hash, encode/decode (hex, base64, URL), and identify digest formats."
    NETWORK = False

    def configure_parser(self, parser: argparse.ArgumentParser) -> None:
        source = parser.add_mutually_exclusive_group()
        source.add_argument("--text", metavar="TEXT", help="input string")
        source.add_argument("--file", type=Path, metavar="FILE", help="input file")
        parser.add_argument(
            "--algorithm",
            action="append",
            choices=ALGORITHMS,
            dest="algorithms",
            help="hash algorithm (repeatable; default: sha256)",
        )
        parser.add_argument(
            "--identify",
            metavar="VALUE",
            help="identify a hash instead of hashing input",
        )
        modes = parser.add_mutually_exclusive_group()
        modes.add_argument("--encode", choices=SCHEMES, help="encode the input")
        modes.add_argument("--decode", choices=SCHEMES, help="decode the input")

    def run(self, options: argparse.Namespace, ctx: PluginContext) -> Report:
        report = Report(plugin=self.name, target="hash/encode utility")
        algorithms = tuple(options.algorithms or ("sha256",))

        if options.identify:
            candidates = identify_hash(options.identify)
            report.target = f"identify:{options.identify[:40]}"
            report.stats["candidates"] = len(candidates)
            if not candidates:
                report.add(
                    category="identify",
                    subject=options.identify[:80],
                    summary="No known hash format matched.",
                    severity=Severity.LOW,
                )
            for candidate in candidates:
                report.add(
                    category="identify",
                    subject=options.identify[:80],
                    summary=f"Looks like {candidate.name} ({candidate.confidence}).",
                    details={
                        "name": candidate.name,
                        "confidence": candidate.confidence,
                        "reason": candidate.reason,
                    },
                )
            return report

        if options.text is None and options.file is None:
            raise UsageError("provide --text or --file (or --identify)")
        if options.text is not None and options.file is not None:
            raise UsageError("--text and --file are mutually exclusive")

        if options.file is not None:
            if not options.file.exists():
                raise InputError(f"file not found: {options.file}")
            report.target = str(options.file)
            label = options.file.name
            data = options.file.read_bytes()
        else:
            report.target = "text input"
            label = "text"
            data = options.text.encode("utf-8")

        if options.encode:
            encoded = encode_text(data.decode("utf-8"), options.encode)
            report.stats["output_bytes"] = len(encoded)
            report.add(
                category="encode",
                subject=label,
                summary=f"{options.encode} encoding ({len(encoded)} chars).",
                details={"scheme": options.encode, "output": encoded},
            )
            return report
        if options.decode:
            decoded = decode_text(data.decode("utf-8"), options.decode)
            report.stats["output_bytes"] = len(decoded)
            report.add(
                category="decode",
                subject=label,
                summary=f"Decoded {options.decode} input to {len(decoded)} bytes.",
                details={
                    "scheme": options.decode,
                    "output_utf8": decoded.decode("utf-8", errors="replace"),
                    "output_hex": decoded.hex(),
                },
            )
            return report

        digests = hash_bytes(data, algorithms)
        report.stats["algorithms"] = len(digests)
        for name, digest in digests.items():
            report.add(
                category="hash",
                subject=label,
                summary=f"{name}: {digest}",
                details={"algorithm": name, "digest": digest, "bytes": len(data)},
            )
        return report
