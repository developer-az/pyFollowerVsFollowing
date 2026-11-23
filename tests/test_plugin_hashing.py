"""hashing: digests, encodings, identification, plugin modes."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from osint_kit.core.errors import InputError, UsageError
from osint_kit.plugins.hashing import (
    HashingPlugin,
    decode_text,
    encode_text,
    hash_bytes,
    hash_file,
    hash_text,
    identify_hash,
)


def test_known_digests() -> None:
    digests = hash_text("abc", ("md5", "sha1", "sha256"))
    assert digests["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert digests["sha1"] == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert digests["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_hash_file_matches_bytes(tmp_path: Path) -> None:
    path = tmp_path / "data.bin"
    path.write_bytes(b"abc" * 1000)
    assert hash_file(path, ("sha256",)) == hash_bytes(b"abc" * 1000, ("sha256",))


def test_hash_file_errors(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="not found"):
        hash_file(tmp_path / "missing.bin")
    with pytest.raises(UsageError, match="unknown hash algorithm"):
        hash_text("x", ("not-a-hash",))


def test_encode_and_decode() -> None:
    assert encode_text("abc", "hex") == "616263"
    assert encode_text("abc", "base64") == "YWJj"
    assert encode_text("a b&c", "url") == "a%20b%26c"
    assert decode_text("616263", "hex") == b"abc"
    assert decode_text("YWJj", "base64") == b"abc"
    assert decode_text("a%20b", "url") == b"a b"


def test_decode_errors() -> None:
    with pytest.raises(UsageError, match="invalid hex"):
        decode_text("zz", "hex")
    with pytest.raises(UsageError, match="invalid base64"):
        decode_text("!!!", "base64")
    with pytest.raises(UsageError, match="unknown encoding"):
        decode_text("x", "rot13")
    with pytest.raises(UsageError, match="unknown encoding"):
        encode_text("x", "rot13")


def test_identify_known_formats() -> None:
    assert identify_hash("900150983cd24fb0d6963f7d28e17f72")[0].name == "md5"
    assert (
        identify_hash("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")[0].name
        == "sha256"
    )
    assert identify_hash("$2b$12$abcdefghijklmnopqrstuv")[0].name == "bcrypt"
    assert identify_hash("$argon2id$v=19$m=65536")[0].name == "argon2id"
    assert identify_hash("$6$salt$hash")[0].name == "sha512crypt"


def test_identify_unknown_and_empty() -> None:
    assert identify_hash("") == ()
    assert identify_hash("notahash") == ()
    assert identify_hash("$unknown$whatever") == ()


def test_plugin_hash_text_and_bytes(context_factory: Any) -> None:
    ctx = context_factory()
    report = HashingPlugin().run(
        argparse.Namespace(
            text="abc",
            file=None,
            algorithms=["md5"],
            identify=None,
            encode=None,
            decode=None,
        ),
        ctx,
    )
    assert report.stats["algorithms"] == 1
    assert report.findings[0].summary == "md5: 900150983cd24fb0d6963f7d28e17f72"


def test_plugin_file_identify_encode_decode(context_factory: Any, tmp_path: Path) -> None:
    ctx = context_factory()
    path = tmp_path / "data.txt"
    path.write_text("abc", encoding="utf-8")

    report = HashingPlugin().run(
        argparse.Namespace(
            text=None,
            file=path,
            algorithms=None,
            identify=None,
            encode=None,
            decode=None,
        ),
        ctx,
    )
    assert report.target == str(path)

    report = HashingPlugin().run(
        argparse.Namespace(
            text=None,
            file=None,
            algorithms=None,
            identify="900150983cd24fb0d6963f7d28e17f72",
            encode=None,
            decode=None,
        ),
        ctx,
    )
    assert report.stats["candidates"] >= 1

    unknown = HashingPlugin().run(
        argparse.Namespace(
            text=None,
            file=None,
            algorithms=None,
            identify="plain-text",
            encode=None,
            decode=None,
        ),
        ctx,
    )
    assert unknown.findings[0].severity.value == "low"

    encoded = HashingPlugin().run(
        argparse.Namespace(
            text="abc",
            file=None,
            algorithms=None,
            identify=None,
            encode="base64",
            decode=None,
        ),
        ctx,
    )
    assert encoded.findings[0].details["output"] == "YWJj"

    decoded = HashingPlugin().run(
        argparse.Namespace(
            text="616263",
            file=None,
            algorithms=None,
            identify=None,
            encode=None,
            decode="hex",
        ),
        ctx,
    )
    assert decoded.findings[0].details["output_utf8"] == "abc"


def test_plugin_usage_errors(context_factory: Any, tmp_path: Path) -> None:
    ctx = context_factory()
    base = argparse.Namespace(
        text=None,
        file=None,
        algorithms=None,
        identify=None,
        encode=None,
        decode=None,
    )
    with pytest.raises(UsageError, match="provide --text or --file"):
        HashingPlugin().run(base, ctx)

    with pytest.raises(InputError, match="not found"):
        HashingPlugin().run(
            argparse.Namespace(**{**vars(base), "file": tmp_path / "nope.bin"}), ctx
        )


@given(st.text(max_size=200), st.sampled_from(["hex", "base64", "url"]))
def test_encoding_roundtrip(text: str, scheme: str) -> None:
    encoded = encode_text(text, scheme)
    assert decode_text(encoded, scheme) == text.encode("utf-8")
