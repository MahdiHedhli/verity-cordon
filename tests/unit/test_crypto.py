"""Tests for the signed-ledger canonicalization and installation key."""

from __future__ import annotations

import base64
import json
import math
import os
import stat
from datetime import UTC, datetime

import pytest

from verity_cordon.core.errors import ConfigurationError
from verity_cordon.core.models import format_utc
from verity_cordon.crypto.canonical import (
    canonical_json,
    canonical_json_bytes,
    parse_json_strict,
    sha256_hex,
)
from verity_cordon.crypto.keys import FileKeyProvider


def test_vc_cj_1_sorts_keys_and_uses_compact_utf8() -> None:
    value = {"z": "café", "a": [True, None, 3]}

    assert canonical_json(value) == '{"a":[true,null,3],"z":"café"}'
    assert canonical_json_bytes(value) == canonical_json(value).encode("utf-8")


def test_vc_cj_1_preserves_unicode_codepoints_without_normalization() -> None:
    composed = canonical_json({"value": "é"})
    decomposed = canonical_json({"value": "e\u0301"})

    assert composed != decomposed
    assert sha256_hex(composed.encode()) != sha256_hex(decomposed.encode())


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_vc_cj_1_rejects_non_finite_values(value: float) -> None:
    with pytest.raises(ValueError, match="finite"):
        canonical_json({"value": value})


def test_strict_json_parser_rejects_duplicate_keys() -> None:
    with pytest.raises(ValueError, match="Duplicate JSON object key"):
        parse_json_strict('{"policy":"safe","policy":"attacker"}')


def test_strict_json_parser_rejects_non_finite_tokens() -> None:
    with pytest.raises(ValueError, match="Non-finite"):
        parse_json_strict('{"value": NaN}')


def test_vc_cj_1_rejects_non_json_values() -> None:
    with pytest.raises((TypeError, ValueError)):
        canonical_json({"payload": b"raw"})


def test_timestamp_normalization_is_exact_utc() -> None:
    timestamp = datetime(2026, 7, 15, 14, 3, 2, 120_000, tzinfo=UTC)

    assert format_utc(timestamp) == "2026-07-15T14:03:02.12Z"
    assert format_utc(datetime(2026, 7, 15, 14, 3, 2, tzinfo=UTC)).endswith("02Z")


@pytest.mark.asyncio
async def test_file_key_provider_signs_raw_digest_and_exports_padded_base64(tmp_path) -> None:
    key_path = tmp_path / "signing-key.pem"
    provider = FileKeyProvider.generate(key_path)
    digest = bytes.fromhex(sha256_hex(b"event"))

    signature = await provider.sign(digest)
    await provider.verify(digest, signature)
    exported = await provider.export_public()

    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    assert provider.key_id == f"vc-ed25519-{sha256_hex(base64.b64decode(exported['public_key']))}"
    assert exported["algorithm"] == "Ed25519"
    assert exported["public_key"].endswith("=")
    assert base64.b64decode(exported["public_key"], validate=True)
    assert base64.b64encode(signature).decode("ascii").endswith("==")


def test_file_key_provider_refuses_unsafe_permissions(tmp_path) -> None:
    key_path = tmp_path / "signing-key.pem"
    FileKeyProvider.generate(key_path)
    os.chmod(key_path, 0o644)

    with pytest.raises(ConfigurationError, match="unsafe permissions"):
        FileKeyProvider.load(key_path)


def test_file_key_provider_refuses_symlink(tmp_path) -> None:
    key_path = tmp_path / "signing-key.pem"
    FileKeyProvider.generate(key_path)
    symlink = tmp_path / "linked.pem"
    symlink.symlink_to(key_path)

    with pytest.raises(ConfigurationError, match="symbolic link"):
        FileKeyProvider.load(symlink)


def test_key_generation_is_explicit_and_non_overwriting(tmp_path) -> None:
    key_path = tmp_path / "signing-key.pem"
    FileKeyProvider.generate(key_path)

    with pytest.raises(FileExistsError):
        FileKeyProvider.generate(key_path)


@pytest.mark.asyncio
async def test_signature_verification_rejects_tampering(tmp_path) -> None:
    provider = FileKeyProvider.generate(tmp_path / "signing-key.pem")
    digest = bytes.fromhex(sha256_hex(b"event"))
    signature = await provider.sign(digest)

    with pytest.raises(ValueError, match="signature"):
        await provider.verify(bytes.fromhex(sha256_hex(b"tampered")), signature)


def test_canonical_output_round_trips_through_strict_json() -> None:
    value = {"nested": {"z": 1, "a": "safe"}}

    assert parse_json_strict(canonical_json(value)) == value
    assert json.loads(canonical_json(value)) == value
