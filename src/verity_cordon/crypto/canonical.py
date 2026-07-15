"""VC-CJ-1 canonical JSON and SHA-256 helpers.

VC-CJ-1 is deliberately small and is not advertised as RFC 8785. It accepts
ordinary JSON values, sorts object keys, emits compact UTF-8 JSON, rejects
duplicate keys at parsing boundaries, rejects non-finite numbers, and performs
no Unicode normalization.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from typing import Any


def _reject_non_finite(token: str) -> None:
    raise ValueError(f"Non-finite JSON number is prohibited: {token}")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON object key is prohibited: {key}")
        result[key] = value
    return result


def parse_json_strict(value: str | bytes | bytearray) -> Any:
    """Parse JSON while rejecting duplicate keys and extension number tokens."""

    return json.loads(
        value,
        object_pairs_hook=_object_without_duplicates,
        parse_constant=_reject_non_finite,
    )


def _validate_json(value: Any, *, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"JSON number at {path} must be finite")
        return
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise TypeError(f"JSON object key at {path} must be a string")
            _validate_json(child, path=f"{path}.{key}")
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            _validate_json(child, path=f"{path}[{index}]")
        return
    raise TypeError(f"Value at {path} is not representable by VC-CJ-1")


def canonical_json(value: Any) -> str:
    """Return the exact VC-CJ-1 representation for a JSON-compatible value."""

    _validate_json(value)
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        encoded.encode("utf-8", errors="strict")
    except (UnicodeEncodeError, ValueError) as exc:
        raise ValueError("Value cannot be represented as canonical UTF-8 JSON") from exc
    return encoded


def canonical_json_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def sha256_bytes(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_sha256_hex(value: Any) -> str:
    return sha256_hex(canonical_json_bytes(value))
