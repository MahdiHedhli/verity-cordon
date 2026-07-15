"""Restrictive local-file Ed25519 installation-key provider."""

from __future__ import annotations

import base64
import os
import stat
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from verity_cordon.core.errors import ConfigurationError
from verity_cordon.crypto.canonical import sha256_hex


def _open_flags(base: int) -> int:
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    return base | no_follow | close_on_exec


def _assert_regular_private_file(descriptor: int) -> None:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise ConfigurationError("The signing key is not a regular file.")
    if os.name != "nt" and metadata.st_uid != os.geteuid():
        raise ConfigurationError("The signing key has an unexpected owner.")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ConfigurationError("The signing key has unsafe permissions.")


class FileKeyProvider:
    """Ed25519 provider backed by a mode-0600 PKCS#8 PEM file."""

    def __init__(self, private_key: Ed25519PrivateKey, path: Path) -> None:
        self._private_key = private_key
        self.path = path
        self._public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._fingerprint = sha256_hex(self._public_bytes)

    @property
    def key_id(self) -> str:
        return f"vc-ed25519-{self._fingerprint}"

    @property
    def public_key_fingerprint(self) -> str:
        return self._fingerprint

    @classmethod
    def generate(cls, path: Path) -> FileKeyProvider:
        """Create a new installation key without overwriting existing state."""

        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            path.parent.chmod(0o700)
        except OSError as exc:
            raise ConfigurationError("Unable to secure the signing-key directory.") from exc

        private_key = Ed25519PrivateKey.generate()
        serialized = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        descriptor = os.open(
            path,
            _open_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL),
            0o600,
        )
        try:
            _assert_regular_private_file(descriptor)
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                handle.write(serialized)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return cls(private_key, path)

    @classmethod
    def load(cls, path: Path) -> FileKeyProvider:
        if path.is_symlink():
            raise ConfigurationError("The signing key must not be a symbolic link.")
        try:
            descriptor = os.open(path, _open_flags(os.O_RDONLY))
        except OSError as exc:
            raise ConfigurationError("Unable to open the installation signing key.") from exc
        try:
            _assert_regular_private_file(descriptor)
            with os.fdopen(descriptor, "rb", closefd=True) as handle:
                raw = handle.read(16_384)
                if handle.read(1):
                    raise ConfigurationError("The installation signing key is oversized.")
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise

        try:
            key: Any = serialization.load_pem_private_key(raw, password=None)
        except (TypeError, ValueError) as exc:
            raise ConfigurationError("The installation signing key is invalid.") from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise ConfigurationError("The installation signing key is not Ed25519.")
        return cls(key, path)

    async def sign(self, digest: bytes) -> bytes:
        if len(digest) != 32:
            raise ValueError("Ed25519 event signatures require a 32-byte SHA-256 digest")
        return self._private_key.sign(digest)

    async def verify(self, digest: bytes, signature: bytes) -> None:
        if len(digest) != 32 or len(signature) != 64:
            raise ValueError("Invalid event signature material")
        try:
            self._private_key.public_key().verify(signature, digest)
        except InvalidSignature as exc:
            raise ValueError("Invalid event signature") from exc

    async def export_public(self) -> dict[str, str]:
        return {
            "algorithm": "Ed25519",
            "key_id": self.key_id,
            "public_key": base64.b64encode(self._public_bytes).decode("ascii"),
            "public_key_fingerprint": self._fingerprint,
        }


def decode_public_key(encoded: str) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid public-key encoding") from exc
    if len(raw) != 32:
        raise ValueError("Invalid Ed25519 public-key length")
    return Ed25519PublicKey.from_public_bytes(raw)
