"""Loopback boundary, bearer authorization, and passphrase-proof browser sessions."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import os
import secrets
import time
from collections import deque
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlparse

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from verity_cordon.core.config import Settings, assert_private_file
from verity_cordon.core.errors import AuthorizationError, ConfigurationError, RateLimitError
from verity_cordon.core.models import format_utc, new_id, utc_now

COOKIE_NAME = "verity_control_room"


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _read_or_create_salt(path: Path) -> bytes:
    if path.exists():
        if path.is_symlink():
            raise ConfigurationError("The Control Room verifier salt must not be a symbolic link.")
        assert_private_file(path)
        value = path.read_bytes()
        if len(value) != 16:
            raise ConfigurationError("The Control Room verifier salt is invalid.")
        return value
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    value = secrets.token_bytes(16)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return value


@dataclass(slots=True)
class _Challenge:
    nonce: bytes
    expires_at: float


@dataclass(slots=True)
class _Session:
    csrf_token: str
    origin: str
    last_activity: float


class ControlRoomAuth:
    def __init__(self, settings: Settings, capability: str) -> None:
        self.settings = settings
        self.capability = capability
        self.salt = _read_or_create_salt(settings.data_dir / "ui-verifier-salt")
        self._verifier = (
            hashlib.pbkdf2_hmac(
                "sha256",
                settings.control_room_passphrase.encode("utf-8"),
                self.salt,
                310_000,
                dklen=32,
            )
            if settings.control_room_passphrase is not None
            else None
        )
        self._challenges: dict[str, _Challenge] = {}
        self._sessions: dict[str, _Session] = {}
        self._challenge_times: deque[float] = deque()
        self._failure_times: deque[float] = deque()
        self._cooldown_until = 0.0
        self._lock = asyncio.Lock()

    def _require_origin(self, request: Request) -> str:
        origin = request.headers.get("origin")
        if origin != self.settings.control_room_origin:
            raise AuthorizationError("The browser origin is not authorized.")
        return origin

    async def create_challenge(self, request: Request) -> dict[str, object]:
        self._require_origin(request)
        if self._verifier is None:
            raise ConfigurationError("Control Room browser authentication is not configured.")
        now = time.monotonic()
        async with self._lock:
            if now < self._cooldown_until:
                raise RateLimitError("Control Room authentication is temporarily cooling down.")
            cutoff = now - 60
            while self._challenge_times and self._challenge_times[0] < cutoff:
                self._challenge_times.popleft()
            if len(self._challenge_times) >= self.settings.ui_challenge_rate_per_minute:
                raise RateLimitError("Too many Control Room challenges were requested.")
            self._challenge_times.append(now)
            challenge_id = new_id()
            nonce = secrets.token_bytes(32)
            expires_at = now + self.settings.ui_challenge_ttl_seconds
            self._challenges[challenge_id] = _Challenge(nonce=nonce, expires_at=expires_at)
            expired = [
                identifier
                for identifier, challenge in self._challenges.items()
                if challenge.expires_at < now
            ]
            for identifier in expired:
                self._challenges.pop(identifier, None)
        return {
            "schema_version": "1.0.0",
            "challenge_id": challenge_id,
            "nonce": _base64url(nonce),
            "salt": _base64url(self.salt),
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": 310_000,
            "expires_at": format_utc(
                utc_now() + timedelta(seconds=self.settings.ui_challenge_ttl_seconds)
            ),
        }

    async def create_session(
        self,
        request: Request,
        *,
        challenge_id: str,
        proof: str,
    ) -> tuple[str, dict[str, str]]:
        origin = self._require_origin(request)
        now = time.monotonic()
        async with self._lock:
            if now < self._cooldown_until:
                raise RateLimitError("Control Room authentication is temporarily cooling down.")
            challenge = self._challenges.pop(challenge_id, None)
            valid = False
            if challenge is not None and challenge.expires_at >= now and self._verifier is not None:
                expected = _base64url(
                    hmac.new(self._verifier, challenge.nonce, hashlib.sha256).digest()
                )
                valid = hmac.compare_digest(expected, proof)
            if not valid:
                window_start = now - self.settings.ui_failure_window_seconds
                while self._failure_times and self._failure_times[0] < window_start:
                    self._failure_times.popleft()
                self._failure_times.append(now)
                if len(self._failure_times) >= self.settings.ui_failure_limit:
                    self._cooldown_until = now + self.settings.ui_cooldown_seconds
                    self._failure_times.clear()
                raise AuthorizationError("The Control Room proof is invalid or expired.")
            self._failure_times.clear()
            session_token = _base64url(secrets.token_bytes(32))
            csrf_token = _base64url(secrets.token_bytes(32))
            self._sessions[session_token] = _Session(
                csrf_token=csrf_token,
                origin=origin,
                last_activity=now,
            )
        return session_token, {
            "schema_version": "1.0.0",
            "csrf_token": csrf_token,
            "expires_at": format_utc(
                utc_now() + timedelta(seconds=self.settings.ui_session_idle_seconds)
            ),
        }

    async def authorize_mutation(self, request: Request) -> None:
        authorization = request.headers.get("authorization", "")
        if authorization.startswith("Bearer "):
            supplied = authorization.removeprefix("Bearer ")
            if hmac.compare_digest(supplied, self.capability):
                return
            raise AuthorizationError("The local mutation capability is invalid.")

        origin = self._require_origin(request)
        session_token = request.cookies.get(COOKIE_NAME)
        csrf = request.headers.get("x-verity-csrf")
        if not session_token or not csrf:
            raise AuthorizationError("A Control Room session and CSRF token are required.")
        now = time.monotonic()
        async with self._lock:
            session = self._sessions.get(session_token)
            if session is None:
                raise AuthorizationError("The Control Room session is invalid.")
            if now - session.last_activity > self.settings.ui_session_idle_seconds:
                self._sessions.pop(session_token, None)
                raise AuthorizationError("The Control Room session expired.")
            if session.origin != origin or not hmac.compare_digest(session.csrf_token, csrf):
                raise AuthorizationError("The Control Room session proof is invalid.")
            session.last_activity = now


class LocalBoundaryMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, settings: Settings) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self.settings = settings
        self.allowed_host = urlparse(settings.control_room_origin).netloc

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        client_host = request.client.host if request.client else ""
        try:
            if not ipaddress.ip_address(client_host).is_loopback:
                raise ValueError
        except ValueError:
            return JSONResponse(
                status_code=403,
                content={"error": "forbidden", "message": "Loopback access is required."},
            )
        if request.headers.get("host") != self.allowed_host:
            return JSONResponse(
                status_code=403,
                content={"error": "forbidden", "message": "The Host header is not authorized."},
            )
        origin = request.headers.get("origin")
        if origin is not None and origin != self.settings.control_room_origin:
            return JSONResponse(
                status_code=403,
                content={"error": "forbidden", "message": "The Origin is not authorized."},
            )
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > self.settings.max_request_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "error": "payload_too_large",
                            "message": "The request exceeds the local size boundary.",
                        },
                    )
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={"error": "bad_request", "message": "Content-Length is invalid."},
                )
        if request.method in {"POST", "PUT", "PATCH"}:
            content_type = request.headers.get("content-type", "").split(";", 1)[0]
            if content_type != "application/json":
                return JSONResponse(
                    status_code=415,
                    content={
                        "error": "unsupported_media_type",
                        "message": "Mutations require application/json.",
                    },
                )
        return await call_next(request)
