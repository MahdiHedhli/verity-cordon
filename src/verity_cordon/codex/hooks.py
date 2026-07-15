"""Thin, bounded command-hook adapter for documented Codex lifecycle events.

This module intentionally uses only the Python standard library so an installed
plugin can execute the copied hook without importing the Verity application.
It validates and forwards evidence; it contains no detector, policy, semantic,
ledger, or materialization behavior.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
import stat
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Protocol, cast
from urllib.parse import urlsplit

SCHEMA_VERSION: Final = "1.0.0"
MAX_STDIN_BYTES: Final = 1_048_576
MAX_RESPONSE_BYTES: Final = 262_144
MAX_EVIDENCE_TEXT: Final = 262_144
MAX_CONTEXT_BYTES: Final = 131_072
DEFAULT_DAEMON_URL: Final = "http://127.0.0.1:8765"
DEFAULT_TIMEOUT_SECONDS: Final = 1.5
START_DELIMITER: Final = "VERITY_CORDON_APPROVED_MEMORY_START"
END_DELIMITER: Final = "VERITY_CORDON_APPROVED_MEMORY_END"
WARNING: Final = "Verity Cordon memory unavailable; continuing without durable memory."

SELECTED_EVENTS: Final = frozenset(
    {
        "SessionStart",
        "UserPromptSubmit",
        "PostToolUse",
        "PreCompact",
        "PostCompact",
        "Stop",
    }
)
PERMISSION_MODES: Final = frozenset(
    {"default", "acceptEdits", "plan", "dontAsk", "bypassPermissions"}
)
SESSION_SOURCES: Final = frozenset({"startup", "resume", "clear", "compact"})
COMPACTION_TRIGGERS: Final = frozenset({"manual", "auto"})


class HookError(Exception):
    """Content-free adapter failure used only for local control flow."""


class HookInputError(HookError):
    """The Codex hook input does not satisfy the supported contract."""


class HookTransportError(HookError):
    """The loopback daemon request could not be completed safely."""


class HookResponseError(HookError):
    """The daemon response does not satisfy the local IPC contract."""


class DuplicateKeyError(HookInputError):
    """A JSON object contains a duplicate key."""


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    body: bytes
    content_type: str | None = None


class Transport(Protocol):
    def __call__(
        self,
        *,
        base_url: str,
        path: str,
        body: bytes,
        headers: dict[str, str],
        timeout: float,
    ) -> HttpResponse: ...


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError("duplicate_json_key")
        result[key] = value
    return result


def _reject_nonfinite(_: str) -> None:
    raise HookInputError("nonfinite_json_number")


def parse_one_object(raw: bytes, *, maximum_bytes: int = MAX_STDIN_BYTES) -> dict[str, Any]:
    """Parse exactly one finite JSON object while rejecting duplicate keys."""

    if not raw or len(raw) > maximum_bytes:
        raise HookInputError("invalid_hook_input_size")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HookInputError("invalid_hook_input_encoding") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_nonfinite,
        )
    except HookInputError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise HookInputError("malformed_hook_json") from exc
    if not isinstance(value, dict):
        raise HookInputError("hook_input_not_object")
    return cast(dict[str, Any], value)


def _canonical_bytes(value: Any) -> bytes:
    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise HookInputError("hook_input_not_json_compatible") from exc
    return rendered.encode("utf-8")


def _require_string(
    value: dict[str, Any],
    key: str,
    *,
    minimum: int = 1,
    maximum: int,
) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not minimum <= len(item) <= maximum or "\x00" in item:
        raise HookInputError("invalid_hook_field")
    return item


def _require_permission(value: dict[str, Any]) -> str:
    permission = _require_string(value, "permission_mode", maximum=64)
    if permission not in PERMISSION_MODES:
        raise HookInputError("invalid_permission_mode")
    return permission


def _normalize_cwd(value: str) -> str:
    normalized = os.path.abspath(os.path.normpath(value))
    if len(normalized) > 4096 or "\x00" in normalized:
        raise HookInputError("invalid_cwd")
    return normalized


def _timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _normalize_common(value: dict[str, Any], expected_event: str) -> dict[str, Any]:
    actual_event = _require_string(value, "hook_event_name", maximum=64)
    if expected_event not in SELECTED_EVENTS or actual_event != expected_event:
        raise HookInputError("unexpected_hook_event")
    transcript_path = value.get("transcript_path")
    if transcript_path is not None and not isinstance(transcript_path, str):
        raise HookInputError("invalid_transcript_path")
    return {
        "session_id": _require_string(value, "session_id", minimum=8, maximum=128),
        "cwd": _normalize_cwd(_require_string(value, "cwd", maximum=4096)),
        "model": _require_string(value, "model", maximum=128),
    }


def normalize_hook_input(
    value: dict[str, Any],
    expected_event: str,
    *,
    now: Callable[[], str] = _timestamp,
) -> tuple[str, dict[str, Any], str | None]:
    """Normalize only contracted fields and return path, body, and retry key."""

    common = _normalize_common(value, expected_event)
    if expected_event == "SessionStart":
        source = _require_string(value, "source", maximum=32)
        if source not in SESSION_SOURCES:
            raise HookInputError("invalid_session_source")
        request = {
            "schema_version": SCHEMA_VERSION,
            "hook_event": expected_event,
            **common,
            "source": source,
            "permission_mode": _require_permission(value),
            "requested_at": now(),
        }
        return "/api/v1/hooks/session-start", request, None

    turn_id = _require_string(value, "turn_id", minimum=8, maximum=128)
    permission_mode: str | None = None
    payload: dict[str, Any]
    if expected_event == "UserPromptSubmit":
        permission_mode = _require_permission(value)
        prompt = _require_string(value, "prompt", maximum=MAX_EVIDENCE_TEXT)
        payload = {"prompt": prompt}
    elif expected_event == "PostToolUse":
        permission_mode = _require_permission(value)
        payload = {
            "tool_name": _require_string(value, "tool_name", maximum=256),
            "tool_use_id": _require_string(value, "tool_use_id", minimum=8, maximum=128),
            "tool_input": value.get("tool_input"),
            "tool_response": value.get("tool_response"),
        }
        if "tool_input" not in value or "tool_response" not in value:
            raise HookInputError("missing_tool_payload")
    elif expected_event in {"PreCompact", "PostCompact"}:
        trigger = _require_string(value, "trigger", maximum=16)
        if trigger not in COMPACTION_TRIGGERS:
            raise HookInputError("invalid_compaction_trigger")
        payload = {"trigger": trigger}
    elif expected_event == "Stop":
        permission_mode = _require_permission(value)
        stop_active = value.get("stop_hook_active")
        message = value.get("last_assistant_message")
        if not isinstance(stop_active, bool):
            raise HookInputError("invalid_stop_state")
        if message is not None and (
            not isinstance(message, str) or len(message) > MAX_EVIDENCE_TEXT
        ):
            raise HookInputError("invalid_assistant_message")
        payload = {
            "stop_hook_active": stop_active,
            "last_assistant_message": message,
        }
    else:
        raise HookInputError("unexpected_hook_event")

    request = {
        "schema_version": SCHEMA_VERSION,
        "hook_event": expected_event,
        **common,
        "turn_id": turn_id,
        "permission_mode": permission_mode,
        "captured_at": now(),
        "payload": payload,
    }
    stable_identity = {
        "schema_version": SCHEMA_VERSION,
        "hook_event": expected_event,
        "session_id": common["session_id"],
        "turn_id": turn_id,
        "tool_use_id": payload.get("tool_use_id"),
        "payload": payload,
    }
    digest = hashlib.sha256(_canonical_bytes(stable_identity)).hexdigest()
    return "/api/v1/hooks/evidence", request, f"vc-hook-{digest}"


def _default_capability_path() -> Path:
    explicit = os.environ.get("VERITY_CAPABILITY_PATH")
    if explicit:
        return Path(explicit).expanduser()
    data_dir = os.environ.get("VERITY_DATA_DIR")
    if data_dir:
        return Path(data_dir).expanduser() / "mutation-capability"
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support" / "verity-cordon"
    elif os.name == "nt":
        local = os.environ.get("LOCALAPPDATA")
        if not local:
            raise HookInputError("capability_path_unavailable")
        base = Path(local) / "Verity Cordon" / "verity-cordon"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        base /= "verity-cordon"
    return base / "mutation-capability"


def read_capability(path: Path) -> str:
    """Read one restrictive, regular, current-user capability file."""

    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        elif path.is_symlink():
            raise HookInputError("unsafe_capability_file")
        descriptor = os.open(path, flags)
        details = os.fstat(descriptor)
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
            raise HookInputError("unsafe_capability_file")
        if os.name != "nt":
            if details.st_mode & 0o077 or details.st_uid != os.geteuid():
                raise HookInputError("unsafe_capability_permissions")
        if details.st_size > 1024:
            raise HookInputError("invalid_capability_file")
        with os.fdopen(descriptor, "r", encoding="ascii", closefd=True) as handle:
            descriptor = -1
            value = handle.read(1025).strip()
    except HookError:
        raise
    except (OSError, UnicodeError) as exc:
        raise HookInputError("capability_unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not 32 <= len(value) <= 512 or any(
        not 0x21 <= ord(character) <= 0x7E for character in value
    ):
        raise HookInputError("invalid_capability")
    return value


def _validate_base_url(base_url: str) -> tuple[str, int, str]:
    parsed = urlsplit(base_url)
    if (
        parsed.scheme != "http"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.hostname is None
    ):
        raise HookTransportError("invalid_daemon_url")
    host = parsed.hostname
    if host == "localhost":
        host = "127.0.0.1"
    else:
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise HookTransportError("daemon_not_loopback")
        except ValueError as exc:
            raise HookTransportError("daemon_not_loopback") from exc
    try:
        port = parsed.port or 80
    except ValueError as exc:
        raise HookTransportError("invalid_daemon_port") from exc
    if not 1 <= port <= 65535:
        raise HookTransportError("invalid_daemon_port")
    netloc = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    return host, port, netloc


def post_loopback_json(
    *,
    base_url: str,
    path: str,
    body: bytes,
    headers: dict[str, str],
    timeout: float,
) -> HttpResponse:
    """POST directly to a verified loopback address without proxy inheritance."""

    host, port, host_header = _validate_base_url(base_url)
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    request_headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
        "Host": host_header,
        "User-Agent": "verity-cordon-codex-hook/0.1",
        **headers,
    }
    try:
        connection.request("POST", path, body=body, headers=request_headers)
        response = connection.getresponse()
        response_body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(response_body) > MAX_RESPONSE_BYTES:
            raise HookResponseError("daemon_response_too_large")
        return HttpResponse(
            status=response.status,
            body=response_body,
            content_type=response.getheader("Content-Type"),
        )
    except HookError:
        raise
    except (OSError, TimeoutError, http.client.HTTPException) as exc:
        raise HookTransportError("daemon_request_failed") from exc
    finally:
        connection.close()


def _decode_response(response: HttpResponse, *, expected_status: int) -> dict[str, Any]:
    if response.status != expected_status or not response.body:
        raise HookResponseError("unexpected_daemon_status")
    content_type = response.content_type or ""
    if content_type and content_type.split(";", 1)[0].strip().lower() != "application/json":
        raise HookResponseError("unexpected_daemon_content_type")
    try:
        return parse_one_object(response.body, maximum_bytes=MAX_RESPONSE_BYTES)
    except HookInputError as exc:
        raise HookResponseError("malformed_daemon_response") from exc


def _validate_evidence_response(value: dict[str, Any]) -> None:
    if set(value) != {"schema_version", "evidence_id", "status", "duplicate"}:
        raise HookResponseError("invalid_evidence_response")
    evidence_id = value.get("evidence_id")
    if (
        value.get("schema_version") != SCHEMA_VERSION
        or value.get("status") not in {"captured", "queued"}
        or not isinstance(evidence_id, str)
        or not 8 <= len(evidence_id) <= 128
        or not isinstance(value.get("duplicate"), bool)
    ):
        raise HookResponseError("invalid_evidence_response")


def _valid_context(value: str) -> bool:
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        return False
    lines = value.splitlines()
    return (
        0 < len(encoded) <= MAX_CONTEXT_BYTES
        and value.count(START_DELIMITER) == 1
        and value.count(END_DELIMITER) == 1
        and bool(lines)
        and lines[0] == START_DELIMITER
        and lines[-1] == END_DELIMITER
        and "\x00" not in value
    )


def _validate_session_response(value: dict[str, Any]) -> str | None:
    required = {
        "schema_version",
        "injection_state",
        "additional_context",
        "memory_ids",
        "token_estimate",
        "ledger_verified",
        "view_consistent",
        "warning_code",
    }
    if set(value) != required or value.get("schema_version") != SCHEMA_VERSION:
        raise HookResponseError("invalid_session_response")
    state = value.get("injection_state")
    if state not in {
        "ready",
        "disabled_empty",
        "disabled_ledger",
        "disabled_policy",
        "disabled_view",
        "unavailable",
    }:
        raise HookResponseError("invalid_session_response")
    memory_ids = value.get("memory_ids")
    token_estimate = value.get("token_estimate")
    ledger_verified = value.get("ledger_verified")
    view_consistent = value.get("view_consistent")
    warning_code = value.get("warning_code")
    if (
        not isinstance(memory_ids, list)
        or any(not isinstance(item, str) or not 8 <= len(item) <= 128 for item in memory_ids)
        or len(memory_ids) != len(set(memory_ids))
        or isinstance(token_estimate, bool)
        or not isinstance(token_estimate, int)
        or token_estimate < 0
        or not isinstance(ledger_verified, bool)
        or not isinstance(view_consistent, bool)
        or warning_code
        not in {
            None,
            "no_active_memory",
            "ledger_unverified",
            "policy_invalid",
            "view_inconsistent",
            "daemon_degraded",
        }
    ):
        raise HookResponseError("invalid_session_response")
    context = value.get("additional_context")
    if state == "ready":
        if (
            not ledger_verified
            or not view_consistent
            or not memory_ids
            or not isinstance(context, str)
            or not _valid_context(context)
            or warning_code is not None
        ):
            raise HookResponseError("unsafe_session_response")
        return context
    if context is not None or memory_ids:
        raise HookResponseError("ineligible_session_context")
    expected_failure = {
        "disabled_ledger": (False, None, "ledger_unverified"),
        "disabled_policy": (None, None, "policy_invalid"),
        "disabled_view": (None, False, "view_inconsistent"),
        "unavailable": (None, None, "daemon_degraded"),
    }
    if state == "disabled_empty":
        if (
            not ledger_verified
            or not view_consistent
            or warning_code
            not in {
                None,
                "no_active_memory",
            }
        ):
            raise HookResponseError("unsafe_empty_session_response")
    else:
        expected_ledger, expected_view, expected_warning = expected_failure[state]
        if (
            (expected_ledger is not None and ledger_verified is not expected_ledger)
            or (expected_view is not None and view_consistent is not expected_view)
            or warning_code != expected_warning
        ):
            raise HookResponseError("inconsistent_session_failure")
    return None


def _warning_output() -> dict[str, Any]:
    return {"continue": True, "systemMessage": WARNING}


@dataclass(slots=True)
class HookAdapter:
    """Content-safe adapter from one Codex hook process to the local daemon."""

    capability_path: Path | None = None
    base_url: str = DEFAULT_DAEMON_URL
    timeout: float = DEFAULT_TIMEOUT_SECONDS
    transport: Transport = post_loopback_json

    def process(self, expected_event: str, raw: bytes) -> dict[str, Any]:
        """Return a valid Codex continuation response for every outcome."""

        try:
            parsed = parse_one_object(raw)
            path, request, idempotency_key = normalize_hook_input(parsed, expected_event)
            capability = read_capability(self.capability_path or _default_capability_path())
            body = _canonical_bytes(request)
            if len(body) > MAX_STDIN_BYTES:
                raise HookInputError("normalized_request_too_large")
            headers = {"Authorization": f"Bearer {capability}"}
            if idempotency_key is not None:
                headers["Idempotency-Key"] = idempotency_key
            response = self.transport(
                base_url=self.base_url,
                path=path,
                body=body,
                headers=headers,
                timeout=self.timeout,
            )
            decoded = _decode_response(
                response,
                expected_status=200 if expected_event == "SessionStart" else 202,
            )
            if expected_event == "SessionStart":
                context = _validate_session_response(decoded)
                if context is not None:
                    return {
                        "continue": True,
                        "hookSpecificOutput": {
                            "hookEventName": "SessionStart",
                            "additionalContext": context,
                        },
                    }
                if decoded["injection_state"] == "disabled_empty":
                    return {"continue": True}
                return _warning_output()
            _validate_evidence_response(decoded)
            return {"continue": True}
        except Exception:
            return _warning_output()


def read_bounded_stdin(stream: Any = None) -> bytes:
    source = stream if stream is not None else sys.stdin.buffer
    raw = source.read(MAX_STDIN_BYTES + 1)
    if len(raw) > MAX_STDIN_BYTES:
        raise HookInputError("hook_input_too_large")
    return cast(bytes, raw)


def main(argv: list[str] | None = None) -> int:
    """Run one synchronous command hook and always fail safe for memory reuse."""

    if os.environ.get("VERITY_SEMANTIC_CHILD") == "1":
        sys.stdout.write('{"continue":true}\n')
        return 0

    arguments = list(sys.argv[1:] if argv is None else argv)
    expected_event = arguments[0] if len(arguments) == 1 else ""
    try:
        raw = read_bounded_stdin()
        result = HookAdapter(
            base_url=os.environ.get("VERITY_DAEMON_URL", DEFAULT_DAEMON_URL)
        ).process(expected_event, raw)
    except Exception:
        result = _warning_output()
    sys.stdout.write(json.dumps(result, ensure_ascii=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
