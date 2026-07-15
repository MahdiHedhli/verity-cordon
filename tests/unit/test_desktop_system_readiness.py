"""Bounded, direct-loopback Desktop protection-readiness client tests."""

from __future__ import annotations

import json
from typing import Any

import pytest

from verity_cordon.codex import demo_installer


def _readiness_body(**updates: Any) -> bytes:
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "ready": True,
        "daemon_ready": True,
        "ledger_verified": True,
        "policy_valid": True,
        "memory_view_consistent": True,
        "policy": {
            "policy_id": "verity.default",
            "version": "1.0.0",
            "mode": "enforce",
            "digest": "a" * 64,
            "validation_state": "valid",
        },
    }
    payload.update(updates)
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _control_room_headers() -> list[tuple[str, str]]:
    return [
        ("Content-Type", "text/html; charset=utf-8"),
        ("Cache-Control", "no-store"),
        (
            "Content-Security-Policy",
            "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        ),
        ("Referrer-Policy", "no-referrer"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
    ]


class _Response:
    def __init__(
        self,
        status: int,
        body: bytes,
        headers: list[tuple[str, str]],
    ) -> None:
        self.status = status
        self._body = body
        self._headers = headers

    def read(self, amount: int) -> bytes:
        return self._body[:amount]

    def getheaders(self) -> list[tuple[str, str]]:
        return self._headers


class _Connection:
    def __init__(
        self,
        responses: list[_Response],
        calls: list[tuple[str, str, dict[str, str]]],
    ) -> None:
        self.responses = responses
        self.calls = calls

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str],
    ) -> None:
        self.calls.append((method, path, headers))

    def getresponse(self) -> _Response:
        return self.responses.pop(0)

    def close(self) -> None:
        return None


class _ConnectionFactory:
    def __init__(self, responses: list[_Response]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str, dict[str, str]]] = []
        self.destinations: list[tuple[str, int, float]] = []

    def __call__(self, host: str, port: int, *, timeout: float) -> _Connection:
        self.destinations.append((host, port, timeout))
        return _Connection(self.responses, self.calls)


def _install_connection_factory(
    monkeypatch: pytest.MonkeyPatch,
    responses: list[_Response],
) -> _ConnectionFactory:
    factory = _ConnectionFactory(responses)
    monkeypatch.setattr(demo_installer.http.client, "HTTPConnection", factory)
    return factory


def test_system_probe_requires_healthy_daemon_and_hardened_control_room(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = _install_connection_factory(
        monkeypatch,
        [
            _Response(200, _readiness_body(), [("Content-Type", "application/json")]),
            _Response(200, b"<!doctype html>", _control_room_headers()),
        ],
    )

    report = demo_installer.probe_desktop_system(host="localhost", port=8765)

    assert report.ready is True
    assert report.daemon_ready is True
    assert report.ledger_verified is True
    assert report.policy_valid is True
    assert report.memory_view_consistent is True
    assert report.control_room_ready is True
    assert report.control_room_headers_ready is True
    assert report.issues == ()
    assert factory.destinations == [
        ("127.0.0.1", 8765, 1.0),
        ("127.0.0.1", 8765, 1.0),
    ]
    assert [call[:2] for call in factory.calls] == [
        ("GET", "/api/v1/readiness"),
        ("GET", "/"),
    ]
    for _, _, headers in factory.calls:
        assert "Authorization" not in headers
        assert "Cookie" not in headers
        assert headers["Host"] == "localhost:8765"


def test_system_probe_fails_content_safely_when_loopback_is_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(*_: Any, **__: Any) -> None:
        raise OSError("synthetic-private-network-detail")

    monkeypatch.setattr(demo_installer.http.client, "HTTPConnection", unavailable)

    report = demo_installer.probe_desktop_system(host="127.0.0.1", port=8765)

    assert report.ready is False
    assert report.issues == ("system_unreachable",)
    assert "synthetic-private-network-detail" not in repr(report)


@pytest.mark.parametrize(
    ("response", "expected_issue"),
    [
        (
            _Response(
                200,
                _readiness_body().replace(
                    b'"ready":true,',
                    b'"ready":true,"ready":true,',
                    1,
                ),
                [("Content-Type", "application/json")],
            ),
            "readiness_contract_invalid",
        ),
        (
            _Response(
                200,
                b"x" * 2049,
                [("Content-Type", "application/json")],
            ),
            "readiness_output_limit",
        ),
        (
            _Response(
                200,
                _readiness_body(policy_valid=None),
                [("Content-Type", "application/json")],
            ),
            "readiness_contract_invalid",
        ),
        (
            _Response(
                200,
                _readiness_body(),
                [("Content-Type", "application/jsonp")],
            ),
            "readiness_contract_invalid",
        ),
        (
            _Response(503, b"synthetic-private-error", [("Content-Type", "application/json")]),
            "readiness_http_error",
        ),
    ],
)
def test_system_probe_rejects_malformed_oversize_and_failed_readiness(
    monkeypatch: pytest.MonkeyPatch,
    response: _Response,
    expected_issue: str,
) -> None:
    _install_connection_factory(monkeypatch, [response])

    report = demo_installer.probe_desktop_system(
        host="127.0.0.1",
        port=8765,
        max_response_bytes=2048,
    )

    assert report.ready is False
    assert report.issues == (expected_issue,)
    assert "synthetic-private-error" not in repr(report)


def test_system_probe_requires_every_control_room_security_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incomplete = [pair for pair in _control_room_headers() if pair[0].lower() != "x-frame-options"]
    _install_connection_factory(
        monkeypatch,
        [
            _Response(200, _readiness_body(), [("Content-Type", "application/json")]),
            _Response(200, b"<!doctype html>", incomplete),
        ],
    )

    report = demo_installer.probe_desktop_system(host="127.0.0.1", port=8765)

    assert report.ready is False
    assert report.control_room_ready is True
    assert report.control_room_headers_ready is False
    assert report.issues == ("control_room_security_headers_invalid",)


@pytest.mark.parametrize(
    ("body", "content_type"),
    [
        (b'{"error":"synthetic"}', "application/json"),
        (b"<!doctype html>", None),
        (b"", "text/html; charset=utf-8"),
    ],
)
def test_system_probe_rejects_non_html_or_empty_control_room_response(
    monkeypatch: pytest.MonkeyPatch,
    body: bytes,
    content_type: str | None,
) -> None:
    headers = [
        (name, value) for name, value in _control_room_headers() if name.lower() != "content-type"
    ]
    if content_type is not None:
        headers.append(("Content-Type", content_type))
    _install_connection_factory(
        monkeypatch,
        [
            _Response(200, _readiness_body(), [("Content-Type", "application/json")]),
            _Response(200, body, headers),
        ],
    )

    report = demo_installer.probe_desktop_system(host="127.0.0.1", port=8765)

    assert report.ready is False
    assert report.control_room_ready is False
    assert "control_room_contract_invalid" in report.issues


def test_system_probe_caps_control_room_body(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_connection_factory(
        monkeypatch,
        [
            _Response(200, _readiness_body(), [("Content-Type", "application/json")]),
            _Response(200, b"x" * 2049, _control_room_headers()),
        ],
    )

    report = demo_installer.probe_desktop_system(
        host="127.0.0.1",
        port=8765,
        max_response_bytes=2048,
    )

    assert report.ready is False
    assert report.control_room_ready is False
    assert "control_room_output_limit" in report.issues


@pytest.mark.parametrize(
    ("updates", "policy_validation", "expected_issue"),
    [
        ({"ready": False, "ledger_verified": False}, "valid", "ledger_invalid"),
        ({"ready": False, "policy_valid": False}, "invalid", "policy_invalid"),
        (
            {"ready": False, "memory_view_consistent": False},
            "valid",
            "materialized_view_stale",
        ),
    ],
)
def test_system_probe_surfaces_invalid_ledger_policy_and_view_components(
    monkeypatch: pytest.MonkeyPatch,
    updates: dict[str, bool],
    policy_validation: str,
    expected_issue: str,
) -> None:
    payload_updates: dict[str, Any] = dict(updates)
    policy = {
        "policy_id": "verity.default",
        "version": "1.0.0",
        "mode": "enforce",
        "digest": "a" * 64,
        "validation_state": policy_validation,
    }
    payload_updates["policy"] = policy
    _install_connection_factory(
        monkeypatch,
        [
            _Response(
                200,
                _readiness_body(**payload_updates),
                [("Content-Type", "application/json")],
            ),
            _Response(200, b"<!doctype html>", _control_room_headers()),
        ],
    )

    report = demo_installer.probe_desktop_system(host="127.0.0.1", port=8765)

    assert report.ready is False
    assert expected_issue in report.issues
    assert report.control_room_ready is True
