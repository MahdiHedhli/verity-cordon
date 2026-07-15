"""Loopback-only FastAPI daemon and Control Room API."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, Query, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.middleware.base import RequestResponseEndpoint

from verity_cordon.core.errors import (
    AuthorizationError,
    ConflictError,
    LedgerError,
    NotFoundError,
    PolicyValidationError,
    RateLimitError,
    ResourceLimitError,
    VerityError,
)
from verity_cordon.core.models import SourceClass
from verity_cordon.crypto.canonical import canonical_json
from verity_cordon.daemon.contracts import (
    CandidateReviewRequest,
    ControlRoomSessionRequest,
    HookEvidenceRequest,
    LedgerVerifyRequest,
    OperatorActionRequest,
    PolicyActivationRequest,
    RebuildRequest,
    SessionStartRequest,
    StreamAbortRequest,
    StreamAppendRequest,
    StreamBeginRequest,
    StreamCommitRequest,
)
from verity_cordon.daemon.evidence_queue import EvidenceQueueWorker
from verity_cordon.daemon.runtime import Runtime
from verity_cordon.daemon.security import (
    COOKIE_NAME,
    ControlRoomAuth,
    LocalBoundaryMiddleware,
)
from verity_cordon.daemon.static import default_control_room_dist, install_control_room
from verity_cordon.memory.service import EvidenceSubmission
from verity_cordon.policies.models import PolicyDocument
from verity_cordon.streaming.session import StreamMetadata

IdempotencyKey = Annotated[
    str,
    Header(
        alias="Idempotency-Key",
        pattern=r"^[A-Za-z0-9._:-]{16,128}$",
    ),
]


def _error_status(error: VerityError) -> int:
    if isinstance(error, RateLimitError):
        return 429
    if isinstance(error, AuthorizationError):
        return 403
    if isinstance(error, NotFoundError):
        return 404
    if isinstance(error, ConflictError):
        return 409
    if isinstance(error, ResourceLimitError):
        return 413
    if isinstance(error, PolicyValidationError):
        return 422
    if isinstance(error, LedgerError):
        return 503
    return 400


def _policy_summary(
    policy: PolicyDocument,
    *,
    validation_state: str = "valid",
) -> dict[str, str]:
    return {
        "policy_id": policy.policy_id,
        "version": policy.version,
        "mode": policy.mode.value,
        "digest": policy.content_digest,
        "validation_state": validation_state,
    }


def _filter_items(
    items: list[dict[str, Any]],
    filters: dict[str, str | None],
) -> list[dict[str, Any]]:
    result = items
    for key, expected in filters.items():
        if expected is None:
            continue
        if key == "risk_category":
            result = [item for item in result if expected in item.get("risk_categories", [])]
        else:
            result = [item for item in result if str(item.get(key)) == expected]
    return result


def _hook_content(request: HookEvidenceRequest) -> tuple[SourceClass, str, str | None]:
    payload = request.payload
    if request.hook_event == "UserPromptSubmit":
        content = payload.get("prompt")
        if not isinstance(content, str) or not content:
            raise ConflictError("UserPromptSubmit evidence requires prompt text.")
        return SourceClass.USER_INPUT, content, "codex.user-prompt"
    if request.hook_event == "PostToolUse":
        tool_name = payload.get("tool_name")
        if not isinstance(tool_name, str) or not tool_name:
            raise ConflictError("PostToolUse evidence requires a tool name.")
        return (
            SourceClass.TOOL_OUTPUT,
            canonical_json(payload.get("tool_response")),
            tool_name,
        )
    if request.hook_event == "Stop":
        message = payload.get("last_assistant_message")
        if not isinstance(message, str) or not message:
            raise ConflictError("Stop evidence has no assistant message to evaluate.")
        return SourceClass.AGENT_OUTPUT, message, "codex.stop"
    trigger = payload.get("trigger", "unknown")
    return SourceClass.COMPACTION, f"Codex compaction trigger: {trigger}.", "codex.compaction"


def create_app(runtime: Runtime) -> FastAPI:
    evidence_worker = EvidenceQueueWorker(runtime.memory_service)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await evidence_worker.start()
        try:
            yield
        finally:
            await evidence_worker.stop()

    app = FastAPI(
        title="Verity Cordon Local IPC",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    app.add_middleware(LocalBoundaryMiddleware, settings=runtime.settings)

    @app.middleware("http")
    async def prevent_api_caching(
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        response = await call_next(request)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        return response

    auth = ControlRoomAuth(runtime.settings, runtime.capability)
    app.state.runtime = runtime
    app.state.auth = auth
    app.state.evidence_worker = evidence_worker

    @app.exception_handler(VerityError)
    async def verity_error_handler(_: Request, error: VerityError) -> JSONResponse:
        headers = (
            {"Retry-After": str(runtime.settings.ui_cooldown_seconds)}
            if isinstance(error, RateLimitError)
            else None
        )
        return JSONResponse(
            status_code=_error_status(error),
            content={"error": error.code, "message": str(error)},
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(_: Request, __: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": "validation_error",
                "message": "The request does not match the local API contract.",
            },
        )

    async def mutation_authorized(request: Request) -> None:
        await auth.authorize_mutation(request)

    mutation = Depends(mutation_authorized)

    @app.get("/api/v1/health")
    async def health() -> dict[str, str]:
        return {"schema_version": "1.0.0", "status": "alive"}

    @app.get("/api/v1/status")
    async def product_status() -> dict[str, Any]:
        policy = runtime.memory_service.policy_engine.policy
        statistics = await runtime.queries.statistics()
        statistics["counts"].update(await runtime.memory_service.evidence_queue_counts())
        verification = await runtime.event_store.verify()
        operational = runtime.event_store.healthy and verification.verified
        return {
            "schema_version": "1.0.0",
            "daemon": "healthy" if operational else "read_only",
            "mode": policy.mode.value,
            "policy": _policy_summary(
                policy,
                validation_state=runtime.policy_validation_state,
            ),
            "ledger": "verified" if operational else "invalid",
            "memory_view": ("consistent" if verification.materialized_view_consistent else "stale"),
            "semantic_provider": runtime.memory_service.semantic_adjudicator.provider_label,
            "counts": statistics["counts"],
        }

    @app.get("/api/v1/statistics")
    async def statistics() -> dict[str, Any]:
        summary = await runtime.queries.statistics()
        summary["counts"].update(await runtime.memory_service.evidence_queue_counts())
        return summary

    @app.post("/api/v1/ui/challenge")
    async def ui_challenge(request: Request) -> dict[str, object]:
        return await auth.create_challenge(request)

    @app.post("/api/v1/ui/session", status_code=status.HTTP_201_CREATED)
    async def ui_session(
        request: Request,
        response: Response,
        body: ControlRoomSessionRequest,
    ) -> dict[str, str]:
        session_token, payload = await auth.create_session(
            request,
            challenge_id=body.challenge_id,
            proof=body.proof,
        )
        response.set_cookie(
            COOKIE_NAME,
            session_token,
            httponly=True,
            samesite="strict",
            secure=False,
            path="/",
            max_age=runtime.settings.ui_session_idle_seconds,
        )
        return payload

    @app.post(
        "/api/v1/hooks/evidence",
        dependencies=[mutation],
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def hook_evidence(
        body: HookEvidenceRequest,
        idempotency_key: IdempotencyKey,
    ) -> dict[str, Any]:
        async def action() -> dict[str, Any]:
            source_class, content, source_name = _hook_content(body)
            evidence = await runtime.memory_service.enqueue_evidence(
                EvidenceSubmission(
                    session_id=body.session_id,
                    task_id=body.turn_id,
                    source_class=source_class,
                    source_name=source_name,
                    content=content,
                    metadata={"hook_event": body.hook_event},
                )
            )
            return {
                "schema_version": "1.0.0",
                "evidence_id": evidence.evidence_id,
                "status": "queued",
                "duplicate": False,
            }

        response = await runtime.idempotency.run(
            operation="hooks.evidence",
            key=idempotency_key,
            request_payload=body.model_dump(mode="json", exclude={"captured_at"}),
            action=action,
        )
        evidence_worker.notify()
        return response

    @app.post("/api/v1/hooks/session-start", dependencies=[mutation])
    async def session_start(body: SessionStartRequest) -> dict[str, Any]:
        context = await runtime.memory_service.session_start_context(
            session_id=body.session_id,
            token_budget=runtime.memory_service.policy_engine.policy.limits.injection_token_budget,
        )
        verification = await runtime.event_store.verify()
        operational = runtime.event_store.healthy and verification.verified
        memories = await runtime.memory_view.list_active() if context and operational else []
        return {
            "schema_version": "1.0.0",
            "injection_state": (
                "ready"
                if context and operational
                else "disabled_empty"
                if operational
                else "disabled_ledger"
            ),
            "additional_context": context if operational else None,
            "memory_ids": [memory.memory_id for memory in memories],
            "token_estimate": (len(context) + 3) // 4 if operational else 0,
            "ledger_verified": operational,
            "view_consistent": operational and verification.materialized_view_consistent,
            "warning_code": None if operational else "ledger_unverified",
        }

    @app.get("/api/v1/candidates")
    async def candidates(
        limit: int = Query(default=100, ge=1, le=500),
        status_filter: str | None = Query(default=None, alias="status"),
        kind: str | None = None,
        namespace: str | None = None,
        source_class: str | None = None,
        session_id: str | None = None,
        policy_version: str | None = None,
        risk_category: str | None = None,
        semantic_provider: str | None = None,
    ) -> dict[str, Any]:
        items = await runtime.queries.list_candidate_summaries()
        filtered = _filter_items(
            items,
            {
                "status": status_filter,
                "kind": kind,
                "namespace": namespace,
                "source_class": source_class,
                "session_id": session_id,
                "policy_version": policy_version,
                "risk_category": risk_category,
                "semantic_provider": semantic_provider,
            },
        )
        return {"items": filtered[:limit], "next_cursor": None}

    @app.get("/api/v1/candidates/{candidate_id}")
    async def candidate_detail(candidate_id: str) -> dict[str, Any]:
        return await runtime.queries.get_candidate_detail(candidate_id)

    @app.post("/api/v1/candidates/{candidate_id}/review", dependencies=[mutation])
    async def review_candidate(
        candidate_id: str,
        body: CandidateReviewRequest,
        idempotency_key: IdempotencyKey,
    ) -> dict[str, Any]:
        async def action() -> dict[str, Any]:
            if body.disposition == "leave_quarantined":
                target = next(
                    (
                        item
                        for item in await runtime.memory_view.list_quarantined()
                        if item.candidate_id == candidate_id
                    ),
                    None,
                )
                if target is None:
                    raise NotFoundError("The quarantined candidate was not found.")
                return {
                    "event_id": target.quarantine_event_id,
                    "candidate_id": candidate_id,
                    "memory_id": None,
                    "status": "quarantined",
                    "ledger_verified": True,
                    "view_consistent": True,
                }
            if body.disposition == "approve":
                record = await runtime.trust_actions.approve(
                    candidate_id,
                    actor_id=body.actor_id,
                    reason=body.reason,
                    confirmed=body.confirmed,
                )
                return {
                    "event_id": record.last_event_id,
                    "candidate_id": candidate_id,
                    "memory_id": record.memory_id,
                    "status": record.status,
                    "ledger_verified": True,
                    "view_consistent": True,
                }
            await runtime.trust_actions.block(
                candidate_id,
                actor_id=body.actor_id,
                reason=body.reason,
                confirmed=body.confirmed,
            )
            events = await runtime.event_store.list_events()
            return {
                "event_id": events[-1].event_id,
                "candidate_id": candidate_id,
                "memory_id": None,
                "status": "blocked",
                "ledger_verified": True,
                "view_consistent": True,
            }

        return await runtime.idempotency.run(
            operation=f"candidates.review:{candidate_id}",
            key=idempotency_key,
            request_payload=body.model_dump(mode="json"),
            action=action,
        )

    @app.get("/api/v1/memories")
    async def memories(
        limit: int = Query(default=100, ge=1, le=500),
        status_filter: str | None = Query(default=None, alias="status"),
        kind: str | None = None,
        namespace: str | None = None,
        source_class: str | None = None,
        session_id: str | None = None,
        policy_version: str | None = None,
        risk_category: str | None = None,
        semantic_provider: str | None = None,
    ) -> dict[str, Any]:
        items = [item.model_dump(mode="json") for item in await runtime.queries.list_memories()]
        filtered = _filter_items(
            items,
            {
                "status": status_filter,
                "kind": kind,
                "namespace": namespace,
                "source_class": source_class,
                "session_id": session_id,
                "policy_version": policy_version,
                "risk_category": risk_category,
                "semantic_provider": semantic_provider,
            },
        )
        return {
            "items": filtered[:limit],
            "next_cursor": None,
        }

    @app.get("/api/v1/memories/{memory_id}")
    async def memory_detail(memory_id: str) -> dict[str, Any]:
        return (await runtime.queries.get_memory(memory_id)).model_dump(mode="json")

    @app.post("/api/v1/memories/{memory_id}/revoke/preview", dependencies=[mutation])
    async def revoke_preview(memory_id: str) -> dict[str, Any]:
        preview = await runtime.trust_actions.preview_revocation(memory_id)
        return {
            "memory_id": memory_id,
            "current_status": "active",
            "would_remove_from_active_view": True,
            "unrelated_active_memories_preserved": preview["unrelated_preserved"],
            "resulting_active_count": preview["active_after"],
        }

    @app.post("/api/v1/memories/{memory_id}/revoke", dependencies=[mutation])
    async def revoke_memory(
        memory_id: str,
        body: OperatorActionRequest,
        idempotency_key: IdempotencyKey,
    ) -> dict[str, Any]:
        async def action() -> dict[str, Any]:
            record = await runtime.trust_actions.revoke(
                memory_id,
                actor_id=body.actor_id,
                reason=body.reason,
                confirmed=body.confirmed,
            )
            return {
                "event_id": record.last_event_id,
                "candidate_id": record.candidate_id,
                "memory_id": record.memory_id,
                "status": "revoked",
                "ledger_verified": True,
                "view_consistent": True,
            }

        return await runtime.idempotency.run(
            operation=f"memory.revoke:{memory_id}",
            key=idempotency_key,
            request_payload=body.model_dump(mode="json"),
            action=action,
        )

    @app.post("/api/v1/memory/rebuild", dependencies=[mutation])
    async def rebuild_memory(
        body: RebuildRequest,
        idempotency_key: IdempotencyKey,
    ) -> dict[str, Any]:
        async def action() -> dict[str, Any]:
            result = await runtime.memory_view.rebuild(dry_run=body.dry_run)
            return {
                "dry_run": body.dry_run,
                "events_replayed": len(await runtime.event_store.list_events()),
                "active_count": result["active_count"],
                "quarantined_count": result["quarantine_count"],
                "differences_found": 1 if result["changed"] else 0,
                "view_consistent": bool(result.get("verified_view", not result["changed"])),
                "ledger_verified": bool(result["verified_history"]),
            }

        return await runtime.idempotency.run(
            operation="memory.rebuild",
            key=idempotency_key,
            request_payload=body.model_dump(mode="json"),
            action=action,
        )

    @app.get("/api/v1/events")
    async def events(
        limit: int = Query(default=200, ge=1, le=1000),
        event_type: str | None = None,
        memory_id: str | None = None,
    ) -> dict[str, Any]:
        items = await runtime.queries.list_event_summaries()
        filtered = _filter_items(
            items,
            {"event_type": event_type, "memory_id": memory_id},
        )
        return {
            "items": filtered[:limit],
            "next_cursor": None,
        }

    @app.get("/api/v1/policies/active")
    async def active_policy() -> dict[str, Any]:
        policy = runtime.memory_service.policy_engine.policy
        return {
            "summary": _policy_summary(
                policy,
                validation_state=runtime.policy_validation_state,
            ),
            "policy": policy.model_dump(mode="json"),
        }

    @app.post("/api/v1/policies/validate", dependencies=[mutation])
    async def validate_policy(body: dict[str, Any]) -> dict[str, Any]:
        try:
            policy = PolicyDocument.model_validate(body)
        except ValidationError:
            return {
                "valid": False,
                "digest": None,
                "errors": [
                    {
                        "path": "$",
                        "code": "policy.invalid",
                        "message": "The policy does not match the required schema.",
                    }
                ],
            }
        return {"valid": True, "digest": policy.content_digest, "errors": []}

    @app.post("/api/v1/policies/activate", dependencies=[mutation])
    async def activate_policy(
        body: PolicyActivationRequest,
        idempotency_key: IdempotencyKey,
    ) -> dict[str, Any]:
        async def action() -> dict[str, Any]:
            policy = await runtime.policy_repository.activate_raw(
                body.policy,
                actor_id=body.actor_id,
                reason=body.reason,
            )
            runtime.replace_policy(policy)
            events = await runtime.event_store.list_events()
            return {
                "summary": _policy_summary(policy),
                "event_id": events[-1].event_id,
                "duplicate": False,
            }

        return await runtime.idempotency.run(
            operation="policies.activate",
            key=idempotency_key,
            request_payload=body.model_dump(mode="json"),
            action=action,
        )

    @app.post("/api/v1/ledger/verify", dependencies=[mutation])
    async def verify_ledger(body: LedgerVerifyRequest) -> dict[str, Any]:
        return (
            await runtime.event_store.verify(
                verify_view=body.verify_materialized_view,
            )
        ).model_dump(mode="json")

    @app.get("/api/v1/ledger/public-key")
    async def public_key() -> dict[str, str]:
        exported = await runtime.key_provider.export_public()
        return {
            "algorithm": exported["algorithm"],
            "signing_key_id": exported["key_id"],
            "public_key_base64": exported["public_key"],
            "fingerprint_sha256": exported["public_key_fingerprint"],
        }

    @app.post(
        "/api/v1/streams",
        dependencies=[mutation],
        status_code=status.HTTP_201_CREATED,
    )
    async def stream_begin(
        body: StreamBeginRequest,
        idempotency_key: IdempotencyKey,
    ) -> dict[str, Any]:
        async def action() -> dict[str, Any]:
            session = await runtime.streaming.begin_write(
                StreamMetadata(
                    session_id=body.session_id,
                    task_id=body.task_id,
                    source_class=body.source_class,
                    namespace_hint=body.namespace,
                )
            )
            return {
                "stream_id": session.stream_id,
                "state": "open",
                "chunks_received": 0,
                "bytes_received": 0,
                "active_memory_created": False,
            }

        return await runtime.idempotency.run(
            operation="streams.begin",
            key=idempotency_key,
            request_payload=body.model_dump(mode="json"),
            action=action,
        )

    @app.post("/api/v1/streams/{stream_id}/chunks", dependencies=[mutation])
    async def stream_append(
        stream_id: str,
        body: StreamAppendRequest,
        idempotency_key: IdempotencyKey,
    ) -> dict[str, Any]:
        async def action() -> dict[str, Any]:
            result = await runtime.streaming.append(
                stream_id,
                body.chunk,
                chunk_sequence=body.chunk_sequence,
            )
            return {
                "stream_id": stream_id,
                "state": result.state,
                "chunks_received": result.chunk_count,
                "bytes_received": result.buffer_bytes,
                "active_memory_created": False,
            }

        return await runtime.idempotency.run(
            operation=f"streams.append:{stream_id}",
            key=idempotency_key,
            request_payload=body.model_dump(mode="json"),
            action=action,
        )

    @app.post("/api/v1/streams/{stream_id}/commit", dependencies=[mutation])
    async def stream_commit(
        stream_id: str,
        body: StreamCommitRequest,
        idempotency_key: IdempotencyKey,
    ) -> dict[str, Any]:
        async def action() -> dict[str, Any]:
            result = await runtime.streaming.commit(
                stream_id,
                expected_chunk_count=body.expected_chunk_count,
            )
            return result.model_dump(mode="json")

        return await runtime.idempotency.run(
            operation=f"streams.commit:{stream_id}",
            key=idempotency_key,
            request_payload=body.model_dump(mode="json"),
            action=action,
        )

    @app.post("/api/v1/streams/{stream_id}/abort", dependencies=[mutation])
    async def stream_abort(
        stream_id: str,
        body: StreamAbortRequest,
        idempotency_key: IdempotencyKey,
    ) -> dict[str, Any]:
        async def action() -> dict[str, Any]:
            return (await runtime.streaming.abort(stream_id, body.reason)).model_dump(mode="json")

        return await runtime.idempotency.run(
            operation=f"streams.abort:{stream_id}",
            key=idempotency_key,
            request_payload=body.model_dump(mode="json"),
            action=action,
        )

    install_control_room(
        app,
        runtime.settings.control_room_dist or default_control_room_dist(),
    )
    return app
