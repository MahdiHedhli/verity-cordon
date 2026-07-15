"""Composition root for the local daemon, CLI, and deterministic demos."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from verity_cordon.core.config import Settings, load_or_create_capability
from verity_cordon.core.errors import (
    ConfigurationError,
    KeyHealthError,
    LedgerIntegrityError,
    PolicyValidationError,
)
from verity_cordon.core.models import Mode
from verity_cordon.crypto.keys import FileKeyProvider
from verity_cordon.daemon.idempotency import IdempotencyStore
from verity_cordon.detectors.builtin import builtin_detectors
from verity_cordon.detectors.plugins import discover_detectors
from verity_cordon.detectors.runner import DetectorRunner
from verity_cordon.ledger.queries import LedgerQueries
from verity_cordon.ledger.store import SQLiteEventStore
from verity_cordon.memory.materializer import SQLiteMemoryView
from verity_cordon.memory.rescan import RetroactiveRescanService
from verity_cordon.memory.service import MemoryService
from verity_cordon.memory.trust_actions import TrustActions
from verity_cordon.policies.engine import PolicyEngine
from verity_cordon.policies.load import load_builtin_policy, load_policy
from verity_cordon.policies.models import PolicyDocument
from verity_cordon.policies.repository import SQLitePolicyRepository
from verity_cordon.semantic.factory import build_semantic_components
from verity_cordon.streaming.service import StreamingMemoryService
from verity_cordon.telemetry.instrumentation import Statistics


@dataclass(slots=True)
class Runtime:
    settings: Settings
    key_provider: FileKeyProvider
    event_store: SQLiteEventStore
    memory_view: SQLiteMemoryView
    memory_service: MemoryService
    rescan: RetroactiveRescanService
    trust_actions: TrustActions
    policy_repository: SQLitePolicyRepository
    queries: LedgerQueries
    streaming: StreamingMemoryService
    statistics: Statistics
    idempotency: IdempotencyStore
    capability: str
    policy_validation_state: Literal["valid", "invalid"]
    subscription_runner: Any | None

    def replace_policy(self, policy: PolicyDocument) -> None:
        self.memory_service.policy_engine = PolicyEngine(policy)
        self.memory_service.semantic_timeout_ms = policy.limits.semantic_timeout_ms
        self.memory_service.detector_runner = DetectorRunner(
            [
                *builtin_detectors(max_candidate_bytes=policy.limits.max_candidate_bytes),
                *discover_detectors(self.settings.detector_plugins),
            ]
        )
        self.streaming.max_stream_bytes = policy.limits.max_stream_bytes
        self.streaming.max_stream_chunks = policy.limits.max_stream_chunks
        self.policy_validation_state = "valid"


async def build_runtime(settings: Settings | None = None) -> Runtime:
    selected = settings or Settings.from_env()
    selected.prepare()
    if not selected.key_path.exists():
        raise KeyHealthError(
            "No installation signing key exists. Run 'verity ledger init-key' explicitly."
        )
    key_provider = FileKeyProvider.load(selected.key_path)
    store = SQLiteEventStore(selected.database_path, key_provider, selected.head_path)
    await store.initialize()
    policy_repository = SQLitePolicyRepository(store)
    policy_configuration_invalid = False
    try:
        configured_policy = (
            load_policy(selected.policy_path)
            if selected.policy_path is not None
            else load_builtin_policy(mode=Mode.ENFORCE)
        )
    except PolicyValidationError:
        configured_policy = load_builtin_policy(mode=Mode.ENFORCE)
        policy_configuration_invalid = True

    initial_verification = await store.verify()
    policy_validation_state: Literal["valid", "invalid"] = "invalid"
    active_policy = configured_policy
    if initial_verification.verified and not policy_configuration_invalid:
        try:
            active_policy = await policy_repository.ensure_initial(configured_policy)
        except LedgerIntegrityError:
            store._mark_unhealthy("active_policy_unverified")
        else:
            policy_validation_state = "valid"
    elif policy_configuration_invalid:
        store._mark_unhealthy("policy_configuration_invalid")

    subscription_runner: Any | None = None
    semantic_model = selected.openai_model
    if selected.semantic_provider == "codex_subscription":
        from verity_cordon.semantic.codex_subscription import CodexSubscriptionRunner

        home_raw = os.environ.get("HOME")
        if not home_raw:
            raise ConfigurationError(
                "HOME is required for the explicit Codex subscription provider."
            )
        home = Path(home_raw)
        codex_home_raw = os.environ.get("CODEX_HOME")
        subscription_runner = CodexSubscriptionRunner(
            executable=selected.codex_executable,
            model=selected.codex_model,
            home=home,
            codex_home=Path(codex_home_raw) if codex_home_raw else None,
            semantic_timeout_seconds=selected.codex_semantic_timeout_seconds,
            auth_timeout_seconds=selected.codex_auth_timeout_seconds,
            max_input_bytes=selected.codex_max_input_bytes,
            max_jsonl_bytes=selected.codex_max_jsonl_bytes,
            max_stderr_bytes=selected.codex_max_stderr_bytes,
            max_final_bytes=selected.codex_max_final_bytes,
            termination_grace_seconds=selected.codex_termination_grace_seconds,
        )
        semantic_model = selected.codex_model
    extractor, adjudicator = build_semantic_components(
        provider=selected.semantic_provider,
        model=semantic_model,
        codex_runner=subscription_runner,
    )
    view = SQLiteMemoryView(store)
    statistics = Statistics()
    memory_service = MemoryService(
        event_store=store,
        memory_view=view,
        extractor=extractor,
        detector_runner=DetectorRunner(
            [
                *builtin_detectors(max_candidate_bytes=active_policy.limits.max_candidate_bytes),
                *(
                    discover_detectors(selected.detector_plugins)
                    if policy_validation_state == "valid"
                    else []
                ),
            ]
        ),
        semantic_adjudicator=adjudicator,
        policy_engine=PolicyEngine(active_policy),
        statistics=statistics,
        pending_evidence_max_items=selected.pending_evidence_max_items,
        pending_evidence_max_bytes=selected.pending_evidence_max_bytes,
        pending_evidence_max_attempts=selected.pending_evidence_max_attempts,
        pending_evidence_max_age_seconds=selected.pending_evidence_max_age_seconds,
    )
    await memory_service.verify_pending_evidence_integrity()
    capability = load_or_create_capability(selected.capability_path)
    runtime = Runtime(
        settings=selected,
        key_provider=key_provider,
        event_store=store,
        memory_view=view,
        memory_service=memory_service,
        rescan=RetroactiveRescanService(memory_service),
        trust_actions=TrustActions(store, view),
        policy_repository=policy_repository,
        queries=LedgerQueries(store, statistics),
        streaming=StreamingMemoryService(
            store=store,
            memory_service=memory_service,
            max_stream_bytes=active_policy.limits.max_stream_bytes,
            max_stream_chunks=active_policy.limits.max_stream_chunks,
        ),
        statistics=statistics,
        idempotency=IdempotencyStore(store),
        capability=capability,
        policy_validation_state=policy_validation_state,
        subscription_runner=subscription_runner,
    )
    return runtime
