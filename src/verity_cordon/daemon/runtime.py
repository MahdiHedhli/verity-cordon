"""Composition root for the local daemon, CLI, and deterministic demos."""

from __future__ import annotations

from dataclasses import dataclass

from verity_cordon.core.config import Settings, load_or_create_capability
from verity_cordon.core.errors import KeyHealthError
from verity_cordon.core.models import Mode
from verity_cordon.crypto.keys import FileKeyProvider
from verity_cordon.detectors.builtin import builtin_detectors
from verity_cordon.detectors.runner import DetectorRunner
from verity_cordon.ledger.queries import LedgerQueries
from verity_cordon.ledger.store import SQLiteEventStore
from verity_cordon.memory.materializer import SQLiteMemoryView
from verity_cordon.memory.service import MemoryService
from verity_cordon.memory.trust_actions import TrustActions
from verity_cordon.policies.engine import PolicyEngine
from verity_cordon.policies.load import load_builtin_policy, load_policy
from verity_cordon.policies.models import PolicyDocument
from verity_cordon.policies.repository import SQLitePolicyRepository
from verity_cordon.semantic.factory import build_semantic_components
from verity_cordon.streaming.service import StreamingMemoryService


@dataclass(slots=True)
class Runtime:
    settings: Settings
    key_provider: FileKeyProvider
    event_store: SQLiteEventStore
    memory_view: SQLiteMemoryView
    memory_service: MemoryService
    trust_actions: TrustActions
    policy_repository: SQLitePolicyRepository
    queries: LedgerQueries
    streaming: StreamingMemoryService
    capability: str

    def replace_policy(self, policy: PolicyDocument) -> None:
        self.memory_service.policy_engine = PolicyEngine(policy)
        self.memory_service.semantic_timeout_ms = policy.limits.semantic_timeout_ms


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
    configured_policy = (
        load_policy(selected.policy_path)
        if selected.policy_path is not None
        else load_builtin_policy(mode=Mode.ENFORCE)
    )
    active_policy = await policy_repository.ensure_initial(configured_policy)
    extractor, adjudicator = build_semantic_components(
        provider=selected.semantic_provider,
        model=selected.openai_model,
    )
    view = SQLiteMemoryView(store)
    memory_service = MemoryService(
        event_store=store,
        memory_view=view,
        extractor=extractor,
        detector_runner=DetectorRunner(
            builtin_detectors(max_candidate_bytes=active_policy.limits.max_candidate_bytes)
        ),
        semantic_adjudicator=adjudicator,
        policy_engine=PolicyEngine(active_policy),
    )
    capability = load_or_create_capability(selected.capability_path)
    runtime = Runtime(
        settings=selected,
        key_provider=key_provider,
        event_store=store,
        memory_view=view,
        memory_service=memory_service,
        trust_actions=TrustActions(store, view),
        policy_repository=policy_repository,
        queries=LedgerQueries(store),
        streaming=StreamingMemoryService(
            store=store,
            memory_service=memory_service,
            max_stream_bytes=active_policy.limits.max_stream_bytes,
            max_stream_chunks=active_policy.limits.max_stream_chunks,
        ),
        capability=capability,
    )
    return runtime
