"""Explicit semantic-provider selection without live-to-fixture fallback."""

from __future__ import annotations

import os
from importlib import import_module
from typing import Any

from verity_cordon.core.errors import ConfigurationError
from verity_cordon.semantic.fixture import (
    FixtureCandidateExtractor,
    FixtureSemanticAdjudicator,
)


def build_semantic_components(
    *,
    provider: str,
    model: str,
    codex_runner: Any | None = None,
) -> tuple[Any, Any]:
    if provider == "fixture":
        return FixtureCandidateExtractor(), FixtureSemanticAdjudicator()
    if provider == "openai":
        if not os.getenv("OPENAI_API_KEY"):
            raise ConfigurationError("OPENAI_API_KEY is required for explicit live mode.")
        try:
            live_module = import_module("verity_cordon.semantic.openai_provider")
        except ModuleNotFoundError as exc:
            raise ConfigurationError("The live semantic provider is unavailable.") from exc
        extractor_type = live_module.OpenAICandidateExtractor
        adjudicator_type = live_module.OpenAISemanticAdjudicator
        return extractor_type(model=model), adjudicator_type(model=model)
    if provider == "codex_subscription":
        if codex_runner is None:
            raise ConfigurationError(
                "The explicit Codex subscription provider requires a verified runner."
            )
        try:
            subscription_module = import_module("verity_cordon.semantic.codex_subscription")
        except ModuleNotFoundError as exc:
            raise ConfigurationError(
                "The Codex subscription semantic provider is unavailable."
            ) from exc
        return (
            subscription_module.CodexSubscriptionCandidateExtractor(runner=codex_runner),
            subscription_module.CodexSubscriptionSemanticAdjudicator(runner=codex_runner),
        )
    raise ConfigurationError(
        "VERITY_SEMANTIC_PROVIDER must be 'fixture', 'openai', or 'codex_subscription'."
    )
