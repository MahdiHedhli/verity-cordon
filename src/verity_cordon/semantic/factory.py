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


def build_semantic_components(*, provider: str, model: str) -> tuple[Any, Any]:
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
    raise ConfigurationError("VERITY_SEMANTIC_PROVIDER must be 'fixture' or 'openai'.")
