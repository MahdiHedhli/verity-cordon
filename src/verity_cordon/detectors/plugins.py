"""Explicitly enabled Python entry-point detector discovery."""

from __future__ import annotations

import inspect
import re
from collections.abc import Callable, Iterable, Sequence
from importlib import metadata
from typing import Any, cast

from verity_cordon.core.errors import ConfigurationError
from verity_cordon.core.protocols import Detector

ENTRY_POINT_GROUP = "verity_cordon.detectors"
_DETECTOR_ID = re.compile(r"^[a-z][a-z0-9_.-]{2,63}$")
_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$")


def _instantiate(entry_point: metadata.EntryPoint) -> Detector:
    try:
        loaded: Any = entry_point.load()
        candidate = loaded if hasattr(loaded, "inspect") else loaded()
    except Exception as exc:
        raise ConfigurationError(
            f"Enabled detector plugin '{entry_point.name}' could not be loaded."
        ) from exc
    detector_id = getattr(candidate, "detector_id", None)
    detector_version = getattr(candidate, "detector_version", None)
    inspect_method = getattr(candidate, "inspect", None)
    if (
        not isinstance(detector_id, str)
        or _DETECTOR_ID.fullmatch(detector_id) is None
        or not isinstance(detector_version, str)
        or _VERSION.fullmatch(detector_version) is None
        or not callable(inspect_method)
        or not inspect.iscoroutinefunction(inspect_method)
    ):
        raise ConfigurationError(
            f"Enabled detector plugin '{entry_point.name}' does not satisfy the async contract."
        )
    return cast(Detector, candidate)


def discover_detectors(
    enabled_names: Sequence[str],
    *,
    entry_points_provider: Callable[[], Iterable[metadata.EntryPoint]] | None = None,
) -> list[Detector]:
    """Load only operator-enabled detectors in deterministic name order."""

    if not enabled_names:
        return []
    if len(enabled_names) != len(set(enabled_names)):
        raise ConfigurationError("Enabled detector plugin names must be unique.")
    provider = entry_points_provider or metadata.entry_points
    available = {point.name: point for point in provider() if point.group == ENTRY_POINT_GROUP}
    missing = sorted(set(enabled_names).difference(available))
    if missing:
        raise ConfigurationError(
            "An enabled detector plugin is not installed: " + ", ".join(missing)
        )
    detectors = [_instantiate(available[name]) for name in sorted(enabled_names)]
    identifiers = [detector.detector_id for detector in detectors]
    if len(identifiers) != len(set(identifiers)):
        raise ConfigurationError("Enabled detector plugins expose duplicate detector IDs.")
    return detectors
