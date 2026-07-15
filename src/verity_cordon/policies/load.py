"""Strict local YAML/JSON policy loading."""

from __future__ import annotations

import json
from datetime import date, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from verity_cordon.core.errors import PolicyValidationError
from verity_cordon.core.models import Mode
from verity_cordon.crypto.canonical import parse_json_strict
from verity_cordon.policies.models import PolicyDocument


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "duplicate policy key is prohibited",
                key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def load_policy_text(content: str, *, format_hint: str = "yaml") -> PolicyDocument:
    try:
        raw: Any
        if format_hint.casefold() == "json":
            raw = parse_json_strict(content)
        else:
            # This loader subclasses SafeLoader and only replaces mapping construction.
            raw = yaml.load(content, Loader=_UniqueKeyLoader)  # noqa: S506
        if not isinstance(raw, dict):
            raise ValueError("Policy document must be an object")
        # Round-trip JSON boundaries prevent YAML-only tagged or non-JSON values.
        raw = parse_json_strict(
            json.dumps(
                raw,
                allow_nan=False,
                default=lambda value: (
                    value.isoformat()
                    if isinstance(value, (date, datetime))
                    else TypeError("Non-JSON policy value")
                ),
            )
        )
        return PolicyDocument.model_validate(raw)
    except (ValueError, TypeError, yaml.YAMLError, ValidationError) as exc:
        raise PolicyValidationError("The policy document is invalid.") from exc


def load_policy(path: Path) -> PolicyDocument:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyValidationError("The policy document cannot be read.") from exc
    return load_policy_text(
        content,
        format_hint="json" if path.suffix.casefold() == ".json" else "yaml",
    )


def load_builtin_policy(mode: Mode) -> PolicyDocument:
    filename = "default-shadow.yaml" if mode == Mode.SHADOW else "default-enforce.yaml"
    content = files("verity_cordon.policies").joinpath(filename).read_text(encoding="utf-8")
    return load_policy_text(content)
