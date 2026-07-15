from __future__ import annotations

import json

import pytest
from evals.runners.run_fixture_evaluation import (
    DEFAULT_DATASET_PATH,
    load_dataset,
    run_evaluation,
    write_results,
)

from verity_cordon.detectors.builtin import SecretSanitizer


def test_dataset_is_original_licensed_synthetic_and_covers_required_classes() -> None:
    dataset, digest = load_dataset(DEFAULT_DATASET_PATH)

    assert len(digest) == 64
    assert dataset.license_metadata.spdx == "Apache-2.0"
    assert dataset.source_metadata.origin == "original_synthetic"
    assert dataset.source_metadata.external_material is False
    assert dataset.source_metadata.real_secrets is False
    assert {
        "benign",
        "obvious_attack",
        "indirect_attack",
        "persistence_attack",
        "tool_output_attack",
        "cross_task_attack",
        "false_positive_trap",
        "secret_handling",
    }.issubset({sample.category for sample in dataset.samples})


@pytest.mark.asyncio
async def test_runner_uses_real_pipeline_and_returns_content_free_fixture_metrics(
    tmp_path,
) -> None:
    dataset, _ = load_dataset(DEFAULT_DATASET_PATH)
    run = await run_evaluation(
        DEFAULT_DATASET_PATH,
        runtime_dir=tmp_path / "runtime",
    )
    serialized = json.dumps(run.report, sort_keys=True)

    assert run.report["dataset"]["sample_count"] == len(dataset.samples)
    assert run.report["runtime"]["policy_mode"] == "enforce"
    assert run.report["runtime"]["semantic_provider"] == "recorded_fixture"
    assert run.report["ledger"]["verified"] is True
    assert run.report["ledger"]["materialized_view_consistent"] is True
    assert run.report["counts"]["samples_total"] == len(dataset.samples)
    assert run.report["counts"]["expected_match_count"] + run.report["counts"][
        "false_positive_count"
    ] + run.report["counts"]["false_negative_count"] == len(dataset.samples)
    assert "not universal accuracy" in run.report["claim_boundary"]
    assert all(sample.content not in serialized for sample in dataset.samples)
    for sample in dataset.samples:
        for marker in sample.sensitive_markers:
            assert marker not in serialized
            assert marker not in run.markdown
    assert SecretSanitizer().sanitize(serialized).contains_secrets is False


@pytest.mark.asyncio
async def test_written_reports_are_safe_and_explicitly_fixture_scoped(tmp_path) -> None:
    dataset, _ = load_dataset(DEFAULT_DATASET_PATH)
    run = await run_evaluation(
        DEFAULT_DATASET_PATH,
        runtime_dir=tmp_path / "runtime",
    )
    json_path, markdown_path = write_results(run, tmp_path / "results")
    json_payload = json_path.read_text(encoding="utf-8")
    markdown_payload = markdown_path.read_text(encoding="utf-8")

    assert json.loads(json_payload)["report_type"] == "verity_fixture_evaluation"
    assert "not universal accuracy" in markdown_payload
    for sample in dataset.samples:
        for marker in sample.sensitive_markers:
            assert marker not in json_payload
            assert marker not in markdown_payload
