"""Run the curated synthetic dataset through the real offline memory pipeline.

The report is intentionally fixture-scoped. It contains identifiers, aggregate
counts, decisions, categories, and timings, but never raw sample content.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from statistics import median
from time import perf_counter
from typing import Any, Literal

from pydantic import Field, model_validator

from verity_cordon.core.models import (
    Action,
    DetectorStatus,
    Mode,
    SourceClass,
    StrictModel,
    format_utc,
)
from verity_cordon.crypto.canonical import parse_json_strict, sha256_hex
from verity_cordon.crypto.keys import FileKeyProvider
from verity_cordon.detectors.builtin import SecretSanitizer, builtin_detectors
from verity_cordon.detectors.runner import DetectorRunner
from verity_cordon.ledger.store import SQLiteEventStore
from verity_cordon.memory.materializer import SQLiteMemoryView
from verity_cordon.memory.service import EvidenceSubmission, MemoryService
from verity_cordon.policies.engine import PolicyEngine
from verity_cordon.policies.load import load_builtin_policy
from verity_cordon.policies.repository import SQLitePolicyRepository
from verity_cordon.semantic.fixture import (
    FixtureCandidateExtractor,
    FixtureSemanticAdjudicator,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET_PATH = REPOSITORY_ROOT / "evals" / "datasets" / "memory-poisoning-fixtures-v1.json"
DEFAULT_RESULTS_DIR = REPOSITORY_ROOT / "evals" / "results"
MAX_DATASET_BYTES = 1_048_576
PROTECTION_ACTIONS = {Action.REDACT, Action.QUARANTINE, Action.BLOCK}


class DatasetLicense(StrictModel):
    spdx: Literal["Apache-2.0"]
    license_file: str = Field(min_length=1, max_length=256)
    applies_to: str = Field(min_length=1, max_length=256)


class DatasetSource(StrictModel):
    origin: Literal["original_synthetic"]
    creator: str = Field(min_length=1, max_length=128)
    created_at: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    external_material: Literal[False]
    real_secrets: Literal[False]


class EvaluationSample(StrictModel):
    sample_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,63}$")
    category: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    expected_label: Literal["benign", "risky"]
    source_class: SourceClass
    source_name: str = Field(min_length=1, max_length=128)
    content: str = Field(min_length=1, max_length=16_384)
    rationale: str = Field(min_length=1, max_length=512)
    sensitive_markers: list[str] = Field(default_factory=list, max_length=8)

    @model_validator(mode="after")
    def validate_secret_fixture(self) -> EvaluationSample:
        sanitizer = SecretSanitizer().sanitize(self.content)
        for marker in self.sensitive_markers:
            if len(marker) < 8 or marker not in self.content:
                raise ValueError("Sensitive fixture markers must be bounded content substrings.")
        if self.sensitive_markers and not sanitizer.contains_secrets:
            raise ValueError("A marked secret fixture must exercise the real sanitizer.")
        if self.sensitive_markers and self.expected_label != "risky":
            raise ValueError("A secret fixture must expect protection.")
        return self


class DatasetDocument(StrictModel):
    schema_version: Literal["1.0.0"]
    dataset_id: str = Field(pattern=r"^[a-z][a-z0-9-]{7,127}$")
    dataset_version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    title: str = Field(min_length=1, max_length=256)
    description: str = Field(min_length=1, max_length=1000)
    scope_notice: str = Field(min_length=1, max_length=1000)
    license_metadata: DatasetLicense = Field(alias="license")
    source_metadata: DatasetSource = Field(alias="source")
    samples: list[EvaluationSample] = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def validate_sample_identity(self) -> DatasetDocument:
        identifiers = [sample.sample_id for sample in self.samples]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("Dataset sample IDs must be unique.")
        return self


@dataclass(frozen=True, slots=True)
class EvaluationRun:
    report: dict[str, Any]
    markdown: str


def load_dataset(path: Path) -> tuple[DatasetDocument, str]:
    """Load a bounded, duplicate-key-safe dataset and return its SHA-256 digest."""

    raw = path.read_bytes()
    if len(raw) > MAX_DATASET_BYTES:
        raise ValueError("Evaluation dataset exceeds the 1 MiB boundary.")
    parsed = parse_json_strict(raw.decode("utf-8"))
    dataset = DatasetDocument.model_validate(parsed)
    return dataset, sha256_hex(raw)


async def _build_service(
    runtime_dir: Path,
) -> tuple[MemoryService, SQLiteEventStore]:
    key_provider = await asyncio.to_thread(_prepare_runtime, runtime_dir)
    store = SQLiteEventStore(
        runtime_dir / "verity.sqlite3",
        key_provider,
        runtime_dir / "ledger-head.json",
    )
    await store.initialize()
    policy = load_builtin_policy(Mode.ENFORCE)
    await SQLitePolicyRepository(store).ensure_initial(policy)
    detector_runner = DetectorRunner(
        builtin_detectors(max_candidate_bytes=policy.limits.max_candidate_bytes)
    )
    service = MemoryService(
        event_store=store,
        memory_view=SQLiteMemoryView(store),
        extractor=FixtureCandidateExtractor(),
        detector_runner=detector_runner,
        semantic_adjudicator=FixtureSemanticAdjudicator(),
        policy_engine=PolicyEngine(policy),
    )
    return service, store


def _prepare_runtime(runtime_dir: Path) -> FileKeyProvider:
    runtime_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    return FileKeyProvider.generate(runtime_dir / "signing-key.pem")


def _median_ms(values: Sequence[float | int]) -> float:
    return round(float(median(values)), 3) if values else 0.0


def _assert_markers_absent(markers: set[str], payload: str | bytes) -> None:
    for marker in markers:
        encoded = marker.encode("utf-8")
        if (isinstance(payload, str) and marker in payload) or (
            isinstance(payload, bytes) and encoded in payload
        ):
            raise RuntimeError("A synthetic secret marker reached a prohibited output surface.")


def _assert_report_has_no_secret_shape(payload: str) -> None:
    if SecretSanitizer().sanitize(payload).contains_secrets:
        raise RuntimeError("A secret-shaped value reached an evaluation report.")


def _assert_runtime_files_safe(runtime_dir: Path, markers: set[str]) -> None:
    for runtime_path in runtime_dir.rglob("*"):
        if runtime_path.is_file():
            _assert_markers_absent(markers, runtime_path.read_bytes())


def _classification(expected_label: str, observed_protected: bool) -> str:
    if expected_label == "risky":
        return "true_positive" if observed_protected else "false_negative"
    return "false_positive" if observed_protected else "true_negative"


def _render_markdown(report: dict[str, Any]) -> str:
    counts = report["counts"]
    latency = report["latency_ms"]
    rates = report["rates"]
    ledger = report["ledger"]
    lines = [
        "# Verity Cordon Fixture Evaluation",
        "",
        f"Generated: `{report['generated_at']}`",
        "",
        "> These results cover only the repository's original synthetic fixtures and the",
        "> deterministic recorded semantic provider. They are not universal accuracy,",
        "> production efficacy, or live-model performance claims.",
        "",
        "## Scope",
        "",
        f"- Dataset: `{report['dataset']['dataset_id']}` version `{report['dataset']['version']}`",
        f"- Dataset SHA-256: `{report['dataset']['sha256']}`",
        f"- License: `{report['dataset']['license']}`",
        (
            f"- Policy: `{report['runtime']['policy_id']}` version "
            f"`{report['runtime']['policy_version']}`"
        ),
        f"- Semantic provider: `{report['runtime']['semantic_provider']}`",
        "",
        "## Fixture counts",
        "",
        "| Measure | Count |",
        "|---|---:|",
        f"| Samples | {counts['samples_total']} |",
        f"| Benign samples | {counts['benign_samples']} |",
        f"| Risky samples | {counts['risky_samples']} |",
        f"| Allowed benign samples | {counts['allowed_benign_samples']} |",
        f"| Protected risky samples | {counts['protected_risky_samples']} |",
        f"| False positives | {counts['false_positive_count']} |",
        f"| False negatives | {counts['false_negative_count']} |",
        f"| Samples with no candidate | {counts['samples_with_no_candidate']} |",
        f"| Candidate decisions | {counts['candidate_decisions_total']} |",
        f"| Semantic assessments | {counts['semantic_assessments_total']} |",
        f"| Semantic timeouts | {counts['semantic_timeouts']} |",
        f"| Detector failures | {counts['detector_failures']} |",
        "",
        "## Observed latency",
        "",
        "| Measure | Milliseconds |",
        "|---|---:|",
        f"| Median end-to-end evaluation wall time | {latency['evaluation_wall_median']} |",
        f"| Median deterministic detector result | {latency['detector_result_median']} |",
        f"| Median fixture semantic assessment | {latency['semantic_assessment_median']} |",
        f"| Ledger verification | {latency['ledger_verification']} |",
        f"| Semantic timeout rate | {rates['semantic_timeout_rate']:.4f} |",
        "",
        "Timings are local observations from this run, not performance guarantees.",
        "",
        "## Ledger",
        "",
        f"- Verified: `{str(ledger['verified']).lower()}`",
        f"- Materialized view consistent: `{str(ledger['materialized_view_consistent']).lower()}`",
        f"- Events: `{ledger['total_events']}`",
        f"- Completeness: `{ledger['completeness_state']}`",
        "",
        "## Sample outcomes",
        "",
        "| Sample | Category | Expected | Observed | Classification | Candidates | Actions |",
        "|---|---|---|---|---|---:|---|",
    ]
    for sample in report["samples"]:
        actions = (
            ", ".join(f"{name}:{count}" for name, count in sorted(sample["action_counts"].items()))
            or "none"
        )
        lines.append(
            "| "
            f"`{sample['sample_id']}` | `{sample['category']}` | "
            f"`{sample['expected_label']}` | `{sample['observed_label']}` | "
            f"`{sample['classification']}` | {sample['candidate_count']} | {actions} |"
        )
    lines.append("")
    return "\n".join(lines)


async def _execute_dataset(
    dataset: DatasetDocument,
    dataset_digest: str,
    runtime_dir: Path,
) -> EvaluationRun:
    service, store = await _build_service(runtime_dir)
    policy = service.policy_engine.policy
    action_counts: Counter[str] = Counter()
    classification_counts: Counter[str] = Counter()
    semantic_provider_counts: Counter[str] = Counter()
    evaluation_latencies: list[float] = []
    detector_latencies: list[int] = []
    semantic_latencies: list[int] = []
    semantic_timeouts = 0
    detector_failures = 0
    candidate_decisions = 0
    sample_reports: list[dict[str, Any]] = []
    sensitive_markers = {
        marker for sample in dataset.samples for marker in sample.sensitive_markers
    }

    for index, sample in enumerate(dataset.samples, start=1):
        started = perf_counter()
        evaluation = await service.evaluate_evidence(
            EvidenceSubmission(
                session_id=f"eval-session-{index:04d}",
                task_id=f"eval-task-{index:04d}",
                source_class=sample.source_class,
                source_name=sample.source_name,
                content=sample.content,
                metadata={"fixture_sample_id": sample.sample_id},
            )
        )
        evaluation_latencies.append((perf_counter() - started) * 1000)
        candidate_decisions += len(evaluation.outcomes)
        sample_action_counts: Counter[str] = Counter()
        detector_categories: set[str] = set()
        semantic_categories: set[str] = set()

        for outcome in evaluation.outcomes:
            action = outcome.decision.actual_action.value
            action_counts[action] += 1
            sample_action_counts[action] += 1
            for detector_result in outcome.detector_results:
                detector_latencies.append(detector_result.latency_ms)
                if detector_result.status != DetectorStatus.OK:
                    detector_failures += 1
                if detector_result.matched is True:
                    detector_categories.update(detector_result.categories)
            assessment = outcome.semantic_assessment
            if assessment is None:
                semantic_provider_counts["not_required"] += 1
            else:
                semantic_provider_counts[assessment.provider_state.value] += 1
                semantic_latencies.append(assessment.latency_ms)
                semantic_categories.update(assessment.categories)
                if assessment.failure is not None and assessment.failure.class_name == "timeout":
                    semantic_timeouts += 1

        observed_protected = any(
            outcome.decision.actual_action in PROTECTION_ACTIONS for outcome in evaluation.outcomes
        )
        classification = _classification(sample.expected_label, observed_protected)
        classification_counts[classification] += 1
        sample_reports.append(
            {
                "sample_id": sample.sample_id,
                "category": sample.category,
                "expected_label": sample.expected_label,
                "observed_label": "protected" if observed_protected else "allowed",
                "classification": classification,
                "candidate_count": len(evaluation.outcomes),
                "action_counts": dict(sorted(sample_action_counts.items())),
                "detector_categories": sorted(detector_categories),
                "semantic_categories": sorted(semantic_categories),
            }
        )

    verification_started = perf_counter()
    verification = await store.verify()
    verification_latency = (perf_counter() - verification_started) * 1000
    events = await store.list_events()
    serialized_events = "\n".join(event.model_dump_json() for event in events)
    _assert_markers_absent(sensitive_markers, serialized_events)
    await asyncio.to_thread(_assert_runtime_files_safe, runtime_dir, sensitive_markers)

    semantic_assessments = sum(
        count for state, count in semantic_provider_counts.items() if state != "not_required"
    )
    report: dict[str, Any] = {
        "schema_version": "1.0.0",
        "report_type": "verity_fixture_evaluation",
        "generated_at": format_utc(),
        "claim_boundary": (
            "Counts describe only this original synthetic dataset and deterministic "
            "fixture provider; they are not universal accuracy, production efficacy, "
            "or live-model performance."
        ),
        "dataset": {
            "dataset_id": dataset.dataset_id,
            "version": dataset.dataset_version,
            "sha256": dataset_digest,
            "license": dataset.license_metadata.spdx,
            "source": dataset.source_metadata.origin,
            "sample_count": len(dataset.samples),
        },
        "runtime": {
            "policy_id": policy.policy_id,
            "policy_version": policy.version,
            "policy_mode": policy.mode.value,
            "detector_bundle_version": service.detector_runner.bundle_version,
            "semantic_provider": "recorded_fixture",
        },
        "counts": {
            "samples_total": len(dataset.samples),
            "benign_samples": sum(sample.expected_label == "benign" for sample in dataset.samples),
            "risky_samples": sum(sample.expected_label == "risky" for sample in dataset.samples),
            "allowed_benign_samples": sum(
                sample["classification"] == "true_negative" and sample["candidate_count"] > 0
                for sample in sample_reports
            ),
            "protected_risky_samples": classification_counts["true_positive"],
            "false_positive_count": classification_counts["false_positive"],
            "false_negative_count": classification_counts["false_negative"],
            "expected_match_count": (
                classification_counts["true_positive"] + classification_counts["true_negative"]
            ),
            "samples_with_no_candidate": sum(
                sample["candidate_count"] == 0 for sample in sample_reports
            ),
            "candidate_decisions_total": candidate_decisions,
            "candidate_action_counts": dict(sorted(action_counts.items())),
            "semantic_assessments_total": semantic_assessments,
            "semantic_provider_counts": dict(sorted(semantic_provider_counts.items())),
            "semantic_timeouts": semantic_timeouts,
            "detector_failures": detector_failures,
        },
        "latency_ms": {
            "evaluation_wall_median": _median_ms(evaluation_latencies),
            "detector_result_median": _median_ms(detector_latencies),
            "semantic_assessment_median": _median_ms(semantic_latencies),
            "ledger_verification": round(verification_latency, 3),
        },
        "rates": {
            "semantic_timeout_rate": (
                round(semantic_timeouts / semantic_assessments, 4) if semantic_assessments else 0.0
            ),
        },
        "ledger": {
            "verified": verification.verified,
            "materialized_view_consistent": verification.materialized_view_consistent,
            "total_events": verification.total_events,
            "completeness_state": verification.completeness_state,
            "first_invalid_event_id": verification.first_invalid_event_id,
        },
        "samples": sample_reports,
    }
    json_payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    markdown = _render_markdown(report)
    _assert_markers_absent(sensitive_markers, json_payload)
    _assert_markers_absent(sensitive_markers, markdown)
    _assert_report_has_no_secret_shape(json_payload)
    _assert_report_has_no_secret_shape(markdown)
    return EvaluationRun(report=report, markdown=markdown)


async def run_evaluation(
    dataset_path: Path = DEFAULT_DATASET_PATH,
    *,
    runtime_dir: Path | None = None,
) -> EvaluationRun:
    """Evaluate the dataset with real ledger, detector, policy, and fixture components."""

    dataset, dataset_digest = await asyncio.to_thread(load_dataset, dataset_path)
    if runtime_dir is not None:
        return await _execute_dataset(dataset, dataset_digest, runtime_dir)
    with tempfile.TemporaryDirectory(prefix="verity-fixture-eval-") as temporary:
        return await _execute_dataset(dataset, dataset_digest, Path(temporary) / "runtime")


def _atomic_write(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def write_results(run: EvaluationRun, output_dir: Path) -> tuple[Path, Path]:
    json_payload = json.dumps(run.report, indent=2, sort_keys=True) + "\n"
    _assert_report_has_no_secret_shape(json_payload)
    _assert_report_has_no_secret_shape(run.markdown)
    json_path = output_dir / "latest.json"
    markdown_path = output_dir / "latest.md"
    _atomic_write(json_path, json_payload)
    _atomic_write(markdown_path, run.markdown)
    return json_path, markdown_path


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the synthetic offline Verity Cordon fixture evaluation."
    )
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_PATH)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_RESULTS_DIR)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Run the evaluation gates without rewriting committed result artifacts.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        run = asyncio.run(run_evaluation(args.dataset))
        counts = run.report["counts"]
        ledger = run.report["ledger"]
        if args.check and (
            counts["false_positive_count"]
            or counts["false_negative_count"]
            or not ledger["verified"]
            or not ledger["materialized_view_consistent"]
        ):
            raise RuntimeError("Fixture evaluation gates did not pass.")
        results = None if args.check else write_results(run, args.output_dir)
    except Exception as exc:
        print(f"Fixture evaluation failed safely ({type(exc).__name__}).", file=sys.stderr)
        return 1

    print(
        "Fixture evaluation complete: "
        f"samples={counts['samples_total']} "
        f"false_positives={counts['false_positive_count']} "
        f"false_negatives={counts['false_negative_count']}"
    )
    if results is not None:
        json_path, markdown_path = results
        print(f"JSON report: {json_path}")
        print(f"Markdown report: {markdown_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
