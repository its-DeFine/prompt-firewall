from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .core import EvaluationResult, Fixture


DEFAULT_MANIFEST = Path(__file__).resolve().parents[2] / "benchmarks" / "provenance" / "benchmark-sources.json"
DEFAULT_SAFEGUARD_TARGETS = (
    Path(__file__).resolve().parents[2] / "benchmarks" / "provenance" / "safeguard-targets.json"
)


@dataclass(frozen=True)
class BenchmarkFamily:
    name: str
    source_kind: str
    status: str
    claim_weight: str
    source_url: str
    license: str
    notes: str

    @property
    def is_external_import(self) -> bool:
        return self.source_kind == "external_import" and self.status in {
            "implemented",
            "executable_fixture_subset_implemented",
            "content_fixture_subset_implemented",
        }


@dataclass(frozen=True)
class ProvenanceSummary:
    total_fixtures: int
    local_synthetic: int
    synthetic_compatibility: int
    external_import: int
    unknown: int
    families: tuple[str, ...]


@dataclass(frozen=True)
class ClaimGateDecision:
    allowed: bool
    reason: str
    external_fixture_count: int
    external_family_count: int
    compared_safeguard_count: int
    deployed_safeguard_count: int
    research_safeguard_count: int
    missing_requirements: tuple[str, ...]


@dataclass(frozen=True)
class SafeguardTarget:
    id: str
    name: str
    source_kind: str
    source_url: str
    status: str
    comparison_role: str
    adapter_status: str
    evaluation_requirements: tuple[str, ...]
    notes: str

    @property
    def is_deployed(self) -> bool:
        return self.source_kind in {"deployed_cloud_guardrail", "deployed_api_guardrail"}

    @property
    def is_research(self) -> bool:
        return self.source_kind == "research_defense"


def load_manifest(path: Path | str = DEFAULT_MANIFEST) -> dict:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def benchmark_families(path: Path | str = DEFAULT_MANIFEST) -> dict[str, BenchmarkFamily]:
    manifest = load_manifest(path)
    return {
        name: BenchmarkFamily(name=name, **payload)
        for name, payload in manifest["benchmark_families"].items()
    }


def safeguard_targets(path: Path | str = DEFAULT_SAFEGUARD_TARGETS) -> dict[str, SafeguardTarget]:
    with open(path, encoding="utf-8") as handle:
        manifest = json.load(handle)
    return {
        payload["id"]: SafeguardTarget(
            id=payload["id"],
            name=payload["name"],
            source_kind=payload["source_kind"],
            source_url=payload["source_url"],
            status=payload["status"],
            comparison_role=payload["comparison_role"],
            adapter_status=payload["adapter_status"],
            evaluation_requirements=tuple(payload["evaluation_requirements"]),
            notes=payload["notes"],
        )
        for payload in manifest["targets"]
    }


def fixture_source_kind(fixture: Fixture, families: dict[str, BenchmarkFamily] | None = None) -> str:
    selected_families = families or benchmark_families()
    family = selected_families.get(fixture.benchmark)
    if family is None:
        return "unknown"
    return family.source_kind


def summarize_fixture_provenance(
    fixtures: list[Fixture],
    families: dict[str, BenchmarkFamily] | None = None,
) -> ProvenanceSummary:
    selected_families = families or benchmark_families()
    counts = {
        "local_synthetic": 0,
        "synthetic_compatibility": 0,
        "external_import": 0,
        "unknown": 0,
    }
    seen_families: set[str] = set()
    for fixture in fixtures:
        seen_families.add(fixture.benchmark)
        kind = fixture_source_kind(fixture, selected_families)
        counts[kind if kind in counts else "unknown"] += 1
    return ProvenanceSummary(
        total_fixtures=len(fixtures),
        local_synthetic=counts["local_synthetic"],
        synthetic_compatibility=counts["synthetic_compatibility"],
        external_import=counts["external_import"],
        unknown=counts["unknown"],
        families=tuple(sorted(seen_families)),
    )


def external_evidence_from_results(
    results: list[EvaluationResult],
    families: dict[str, BenchmarkFamily] | None = None,
) -> tuple[int, int]:
    selected_families = families or benchmark_families()
    external_fixture_ids: set[str] = set()
    external_families: set[str] = set()
    for result in results:
        family_name = result.fixture_id.split(":", 1)[0]
        # EvaluationResult intentionally stores fixture_id only. Prefer explicit
        # benchmark prefixes when imported benchmark rows land.
        for name, family in selected_families.items():
            if result.fixture_id.startswith(name) and family.is_external_import:
                external_fixture_ids.add(result.fixture_id)
                external_families.add(name)
        if family_name in selected_families and selected_families[family_name].is_external_import:
            external_fixture_ids.add(result.fixture_id)
            external_families.add(family_name)
    return len(external_fixture_ids), len(external_families)


def superiority_claim_gate(
    fixtures: list[Fixture],
    raw_model_runs: bool = False,
    repeated_attempts: bool = False,
    utility_measure: bool = False,
    failure_report: bool = False,
    compared_safeguards: tuple[str, ...] = (),
    manifest_path: Path | str = DEFAULT_MANIFEST,
    safeguard_targets_path: Path | str = DEFAULT_SAFEGUARD_TARGETS,
) -> ClaimGateDecision:
    manifest = load_manifest(manifest_path)
    families = benchmark_families(manifest_path)
    targets = safeguard_targets(safeguard_targets_path)
    rules = manifest["claim_rules"]["superiority_claim"]

    external_fixture_count = 0
    external_family_names: set[str] = set()
    for fixture in fixtures:
        family = families.get(fixture.benchmark)
        if family and family.is_external_import:
            external_fixture_count += 1
            external_family_names.add(fixture.benchmark)

    compared = tuple(dict.fromkeys(compared_safeguards))
    deployed_safeguards = {
        target_id for target_id in compared if target_id in targets and targets[target_id].is_deployed
    }
    research_safeguards = {
        target_id for target_id in compared if target_id in targets and targets[target_id].is_research
    }

    missing: list[str] = []
    if external_fixture_count < rules["minimum_external_fixtures"]:
        missing.append(f"minimum_external_fixtures={rules['minimum_external_fixtures']}")
    if len(external_family_names) < rules["minimum_external_families"]:
        missing.append(f"minimum_external_families={rules['minimum_external_families']}")
    if len(compared) < rules["minimum_compared_safeguards"]:
        missing.append(f"minimum_compared_safeguards={rules['minimum_compared_safeguards']}")
    if len(deployed_safeguards) < rules["minimum_deployed_safeguards"]:
        missing.append(f"minimum_deployed_safeguards={rules['minimum_deployed_safeguards']}")
    if len(research_safeguards) < rules["minimum_research_safeguards"]:
        missing.append(f"minimum_research_safeguards={rules['minimum_research_safeguards']}")
    if rules["requires_raw_model_runs"] and not raw_model_runs:
        missing.append("raw_model_runs")
    if rules["requires_repeated_attempts"] and not repeated_attempts:
        missing.append("repeated_attempts")
    if rules["requires_utility_measure"] and not utility_measure:
        missing.append("utility_measure")
    if rules["requires_failure_report"] and not failure_report:
        missing.append("failure_report")

    if missing:
        return ClaimGateDecision(
            allowed=False,
            reason="superiority claim blocked: proof requirements are not met",
            external_fixture_count=external_fixture_count,
            external_family_count=len(external_family_names),
            compared_safeguard_count=len(compared),
            deployed_safeguard_count=len(deployed_safeguards),
            research_safeguard_count=len(research_safeguards),
            missing_requirements=tuple(missing),
        )

    return ClaimGateDecision(
        allowed=True,
        reason="superiority claim allowed by configured proof requirements",
        external_fixture_count=external_fixture_count,
        external_family_count=len(external_family_names),
        compared_safeguard_count=len(compared),
        deployed_safeguard_count=len(deployed_safeguards),
        research_safeguard_count=len(research_safeguards),
        missing_requirements=(),
    )
