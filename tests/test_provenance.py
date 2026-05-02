from prompt_firewall.fixtures import fixtures
from prompt_firewall.provenance import (
    benchmark_families,
    summarize_fixture_provenance,
    superiority_claim_gate,
)


def test_fixture_provenance_is_explicit():
    summary = summarize_fixture_provenance(fixtures())

    assert summary.total_fixtures == 103
    assert summary.local_synthetic == 12
    assert summary.synthetic_compatibility == 9
    assert summary.external_import == 82
    assert summary.unknown == 0
    assert summary.families == (
        "agentdojo_external",
        "agentdojo_style",
        "prompt_firewall",
        "tensor_trust_external",
        "tensor_trust_style",
    )


def test_external_benchmark_targets_are_manifested_but_not_claim_ready():
    families = benchmark_families()

    assert families["agentdojo_external"].source_kind == "external_import"
    assert families["agentdojo_external"].status == "executable_fixture_subset_implemented"
    assert families["tensor_trust_external"].status == "content_fixture_subset_implemented"
    assert families["tensor_trust_external"].license == "BSD-2-Clause"
    assert families["agentdyn_external"].license == "MIT"


def test_superiority_claim_is_blocked_without_run_evidence():
    decision = superiority_claim_gate(
        fixtures(),
        raw_model_runs=False,
        repeated_attempts=False,
        utility_measure=False,
        failure_report=False,
    )

    assert not decision.allowed
    assert decision.external_fixture_count == 82
    assert "minimum_external_fixtures=30" not in decision.missing_requirements
    assert "minimum_external_families=2" not in decision.missing_requirements
    assert "raw_model_runs" in decision.missing_requirements
    assert "repeated_attempts" in decision.missing_requirements
    assert "utility_measure" in decision.missing_requirements
    assert "failure_report" in decision.missing_requirements
