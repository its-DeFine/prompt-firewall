from prompt_firewall.fixtures import fixtures
from prompt_firewall.provenance import (
    benchmark_families,
    summarize_fixture_provenance,
    superiority_claim_gate,
)


def test_fixture_provenance_is_explicit():
    summary = summarize_fixture_provenance(fixtures())

    assert summary.total_fixtures == 21
    assert summary.local_synthetic == 12
    assert summary.synthetic_compatibility == 9
    assert summary.external_import == 0
    assert summary.unknown == 0
    assert summary.families == ("agentdojo_style", "prompt_firewall", "tensor_trust_style")


def test_external_benchmark_targets_are_manifested_but_not_claim_ready():
    families = benchmark_families()

    assert families["agentdojo_external"].source_kind == "external_import"
    assert families["agentdojo_external"].status == "metadata_importer_implemented"
    assert families["tensor_trust_external"].license == "BSD-2-Clause"
    assert families["agentdyn_external"].license == "MIT"


def test_superiority_claim_is_blocked_without_external_rows():
    decision = superiority_claim_gate(
        fixtures(),
        raw_model_runs=True,
        repeated_attempts=True,
        utility_measure=True,
        failure_report=True,
    )

    assert not decision.allowed
    assert decision.external_fixture_count == 0
    assert "minimum_external_fixtures=30" in decision.missing_requirements
    assert "minimum_external_families=2" in decision.missing_requirements
