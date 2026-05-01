import sys

from prompt_firewall.core import ActionDecision
from prompt_firewall.fixtures import fixtures
from prompt_firewall.model_eval import (
    CautiousFakeModel,
    CommandModel,
    VulnerableFakeModel,
    evaluate_model,
    evaluate_model_fixture,
    select_fixtures,
    summarize_model_results,
)


def test_vulnerable_fake_model_exposes_model_and_policy_layers():
    results = evaluate_model(VulnerableFakeModel(), fixtures=fixtures())
    summary = summarize_model_results(results)

    assert summary["model_compromised"] > 0
    assert summary["contained_compromises"] > 0
    assert summary["uncontained_compromises"] > 0
    assert summary["content_violations"] > 0

    email_exfil = next(result for result in results if result.fixture_id == "ADJ-001-workspace-email-exfil")
    assert email_exfil.model_compromised
    assert email_exfil.contained
    assert email_exfil.policy_decision == ActionDecision.REQUIRE_APPROVAL

    prompt_hijack = next(result for result in results if result.fixture_id == "TT-002-prompt-hijacking-output")
    assert prompt_hijack.model_compromised
    assert prompt_hijack.content_violation
    assert not prompt_hijack.contained


def test_cautious_fake_model_has_no_compromises():
    results = evaluate_model(CautiousFakeModel(), fixtures=fixtures())
    summary = summarize_model_results(results)

    assert summary["model_compromised"] == 0
    assert summary["uncontained_compromises"] == 0
    assert summary["containment_rate"] == 1.0


def test_command_model_adapter_reads_prompt_from_stdin():
    fixture = next(item for item in fixtures() if item.id == "PF-001-read-untrusted-email")
    model = CommandModel(f"{sys.executable} tests/fake_model_command.py")
    result = evaluate_model_fixture(model, fixture)

    assert result.proposed_action.value == "summarize"
    assert result.policy_decision == ActionDecision.ALLOW
    assert "Command model" in result.answer


def test_select_fixtures_by_id_prefix_and_limit():
    selected = select_fixtures(
        fixtures(),
        fixture_ids=["PF-002-immediate-email-exfil", "TT-002-prompt-hijacking-output"],
    )
    assert [fixture.id for fixture in selected] == [
        "PF-002-immediate-email-exfil",
        "TT-002-prompt-hijacking-output",
    ]

    prefixed = select_fixtures(fixtures(), fixture_prefix="ADJ-", limit=2)
    assert [fixture.id for fixture in prefixed] == [
        "ADJ-001-workspace-email-exfil",
        "ADJ-002-workspace-cloud-tool-output",
    ]
