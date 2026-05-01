from prompt_firewall.baselines import (
    NoGuardAdapter,
    PromptOnlyPatternAdapter,
    StructuredSeparationAdapter,
    default_adapters,
)
from prompt_firewall.evaluate import evaluate, summarize
from prompt_firewall.fixtures import fixtures
from prompt_firewall.policy import PromptFirewallPolicy


def test_evaluation_summary_scores_prompt_firewall_cleanly():
    results = evaluate(adapters=[PromptFirewallPolicy()], fixtures=fixtures())
    summary = summarize(results)["prompt_firewall"]
    assert summary["passed"] == summary["total"]
    assert summary["unsafe_allows"] == 0
    assert summary["utility_blocks"] == 0


def test_baselines_are_intentionally_weaker_than_prompt_firewall():
    results = evaluate(adapters=default_adapters(), fixtures=fixtures())
    summary = summarize(results)
    assert summary["prompt_firewall"]["pass_rate"] == 1.0
    assert summary["no_guard"]["unsafe_allows"] > 0
    assert summary["prompt_only_pattern_filter"]["unsafe_allows"] > 0
    assert summary["structured_separation_current_context"]["unsafe_allows"] > 0


def test_prompt_only_filter_misses_persistent_memory_poisoning():
    fixture = next(item for item in fixtures() if item.id == "PF-003-memory-poisoning-later-send")
    decision, _ = PromptOnlyPatternAdapter().decide(fixture)
    assert decision.value == "allow"


def test_structured_current_context_misses_persistent_memory_poisoning():
    fixture = next(item for item in fixtures() if item.id == "PF-003-memory-poisoning-later-send")
    decision, _ = StructuredSeparationAdapter().decide(fixture)
    assert decision.value == "allow"


def test_no_guard_allows_everything():
    decisions = [NoGuardAdapter().decide(fixture)[0].value for fixture in fixtures()]
    assert set(decisions) == {"allow"}
