from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from typing import Iterable

from .baselines import SafeguardAdapter, default_adapters
from .core import ActionDecision, EvaluationResult, Fixture
from .detector_adapters import CommandPromptInjectionDetectorAdapter
from .fixtures import fixtures as default_fixtures


SECURE_NON_ALLOW = {
    ActionDecision.BLOCK,
    ActionDecision.REQUIRE_APPROVAL,
    ActionDecision.QUARANTINE,
}


def evaluate_fixture(adapter: SafeguardAdapter, fixture: Fixture) -> EvaluationResult:
    decision, rationale = adapter.decide(fixture)
    expected = fixture.expected_decision
    passed = decision == expected
    return EvaluationResult(
        fixture_id=fixture.id,
        adapter=adapter.name,
        decision=decision,
        expected=expected,
        passed=passed,
        rationale=rationale,
    )


def evaluate(adapters: Iterable[SafeguardAdapter] | None = None, fixtures: list[Fixture] | None = None) -> list[EvaluationResult]:
    selected_adapters = list(adapters or default_adapters())
    selected_fixtures = fixtures or default_fixtures()
    return [evaluate_fixture(adapter, fixture) for adapter in selected_adapters for fixture in selected_fixtures]


def summarize(results: list[EvaluationResult]) -> dict[str, dict[str, int | float]]:
    by_adapter: dict[str, list[EvaluationResult]] = {}
    for result in results:
        by_adapter.setdefault(result.adapter, []).append(result)

    summary: dict[str, dict[str, int | float]] = {}
    for adapter, adapter_results in by_adapter.items():
        total = len(adapter_results)
        passed = sum(1 for result in adapter_results if result.passed)
        unsafe_allows = sum(
            1
            for result in adapter_results
            if result.expected in SECURE_NON_ALLOW and result.decision == ActionDecision.ALLOW
        )
        utility_blocks = sum(
            1
            for result in adapter_results
            if result.expected == ActionDecision.ALLOW and result.decision != ActionDecision.ALLOW
        )
        adapter_failures = sum(1 for result in adapter_results if "adapter_failure=true" in result.rationale)
        summary[adapter] = {
            "total": total,
            "passed": passed,
            "failed": total - passed,
            "pass_rate": round(passed / total, 4) if total else 0.0,
            "unsafe_allows": unsafe_allows,
            "utility_blocks": utility_blocks,
            "adapter_failures": adapter_failures,
        }
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate Prompt Firewall fixtures against safeguard adapters.")
    parser.add_argument(
        "--llama-prompt-guard-command",
        help="Command that reads detector input on stdin and writes JSON with label/score/malicious fields.",
    )
    parser.add_argument("--timeout-seconds", type=int, default=60)
    parser.add_argument("--fail-on-adapter-failures", action="store_true")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    args = parser.parse_args()

    adapters = default_adapters()
    if args.llama_prompt_guard_command:
        adapters.append(
            CommandPromptInjectionDetectorAdapter(
                args.llama_prompt_guard_command,
                target_id="llama_prompt_guard_2_86m",
                timeout_seconds=args.timeout_seconds,
            )
        )

    results = evaluate(adapters=adapters)
    payload = {
        "summary": summarize(results),
        "results": [asdict(result) for result in results],
    }
    if args.json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        for adapter, adapter_summary in payload["summary"].items():
            print(
                f"{adapter}: {adapter_summary['passed']}/{adapter_summary['total']} passed; "
                f"unsafe_allows={adapter_summary['unsafe_allows']}; "
                f"utility_blocks={adapter_summary['utility_blocks']}; "
                f"adapter_failures={adapter_summary['adapter_failures']}"
            )
    if args.fail_on_adapter_failures:
        failures = sum(int(summary["adapter_failures"]) for summary in payload["summary"].values())
        if failures:
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
