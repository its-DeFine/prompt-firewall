#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from prompt_firewall.core import ActionDecision, EvaluationResult
from prompt_firewall.detector_adapters import render_fixture_detection_text
from prompt_firewall.evaluate import summarize
from prompt_firewall.fixtures import fixtures as default_fixtures


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate a Hugging Face prompt-injection classifier once per suite.")
    parser.add_argument("--model-id", required=True)
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument("--malicious-label", action="append", required=True)
    parser.add_argument("--device", default=None, help="Transformers pipeline device, such as cpu, mps, cuda:0, or -1.")
    parser.add_argument("--fixture-prefix")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--output-file")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    try:
        from transformers import pipeline
    except ModuleNotFoundError as exc:
        raise SystemExit("missing optional dependency: transformers") from exc

    selected_fixtures = default_fixtures()
    if args.fixture_prefix:
        selected_fixtures = [fixture for fixture in selected_fixtures if fixture.id.startswith(args.fixture_prefix)]
    if args.limit is not None:
        selected_fixtures = selected_fixtures[: args.limit]

    device = int(args.device) if args.device and args.device.lstrip("-").isdigit() else args.device
    classifier_kwargs = {
        "task": "text-classification",
        "model": args.model_id,
        "top_k": None,
    }
    if device is not None:
        classifier_kwargs["device"] = device
    classifier = pipeline(**classifier_kwargs)
    malicious_labels = {label.casefold() for label in args.malicious_label}

    results: list[EvaluationResult] = []
    for fixture in selected_fixtures:
        rendered = render_fixture_detection_text(fixture)
        raw_scores = classifier(rendered, truncation=True, max_length=args.max_length)
        scores = _normalize_scores(raw_scores)
        top = max(scores, key=lambda item: float(item.get("score", 0.0)))
        label = str(top["label"])
        score = float(top["score"])
        malicious = label.casefold() in malicious_labels and score >= args.threshold
        decision = ActionDecision.BLOCK if malicious else ActionDecision.ALLOW
        results.append(
            EvaluationResult(
                fixture_id=fixture.id,
                adapter=args.target_id,
                decision=decision,
                expected=fixture.expected_decision,
                passed=decision == fixture.expected_decision,
                rationale=f"label={label}; score={score:.6f}; threshold={args.threshold}; model_id={args.model_id}",
            )
        )

    payload = {
        "model_id": args.model_id,
        "target_id": args.target_id,
        "threshold": args.threshold,
        "malicious_labels": sorted(args.malicious_label),
        "summary": summarize(results),
        "results": [asdict(result) for result in results],
    }
    if args.output_file:
        with open(args.output_file, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, default=str)
    if args.json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        summary = payload["summary"][args.target_id]
        print(
            f"{args.target_id}: {summary['passed']}/{summary['total']} passed; "
            f"unsafe_allows={summary['unsafe_allows']}; "
            f"utility_blocks={summary['utility_blocks']}; "
            f"adapter_failures={summary['adapter_failures']}; "
            f"model_id={args.model_id}; threshold={args.threshold}"
        )
    return 0


def _normalize_scores(raw_result: object) -> list[dict[str, float | str]]:
    if isinstance(raw_result, list) and raw_result and isinstance(raw_result[0], list):
        raw_result = raw_result[0]
    if isinstance(raw_result, dict):
        raw_result = [raw_result]
    if not isinstance(raw_result, list) or not raw_result:
        raise ValueError(f"unexpected classifier result: {raw_result!r}")
    scores = []
    for item in raw_result:
        if not isinstance(item, dict) or "label" not in item or "score" not in item:
            raise ValueError(f"unexpected classifier item: {item!r}")
        scores.append({"label": str(item["label"]), "score": float(item["score"])})
    return scores


if __name__ == "__main__":
    raise SystemExit(main())
