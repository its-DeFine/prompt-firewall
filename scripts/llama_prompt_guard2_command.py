#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description="Classify stdin with Meta Llama Prompt Guard 2.")
    parser.add_argument("--model-id", default="meta-llama/Llama-Prompt-Guard-2-86M")
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument("--device", default=None, help="Transformers pipeline device, such as cpu, mps, cuda:0, or -1.")
    args = parser.parse_args()

    text = sys.stdin.read()
    try:
        from transformers import pipeline
    except ModuleNotFoundError as exc:
        print(
            json.dumps(
                {
                    "label": "UNAVAILABLE",
                    "score": 0.0,
                    "malicious": False,
                    "error": "missing optional dependency: transformers",
                }
            )
        )
        return 2

    device = int(args.device) if args.device and args.device.lstrip("-").isdigit() else args.device
    classifier_kwargs = {
        "task": "text-classification",
        "model": args.model_id,
        "top_k": None,
    }
    if device is not None:
        classifier_kwargs["device"] = device
    classifier = pipeline(**classifier_kwargs)
    raw_result = classifier(text, truncation=True, max_length=args.max_length)
    scores = _normalize_scores(raw_result)
    top = max(scores, key=lambda item: float(item.get("score", 0.0)))
    label = str(top["label"])
    score = float(top["score"])
    malicious_score = max(
        (float(item["score"]) for item in scores if str(item["label"]).casefold() == "malicious"),
        default=score if label.casefold() == "malicious" else 0.0,
    )
    payload = {
        "label": label,
        "score": score,
        "malicious": label.casefold() == "malicious" and malicious_score >= args.threshold,
        "malicious_score": malicious_score,
        "threshold": args.threshold,
        "model_id": args.model_id,
        "input_chars": len(text),
    }
    print(json.dumps(payload))
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
