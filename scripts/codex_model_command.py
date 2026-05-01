#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ACTION_TYPES = [
    "read",
    "summarize",
    "draft",
    "store_memory",
    "promote_memory",
    "update_profile",
    "queue_task",
    "send_email",
    "post_external",
    "commit_code",
    "delete",
    "secret_access",
    "payment",
    "change_policy",
]


OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "action_type": {"type": "string", "enum": ACTION_TYPES},
        "source_ids": {"type": "array", "items": {"type": "string"}},
        "answer": {"type": "string"},
    },
    "required": ["action_type", "source_ids", "answer"],
    "additionalProperties": False,
}


def build_prompt(fixture_prompt: str) -> str:
    return fixture_prompt


def main() -> int:
    parser = argparse.ArgumentParser(description="Codex CLI command adapter for Prompt Firewall model evaluation.")
    parser.add_argument("--codex-bin", default="/opt/homebrew/bin/codex")
    parser.add_argument("--model", default=os.environ.get("PROMPT_FIREWALL_CODEX_MODEL", "gpt-5.4-mini"))
    parser.add_argument("--effort", default=os.environ.get("PROMPT_FIREWALL_CODEX_EFFORT", "low"))
    parser.add_argument("--cd", default=os.environ.get("PROMPT_FIREWALL_CODEX_CWD", os.getcwd()))
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args()

    fixture_prompt = sys.stdin.read()
    prompt = build_prompt(fixture_prompt)

    with tempfile.TemporaryDirectory(prefix="prompt-firewall-codex-") as tmp:
        schema_path = Path(tmp) / "schema.json"
        output_path = Path(tmp) / "output.json"
        schema_path.write_text(json.dumps(OUTPUT_SCHEMA), encoding="utf-8")

        cmd = [
            args.codex_bin,
            "exec",
            "--sandbox",
            "read-only",
            "--ephemeral",
            "--ignore-rules",
            "--ignore-user-config",
            "-C",
            args.cd,
            "-m",
            args.model,
            "-c",
            f'model_reasoning_effort="{args.effort}"',
            "--output-schema",
            str(schema_path),
            "-o",
            str(output_path),
            prompt,
        ]
        completed = subprocess.run(cmd, text=True, capture_output=True, timeout=args.timeout_seconds, check=False)
        if output_path.exists():
            output = output_path.read_text(encoding="utf-8")
            if output.strip():
                sys.stdout.write(output)
                return 0

        if "UserPromptSubmit Blocked" in completed.stderr:
            answer = "Codex CLI prompt hook blocked the fixture before model response."
        else:
            answer = "Codex CLI produced no schema output."
        fallback = {
            "action_type": "draft",
            "source_ids": [],
            "answer": answer,
        }
        sys.stdout.write(json.dumps(fallback))
        if completed.returncode == 0:
            return 0

        return completed.returncode or 1


if __name__ == "__main__":
    raise SystemExit(main())
