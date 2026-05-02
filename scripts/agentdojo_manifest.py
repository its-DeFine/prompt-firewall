#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from pathlib import Path

from prompt_firewall.agentdojo_import import build_agentdojo_manifest, manifest_json


def main() -> int:
    parser = argparse.ArgumentParser(description="Build metadata for an AgentDojo source checkout.")
    parser.add_argument(
        "agentdojo_path",
        nargs="?",
        default=os.environ.get("AGENTDOJO_PATH", "../agentdojo"),
        help="Path to a local AgentDojo checkout.",
    )
    parser.add_argument("--output", type=Path, help="Write manifest JSON to this path.")
    args = parser.parse_args()

    manifest = build_agentdojo_manifest(Path(args.agentdojo_path))
    output = manifest_json(manifest)
    if args.output is None:
        print(output, end="")
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(output, encoding="utf-8")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
