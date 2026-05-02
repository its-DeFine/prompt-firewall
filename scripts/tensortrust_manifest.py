#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

from prompt_firewall.tensortrust_import import build_tensortrust_manifest, manifest_json


def main() -> int:
    parser = argparse.ArgumentParser(description="Build metadata for a Tensor Trust data checkout.")
    parser.add_argument(
        "tensortrust_data_path",
        nargs="?",
        default=os.environ.get("TENSORTRUST_DATA_PATH", "../tensor-trust-data"),
        help="Path to a local tensor-trust-data checkout.",
    )
    parser.add_argument(
        "--code-path",
        default=os.environ.get("TENSORTRUST_CODE_PATH", "../tensor-trust"),
        help="Optional path to a local tensor-trust source checkout for commit provenance.",
    )
    parser.add_argument("--hijacking-limit", type=int, default=20)
    parser.add_argument("--extraction-limit", type=int, default=20)
    parser.add_argument("--output", type=Path, help="Write manifest JSON to this path.")
    args = parser.parse_args()

    manifest = build_tensortrust_manifest(
        Path(args.tensortrust_data_path),
        code_commit=_git_commit(Path(args.code_path)),
        hijacking_limit=args.hijacking_limit,
        extraction_limit=args.extraction_limit,
    )
    output = manifest_json(manifest)
    if args.output is None:
        print(output, end="")
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(output, encoding="utf-8")
    print(f"wrote {args.output}")
    return 0


def _git_commit(path: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return "unknown"
    return result.stdout.strip()


if __name__ == "__main__":
    raise SystemExit(main())
