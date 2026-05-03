#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from prompt_firewall.fixtures import fixtures
from prompt_firewall.provenance import summarize_fixture_provenance, superiority_claim_gate


def main() -> int:
    parser = argparse.ArgumentParser(description="Check benchmark provenance and release claim gates.")
    parser.add_argument("--json", action="store_true", help="Emit JSON.")
    parser.add_argument("--check-superiority", action="store_true", help="Fail if superiority claim is not allowed.")
    parser.add_argument(
        "--compared-safeguard",
        action="append",
        default=[],
        help="Safeguard target id with completed comparison evidence. May be repeated.",
    )
    args = parser.parse_args()

    current_fixtures = fixtures()
    summary = summarize_fixture_provenance(current_fixtures)
    gate = superiority_claim_gate(current_fixtures, compared_safeguards=tuple(args.compared_safeguard))
    payload = {
        "provenance": asdict(summary),
        "superiority_claim_gate": asdict(gate),
    }

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(
            "fixtures={total} local_synthetic={local} synthetic_compatibility={compat} "
            "external_import={external} unknown={unknown}".format(
                total=summary.total_fixtures,
                local=summary.local_synthetic,
                compat=summary.synthetic_compatibility,
                external=summary.external_import,
                unknown=summary.unknown,
            )
        )
        print(f"superiority_allowed={gate.allowed} reason={gate.reason}")
        if gate.missing_requirements:
            print("missing=" + ",".join(gate.missing_requirements))

    if args.check_superiority and not gate.allowed:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
