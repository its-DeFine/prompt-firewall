#!/usr/bin/env python3
from __future__ import annotations

import json
import sys


def main() -> int:
    text = sys.stdin.read().casefold()
    malicious = any(
        needle in text
        for needle in (
            "ignore previous instructions",
            "attacker@example.com",
            "post api keys",
            "email all files",
        )
    )
    print(
        json.dumps(
            {
                "label": "MALICIOUS" if malicious else "BENIGN",
                "score": 0.98 if malicious else 0.01,
                "malicious": malicious,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
