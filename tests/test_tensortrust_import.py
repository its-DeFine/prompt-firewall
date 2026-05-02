from __future__ import annotations

from pathlib import Path

from prompt_firewall.core import ActionDecision, ActionType
from prompt_firewall.tensortrust_import import (
    build_tensortrust_manifest,
    manifest_json,
    tensortrust_external_fixtures,
)


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "tensortrust_minimal"


def test_tensortrust_manifest_records_hashes_not_raw_text(tmp_path):
    manifest = build_tensortrust_manifest(
        FIXTURE_ROOT,
        code_commit="code-fixture",
        data_commit="data-fixture",
        hijacking_limit=1,
        extraction_limit=1,
    )

    assert manifest["format_version"] == "tensortrust-source-metadata-v1"
    assert manifest["upstream"]["code_commit"] == "code-fixture"
    assert manifest["upstream"]["data_commit"] == "data-fixture"
    assert manifest["selection"]["raw_text_vendored"] is False
    assert [summary["row_count"] for summary in manifest["dataset_summaries"]] == [2, 2]
    assert len(manifest["selected_rows"]) == 2
    assert all("attack" not in row for row in manifest["selected_rows"])
    assert all("access_code" not in row for row in manifest["selected_rows"])
    assert all("attack_sha256" in row for row in manifest["selected_rows"])

    manifest_path = tmp_path / "tensortrust-metadata.json"
    manifest_path.write_text(manifest_json(manifest), encoding="utf-8")
    converted = tensortrust_external_fixtures(manifest_path)

    assert len(converted) == 2
    assert converted[0].benchmark == "tensor_trust_external"
    assert converted[0].proposed_action.type == ActionType.DRAFT
    assert converted[0].expected_decision == ActionDecision.ALLOW
    assert converted[0].forbidden_output_substrings == ("Access Granted",)
    assert converted[1].proposed_action.type == ActionType.SECRET_ACCESS
    assert converted[1].expected_decision == ActionDecision.BLOCK
