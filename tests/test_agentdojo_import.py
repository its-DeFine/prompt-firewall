from __future__ import annotations

from pathlib import Path

from prompt_firewall.agentdojo_import import build_agentdojo_manifest, discover_agentdojo_task_rows


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "agentdojo_minimal"


def test_agentdojo_task_rows_parse_registration_and_update_decorators():
    rows = discover_agentdojo_task_rows(FIXTURE_ROOT)

    assert [(row.task_kind, row.task_id, row.declared_version, row.source_version) for row in rows] == [
        ("injection_task", "injection_task_0", "1.0.0", "1.0.0"),
        ("injection_task", "injection_task_9", "1.2.0", "1.0.0"),
        ("user_task", "user_task_0", "1.0.0", "1.0.0"),
        ("user_task", "user_task_1", "1.2.0", "1.0.0"),
    ]
    assert {row.source_kind for row in rows} == {"external_import_metadata"}
    assert {row.benchmark_family for row in rows} == {"agentdojo_external"}


def test_agentdojo_manifest_is_metadata_only_and_source_pinned():
    manifest = build_agentdojo_manifest(FIXTURE_ROOT, upstream_commit="fixture-commit")

    assert manifest["format_version"] == "agentdojo-source-metadata-v1"
    assert manifest["upstream"]["commit"] == "fixture-commit"
    assert manifest["total_task_rows"] == 4
    assert manifest["suite_summaries"] == [
        {
            "suite": "workspace",
            "user_task_rows": 2,
            "injection_task_rows": 2,
            "injection_vectors": 2,
        }
    ]
    assert all("prompt" not in row for row in manifest["task_rows"])
    assert len(manifest["source_files"]) == 3
