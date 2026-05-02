from __future__ import annotations

import ast
import hashlib
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


AGENTDOJO_SOURCE_URL = "https://github.com/ethz-spylab/agentdojo"
AGENTDOJO_LICENSE = "MIT"
BENCHMARK_FAMILY = "agentdojo_external"
METADATA_FORMAT_VERSION = "agentdojo-source-metadata-v1"

DEFAULT_TASK_ROOT = Path("src/agentdojo/default_suites")
DEFAULT_DATA_ROOT = Path("src/agentdojo/data/suites")


class AgentDojoImportError(ValueError):
    """Raised when an AgentDojo checkout cannot be parsed as expected."""


@dataclass(frozen=True)
class AgentDojoTaskRow:
    suite: str
    declared_version: str
    source_version: str
    task_kind: str
    task_id: str
    class_name: str
    decorator: str
    source_version_dir: str
    source_path: str
    source_line: int
    source_kind: str = "external_import_metadata"
    benchmark_family: str = BENCHMARK_FAMILY


@dataclass(frozen=True)
class AgentDojoSuiteSummary:
    suite: str
    user_task_rows: int
    injection_task_rows: int
    injection_vectors: int


@dataclass(frozen=True)
class AgentDojoSourceFile:
    path: str
    sha256: str


def discover_agentdojo_task_rows(agentdojo_path: Path | str) -> list[AgentDojoTaskRow]:
    root = Path(agentdojo_path)
    task_root = root / DEFAULT_TASK_ROOT
    if not task_root.exists():
        raise FileNotFoundError(f"AgentDojo task root not found: {task_root}")

    rows: list[AgentDojoTaskRow] = []
    for task_file in sorted(task_root.glob("*/*/*tasks.py")):
        rows.extend(_parse_task_file(root, task_file))
    return sorted(rows, key=_task_row_sort_key)


def build_agentdojo_manifest(
    agentdojo_path: Path | str,
    upstream_commit: str | None = None,
) -> dict[str, Any]:
    root = Path(agentdojo_path)
    rows = discover_agentdojo_task_rows(root)
    vector_counts = _injection_vector_counts(root)
    source_files = _source_file_hashes(root)
    suites = sorted({row.suite for row in rows} | set(vector_counts))

    suite_summaries = [
        AgentDojoSuiteSummary(
            suite=suite,
            user_task_rows=sum(1 for row in rows if row.suite == suite and row.task_kind == "user_task"),
            injection_task_rows=sum(
                1 for row in rows if row.suite == suite and row.task_kind == "injection_task"
            ),
            injection_vectors=vector_counts.get(suite, 0),
        )
        for suite in suites
    ]

    return {
        "format_version": METADATA_FORMAT_VERSION,
        "benchmark_family": BENCHMARK_FAMILY,
        "source_kind": "external_import_metadata",
        "upstream": {
            "source_url": AGENTDOJO_SOURCE_URL,
            "commit": upstream_commit or _git_commit(root),
            "license": AGENTDOJO_LICENSE,
        },
        "total_task_rows": len(rows),
        "suite_summaries": [asdict(summary) for summary in suite_summaries],
        "source_files": [asdict(source_file) for source_file in source_files],
        "task_rows": [asdict(row) for row in rows],
    }


def manifest_json(manifest: dict[str, Any]) -> str:
    return json.dumps(manifest, indent=2, sort_keys=True) + "\n"


def _parse_task_file(agentdojo_root: Path, task_file: Path) -> list[AgentDojoTaskRow]:
    rel = task_file.relative_to(agentdojo_root)
    parts = rel.parts
    try:
        default_suites_index = parts.index("default_suites")
        source_version_dir = parts[default_suites_index + 1]
        suite = parts[default_suites_index + 2]
    except (ValueError, IndexError) as exc:
        raise AgentDojoImportError(f"Unexpected AgentDojo task path: {rel}") from exc

    tree = ast.parse(task_file.read_text(encoding="utf-8"), filename=str(task_file))
    constants = _module_version_constants(tree)
    rows: list[AgentDojoTaskRow] = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        for decorator in node.decorator_list:
            parsed = _parse_task_decorator(decorator, constants)
            if parsed is None:
                continue
            task_kind, decorator_name, version = parsed
            rows.append(
                AgentDojoTaskRow(
                    suite=suite,
                    declared_version=_version_to_string(version),
                    source_version=_source_version_to_string(source_version_dir),
                    task_kind=task_kind,
                    task_id=_task_id(task_kind, node.name),
                    class_name=node.name,
                    decorator=decorator_name,
                    source_version_dir=source_version_dir,
                    source_path=rel.as_posix(),
                    source_line=node.lineno,
                )
            )
    return rows


def _module_version_constants(tree: ast.Module) -> dict[str, tuple[int, int, int]]:
    constants: dict[str, tuple[int, int, int]] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        version = _literal_version(node.value, constants)
        if version is not None:
            constants[target.id] = version
    return constants


def _parse_task_decorator(
    decorator: ast.expr,
    constants: dict[str, tuple[int, int, int]],
) -> tuple[str, str, tuple[int, int, int]] | None:
    decorator_name: str | None = None
    args: list[ast.expr] = []

    if isinstance(decorator, ast.Attribute):
        decorator_name = decorator.attr
    elif isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
        decorator_name = decorator.func.attr
        args = list(decorator.args)

    if decorator_name == "register_user_task":
        return "user_task", decorator_name, (1, 0, 0)
    if decorator_name == "register_injection_task":
        return "injection_task", decorator_name, (1, 0, 0)
    if decorator_name == "update_user_task":
        return "user_task", decorator_name, _required_version_arg(decorator_name, args, constants)
    if decorator_name == "update_injection_task":
        return "injection_task", decorator_name, _required_version_arg(decorator_name, args, constants)
    return None


def _required_version_arg(
    decorator_name: str,
    args: list[ast.expr],
    constants: dict[str, tuple[int, int, int]],
) -> tuple[int, int, int]:
    if not args:
        raise AgentDojoImportError(f"{decorator_name} decorator is missing a version argument")
    version = _literal_version(args[0], constants)
    if version is None:
        raise AgentDojoImportError(f"Cannot resolve version for {decorator_name}")
    return version


def _literal_version(
    node: ast.expr,
    constants: dict[str, tuple[int, int, int]],
) -> tuple[int, int, int] | None:
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    try:
        value = ast.literal_eval(node)
    except (ValueError, TypeError):
        return None
    if (
        isinstance(value, tuple)
        and len(value) == 3
        and all(isinstance(component, int) for component in value)
    ):
        return value
    return None


def _task_id(task_kind: str, class_name: str) -> str:
    prefix = "UserTask" if task_kind == "user_task" else "InjectionTask"
    match = re.fullmatch(rf"{prefix}(\d+)", class_name)
    if match is None:
        raise AgentDojoImportError(f"Unexpected AgentDojo {task_kind} class name: {class_name}")
    return f"{task_kind}_{match.group(1)}"


def _task_row_sort_key(row: AgentDojoTaskRow) -> tuple[str, str, int, str]:
    task_number = int(row.task_id.rsplit("_", 1)[1])
    return row.suite, row.task_kind, task_number, row.source_version


def _version_to_string(version: tuple[int, int, int]) -> str:
    return ".".join(str(component) for component in version)


def _source_version_to_string(source_version_dir: str) -> str:
    if not source_version_dir.startswith("v"):
        raise AgentDojoImportError(f"Unexpected AgentDojo source version directory: {source_version_dir}")
    parts = source_version_dir.removeprefix("v").split("_")
    if not parts or len(parts) > 3 or not all(part.isdigit() for part in parts):
        raise AgentDojoImportError(f"Unexpected AgentDojo source version directory: {source_version_dir}")
    return ".".join([*parts, *("0" for _ in range(3 - len(parts)))])


def _injection_vector_counts(agentdojo_root: Path) -> dict[str, int]:
    data_root = agentdojo_root / DEFAULT_DATA_ROOT
    if not data_root.exists():
        return {}
    counts: dict[str, int] = {}
    for vector_file in sorted(data_root.glob("*/injection_vectors.yaml")):
        suite = vector_file.parent.name
        counts[suite] = _count_top_level_yaml_keys(vector_file)
    return counts


def _count_top_level_yaml_keys(path: Path) -> int:
    count = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith((" ", "\t")):
            continue
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if re.match(r"^[A-Za-z0-9_-]+:", stripped):
            count += 1
    return count


def _source_file_hashes(agentdojo_root: Path) -> list[AgentDojoSourceFile]:
    paths = list((agentdojo_root / DEFAULT_TASK_ROOT).glob("*/*/*tasks.py"))
    data_root = agentdojo_root / DEFAULT_DATA_ROOT
    if data_root.exists():
        paths.extend(data_root.glob("*/injection_vectors.yaml"))
    return [
        AgentDojoSourceFile(path=path.relative_to(agentdojo_root).as_posix(), sha256=_sha256(path))
        for path in sorted(paths)
    ]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
