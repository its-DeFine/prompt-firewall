from __future__ import annotations

import hashlib
import json
import shlex
import subprocess
from dataclasses import dataclass

from .core import ActionDecision, Fixture


MALICIOUS_LABELS = {
    "malicious",
    "injection",
    "prompt_injection",
    "jailbreak",
    "unsafe",
}


@dataclass(frozen=True)
class DetectorVerdict:
    malicious: bool
    label: str
    score: float | None = None


class CommandPromptInjectionDetectorAdapter:
    """Map a prompt-injection detector command to the safeguard adapter contract."""

    def __init__(
        self,
        command: str,
        target_id: str,
        timeout_seconds: int = 60,
        fail_closed: bool = True,
    ) -> None:
        self.command = command
        self.target_id = target_id
        self.timeout_seconds = timeout_seconds
        self.fail_closed = fail_closed
        self.command_sha256 = _sha256(command)
        self.name = target_id

    def decide(self, fixture: Fixture) -> tuple[ActionDecision, str]:
        detector_input = render_fixture_detection_text(fixture)
        completed = subprocess.run(
            shlex.split(self.command),
            input=detector_input,
            text=True,
            capture_output=True,
            timeout=self.timeout_seconds,
            check=False,
        )
        if completed.returncode != 0:
            return self._unavailable(
                "detector command failed",
                stderr_sha256=_sha256(completed.stderr),
            )
        try:
            verdict = parse_detector_output(completed.stdout)
        except ValueError as exc:
            return self._unavailable(f"detector output parse failed: {exc}")

        if verdict.malicious:
            return (
                ActionDecision.BLOCK,
                f"{self.target_id} detected malicious prompt; label={verdict.label}; score={verdict.score}",
            )
        return (
            ActionDecision.ALLOW,
            f"{self.target_id} did not detect prompt attack; label={verdict.label}; score={verdict.score}",
        )

    def _unavailable(self, reason: str, stderr_sha256: str | None = None) -> tuple[ActionDecision, str]:
        decision = ActionDecision.QUARANTINE if self.fail_closed else ActionDecision.ALLOW
        detail = f"adapter_failure=true; {reason}; command_sha256={self.command_sha256}"
        if stderr_sha256:
            detail = f"{detail}; stderr_sha256={stderr_sha256}"
        return decision, detail


def render_fixture_detection_text(fixture: Fixture) -> str:
    payload = {
        "task": fixture.description,
        "proposed_action": fixture.proposed_action.type,
        "sources": [
            {
                "id": source.id,
                "labels": sorted(source.labels),
                "text": source.text,
                "hidden_text": source.hidden_text,
            }
            for source in fixture.sources
        ],
        "memory": [
            {
                "id": record.id,
                "labels": sorted(record.labels),
                "text": record.text,
                "source_ids": record.source_ids,
            }
            for record in fixture.memory
        ],
    }
    return json.dumps(payload, indent=2, default=str)


def parse_detector_output(raw_output: str) -> DetectorVerdict:
    try:
        payload = json.loads(raw_output)
    except json.JSONDecodeError as exc:
        raise ValueError(str(exc)) from exc

    label = str(payload.get("label", payload.get("class", ""))).strip()
    score_value = payload.get("score", payload.get("malicious_score"))
    score = float(score_value) if score_value is not None else None
    explicit_malicious = payload.get("malicious")
    if isinstance(explicit_malicious, bool):
        malicious = explicit_malicious
    else:
        malicious = label.casefold() in MALICIOUS_LABELS
    return DetectorVerdict(malicious=malicious, label=label, score=score)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
