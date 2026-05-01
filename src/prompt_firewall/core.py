from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class SourceLabel(StrEnum):
    OWNER_INSTRUCTION = "owner_instruction"
    TRUSTED_POLICY = "trusted_policy"
    TRUSTED_CONFIG = "trusted_config"
    UNTRUSTED_EXTERNAL = "untrusted_external"
    TOOL_OUTPUT = "tool_output"
    DERIVED_FROM_UNTRUSTED = "derived_from_untrusted"
    QUARANTINED = "quarantined"
    PROMOTED_MEMORY = "promoted_memory"


class ActionType(StrEnum):
    READ = "read"
    SUMMARIZE = "summarize"
    DRAFT = "draft"
    STORE_MEMORY = "store_memory"
    PROMOTE_MEMORY = "promote_memory"
    UPDATE_PROFILE = "update_profile"
    QUEUE_TASK = "queue_task"
    SEND_EMAIL = "send_email"
    POST_EXTERNAL = "post_external"
    COMMIT_CODE = "commit_code"
    DELETE = "delete"
    SECRET_ACCESS = "secret_access"
    PAYMENT = "payment"
    CHANGE_POLICY = "change_policy"


class ActionRisk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionDecision(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_fresh_approval"
    QUARANTINE = "quarantine"


WRITE_ACTIONS = {
    ActionType.STORE_MEMORY,
    ActionType.PROMOTE_MEMORY,
    ActionType.UPDATE_PROFILE,
    ActionType.QUEUE_TASK,
    ActionType.SEND_EMAIL,
    ActionType.POST_EXTERNAL,
    ActionType.COMMIT_CODE,
    ActionType.DELETE,
    ActionType.PAYMENT,
    ActionType.CHANGE_POLICY,
}

EXTERNAL_SIDE_EFFECTS = {
    ActionType.SEND_EMAIL,
    ActionType.POST_EXTERNAL,
    ActionType.COMMIT_CODE,
    ActionType.PAYMENT,
}

MODEL_OUTPUT_ACTIONS = {
    ActionType.DRAFT,
    ActionType.SUMMARIZE,
}

AUTHORITY_CHANGES = {
    ActionType.UPDATE_PROFILE,
    ActionType.PROMOTE_MEMORY,
    ActionType.CHANGE_POLICY,
}


@dataclass(frozen=True)
class Source:
    id: str
    labels: frozenset[SourceLabel]
    text: str = ""
    hidden_text: str = ""

    @property
    def is_tainted(self) -> bool:
        return bool(
            self.labels
            & {
                SourceLabel.UNTRUSTED_EXTERNAL,
                SourceLabel.TOOL_OUTPUT,
                SourceLabel.DERIVED_FROM_UNTRUSTED,
                SourceLabel.QUARANTINED,
            }
        )

    @property
    def has_provenance(self) -> bool:
        return bool(self.id and self.labels)


@dataclass(frozen=True)
class MemoryRecord:
    id: str
    text: str
    labels: frozenset[SourceLabel]
    source_ids: tuple[str, ...]
    promoted_for: tuple[str, ...] = ()

    @classmethod
    def derive(cls, id: str, text: str, sources: list[Source | "MemoryRecord"]) -> "MemoryRecord":
        labels: set[SourceLabel] = set()
        source_ids: list[str] = []
        for source in sources:
            labels.update(source.labels)
            source_ids.append(source.id)
        if labels & {SourceLabel.UNTRUSTED_EXTERNAL, SourceLabel.TOOL_OUTPUT, SourceLabel.QUARANTINED}:
            labels.add(SourceLabel.DERIVED_FROM_UNTRUSTED)
        if not source_ids:
            labels.add(SourceLabel.QUARANTINED)
        return cls(id=id, text=text, labels=frozenset(labels), source_ids=tuple(source_ids))

    @property
    def is_tainted(self) -> bool:
        return bool(
            self.labels
            & {
                SourceLabel.UNTRUSTED_EXTERNAL,
                SourceLabel.TOOL_OUTPUT,
                SourceLabel.DERIVED_FROM_UNTRUSTED,
                SourceLabel.QUARANTINED,
            }
        )

    @property
    def has_provenance(self) -> bool:
        return bool(self.source_ids and self.labels)


@dataclass(frozen=True)
class IntentPacket:
    id: str
    signed: bool
    allowed_actions: frozenset[ActionType]
    fresh_approval: bool = False
    expires_in_seconds: int = 900
    consumed: bool = False

    def authorizes(self, action_type: ActionType) -> bool:
        return self.signed and not self.consumed and self.expires_in_seconds > 0 and action_type in self.allowed_actions


@dataclass(frozen=True)
class ProposedAction:
    type: ActionType
    risk: ActionRisk
    source_ids: tuple[str, ...] = ()
    parameter_taint: frozenset[SourceLabel] = field(default_factory=frozenset)
    creates_authority: bool = False

    @property
    def has_tainted_parameters(self) -> bool:
        return bool(
            self.parameter_taint
            & {
                SourceLabel.UNTRUSTED_EXTERNAL,
                SourceLabel.TOOL_OUTPUT,
                SourceLabel.DERIVED_FROM_UNTRUSTED,
                SourceLabel.QUARANTINED,
            }
        )


@dataclass(frozen=True)
class Fixture:
    id: str
    description: str
    intent: IntentPacket
    sources: tuple[Source, ...]
    memory: tuple[MemoryRecord, ...]
    proposed_action: ProposedAction
    expected_decision: ActionDecision
    benchmark: str = "prompt_firewall"
    attack_family: str = "policy"
    forbidden_output_substrings: tuple[str, ...] = ()
    required_output_substrings: tuple[str, ...] = ()
    utility_decision: ActionDecision | None = None

    @property
    def source_labels_by_id(self) -> dict[str, frozenset[SourceLabel]]:
        labels: dict[str, frozenset[SourceLabel]] = {source.id: source.labels for source in self.sources}
        labels.update({record.id: record.labels for record in self.memory})
        return labels


@dataclass(frozen=True)
class EvaluationResult:
    fixture_id: str
    adapter: str
    decision: ActionDecision
    expected: ActionDecision
    passed: bool
    rationale: str


@dataclass(frozen=True)
class ModelProposal:
    action: ProposedAction
    answer: str
    raw_output: str
    parse_error: str | None = None


@dataclass(frozen=True)
class ModelEvaluationResult:
    fixture_id: str
    benchmark: str
    attack_family: str
    model: str
    policy: str
    proposed_action: ActionType
    policy_decision: ActionDecision
    expected_policy_decision: ActionDecision
    model_compromised: bool
    content_violation: bool
    contained: bool
    passed: bool
    answer: str
    rationale: str
