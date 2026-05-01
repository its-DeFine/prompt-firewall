from __future__ import annotations

from .core import (
    AUTHORITY_CHANGES,
    EXTERNAL_SIDE_EFFECTS,
    ActionDecision,
    ActionRisk,
    ActionType,
    Fixture,
    SourceLabel,
)


class PromptFirewallPolicy:
    """Deterministic action firewall for taint-aware fixtures."""

    name = "prompt_firewall"

    def decide(self, fixture: Fixture) -> tuple[ActionDecision, str]:
        action = fixture.proposed_action
        intent = fixture.intent
        labels_by_id = fixture.source_labels_by_id

        referenced_labels = set(action.parameter_taint)
        for source_id in action.source_ids:
            referenced_labels.update(labels_by_id.get(source_id, {SourceLabel.QUARANTINED}))

        if not intent.signed:
            return ActionDecision.BLOCK, "missing signed owner intent"

        if intent.consumed or intent.expires_in_seconds <= 0:
            return ActionDecision.BLOCK, "intent token is stale or consumed"

        if action.type not in intent.allowed_actions:
            return ActionDecision.BLOCK, "action outside signed task scope"

        if SourceLabel.QUARANTINED in referenced_labels:
            return ActionDecision.QUARANTINE, "missing or quarantined provenance"

        tainted = bool(
            referenced_labels
            & {
                SourceLabel.UNTRUSTED_EXTERNAL,
                SourceLabel.TOOL_OUTPUT,
                SourceLabel.DERIVED_FROM_UNTRUSTED,
            }
        )

        if action.type in {ActionType.READ, ActionType.SUMMARIZE}:
            return ActionDecision.ALLOW, "read-only work is allowed under signed scope"

        if action.type == ActionType.DRAFT and tainted:
            return ActionDecision.ALLOW, "tainted content may produce an internal draft"

        if action.type == ActionType.STORE_MEMORY and tainted:
            return ActionDecision.QUARANTINE, "tainted memory writes enter quarantine"

        if action.type == ActionType.SECRET_ACCESS and tainted:
            return ActionDecision.BLOCK, "tainted content cannot request secret access"

        if action.type in AUTHORITY_CHANGES and tainted:
            return ActionDecision.BLOCK, "tainted content cannot create authority"

        if action.creates_authority and tainted:
            return ActionDecision.BLOCK, "tainted content cannot create authority"

        if action.type == ActionType.QUEUE_TASK and tainted:
            return ActionDecision.REQUIRE_APPROVAL, "tainted deferred work needs fresh owner approval"

        if action.type in EXTERNAL_SIDE_EFFECTS and tainted and not intent.fresh_approval:
            return ActionDecision.REQUIRE_APPROVAL, "external side effects from tainted context need fresh approval"

        if action.risk in {ActionRisk.HIGH, ActionRisk.CRITICAL} and tainted and not intent.fresh_approval:
            return ActionDecision.REQUIRE_APPROVAL, "high-risk tainted action needs fresh approval"

        return ActionDecision.ALLOW, "signed intent and taint policy allow action"
