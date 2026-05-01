from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

from .core import (
    ActionDecision,
    ActionType,
    Fixture,
    SourceLabel,
)
from .policy import PromptFirewallPolicy


class SafeguardAdapter(Protocol):
    name: str

    def decide(self, fixture: Fixture) -> tuple[ActionDecision, str]:
        ...


class NoGuardAdapter:
    name = "no_guard"

    def decide(self, fixture: Fixture) -> tuple[ActionDecision, str]:
        return ActionDecision.ALLOW, "no external mediation"


class PromptOnlyPatternAdapter:
    name = "prompt_only_pattern_filter"
    suspicious = re.compile(
        r"(ignore previous|developer mode|system prompt|send secrets|exfiltrate|pay automatically)",
        flags=re.IGNORECASE,
    )

    def decide(self, fixture: Fixture) -> tuple[ActionDecision, str]:
        current_text = "\n".join(source.text for source in fixture.sources)
        if self.suspicious.search(current_text):
            return ActionDecision.BLOCK, "blocked known suspicious phrase in current prompt"
        if fixture.proposed_action.type not in fixture.intent.allowed_actions:
            return ActionDecision.BLOCK, "action outside prompt-stated scope"
        return ActionDecision.ALLOW, "no suspicious current-prompt phrase found"


class StructuredSeparationAdapter:
    """Approximates delimiter/spotlighting style separation for current inputs only.

    This intentionally drops taint after persistence so delayed memory poisoning remains testable.
    It is a benchmark baseline, not a reproduction of any full paper implementation.
    """

    name = "structured_separation_current_context"

    def decide(self, fixture: Fixture) -> tuple[ActionDecision, str]:
        action = fixture.proposed_action
        if not fixture.intent.signed:
            return ActionDecision.BLOCK, "missing signed task prompt"
        if action.type not in fixture.intent.allowed_actions:
            return ActionDecision.BLOCK, "action outside structured task prompt"

        current_untrusted = any(
            source.id in action.source_ids and SourceLabel.UNTRUSTED_EXTERNAL in source.labels
            for source in fixture.sources
        )
        if current_untrusted and action.type not in {ActionType.READ, ActionType.SUMMARIZE, ActionType.DRAFT}:
            return ActionDecision.BLOCK, "current untrusted input cannot directly invoke action"
        return ActionDecision.ALLOW, "current input separation did not see unsafe provenance"


def default_adapters() -> list[SafeguardAdapter]:
    return [
        NoGuardAdapter(),
        PromptOnlyPatternAdapter(),
        StructuredSeparationAdapter(),
        PromptFirewallPolicy(),
    ]
