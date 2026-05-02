# Evaluation Plan

## Goal

Evaluate whether a safeguard prevents untrusted content from becoming authority while preserving useful read, summarize, and draft workflows.

The benchmark separates two questions:

1. Security: did the system prevent unauthorized side effects?
2. Utility: did the system still complete benign work?

## Why Deterministic First

LLM-only evaluation is noisy. The first engineering step is a deterministic harness where fixtures encode:

- signed owner intent
- source provenance
- taint labels
- memory transformations
- proposed action
- expected policy decision

This lets us test the control boundary before model behavior enters the loop.

## Safeguard Classes to Compare

### No Guard

The model can execute any proposed action. This is the negative control.

Expected result: high utility, high unsafe action rate.

### Prompt-Only Pattern Filtering

The system blocks known phrases such as "ignore previous instructions". This catches obvious attacks and misses obfuscated or delayed attacks.

Expected result: brittle security, possible false confidence.

### Structured Separation and Spotlighting

Structured separation, delimiters, and spotlighting help the model distinguish input sources in the current prompt. They are valuable, but a test must check whether provenance survives storage, retrieval, and handoff.

Expected result: better immediate behavior, weaker delayed-chain coverage unless the system persists provenance.

### Instruction Hierarchy

Instruction hierarchy trains or configures models to prioritize system and developer instructions over lower-privilege text. This is useful model behavior, but the test still checks whether an unsafe tool call can execute if the model is confused.

Expected result: lower attack success rate at the model layer, still needs action mediation for high-impact tools.

### Capability and Control-Flow Mediation

CaMeL-style defenses and Prompt Firewall both put a protective layer around the model. The benchmark should test whether untrusted data can alter control flow or create unauthorized data flows.

Expected result: strongest security when policy enforcement happens outside the LLM.

## Testing Another Safeguard

To compare another prompt-injection safeguard, implement an adapter with this behavior:

```python
class MySafeguard:
    name = "my_safeguard"

    def decide(self, fixture) -> tuple[ActionDecision, str]:
        ...
```

The adapter must return one of:

- `allow`
- `block`
- `require_fresh_approval`
- `quarantine`

For model-layer safeguards, run the model or protocol first, map the proposed result to one of those decisions, and record the prompt, model, parameters, and attack budget outside the fixture. For execution-layer safeguards, evaluate the policy decision directly.

Report two numbers separately:

- model robustness: whether the model ignored or followed injected instructions
- execution containment: whether the system prevented unauthorized side effects

Prompt Firewall is primarily an execution-containment design. It can be paired with model-layer defenses such as instruction hierarchy, structured queries, or spotlighting.

## Current v0 Fixtures

The v0 fixture suite lives in `src/prompt_firewall/fixtures.py` and is summarized in `benchmarks/persistent-taint-fixtures.md`.

It covers:

- immediate email exfiltration
- hidden email text summarized into memory
- later retrieval of tainted memory
- profile/preference poisoning
- external calendar to autonomous task queue
- missing provenance
- internal draft utility
- fresh approval path
- consumed-token replay
- tool-output handoff poisoning
- out-of-scope payment
- tainted memory write quarantine
- AgentDojo-style workspace, travel, banking, and tool-output attacks
- Tensor-Trust-style prompt extraction and prompt hijacking attacks
- executable AgentDojo external injection-task side effects sourced from upstream metadata

## Scoring

Run:

```bash
make eval
```

The evaluator reports:

- total fixtures
- pass count
- pass rate
- unsafe allows
- utility blocks

For CI, run:

```bash
make test
```

For model-in-the-loop evaluation, run:

```bash
make model-eval
```

This runs a deliberately vulnerable fake model through the same fixtures. To plug in a live model, see `docs/model-in-the-loop.md`.

## Proper Evaluation Standard

The v0 harness is not enough to claim broad security. A serious evaluation needs:

- at least 30 fully assessed episodes
- blind or held-out fixtures
- independent adjudication for ambiguous expected decisions
- explicit utility tasks, not only attacks
- attack families from published benchmarks such as AgentDojo and Tensor Trust
- repeated attempts per attack to measure attack-budget effects
- clear distinction between model robustness and execution-layer containment

## Stop Rules

Do not claim Prompt Firewall "solves prompt injection".

Acceptable claim:

```text
Prompt Firewall reduces prompt-injection impact by making stored context non-authoritative unless it carries signed intent and passes deterministic policy.
```
