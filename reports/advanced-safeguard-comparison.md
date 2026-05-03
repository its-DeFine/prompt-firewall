# Advanced Safeguard Comparison Report

Status: scaffold only. This report is not superiority evidence until named safeguard runs have zero adapter failures, repeated attempts, utility measurements, and failure analysis.

## Target Gate

The superiority gate requires:

- at least six named compared safeguards
- at least three deployed safeguard comparisons
- at least two research-defense comparisons
- raw model runs
- repeated attempts
- utility measurement
- failure report

## Current Named Adapter

### Meta Llama Prompt Guard 2 86M

Target id: `llama_prompt_guard_2_86m`

Adapter status: command adapter scaffolded.

Run:

```bash
python3 -m pip install -e ".[prompt-guard]"
make eval-llama-prompt-guard
```

Current local environment result before installing optional dependencies:

```text
make eval-llama-prompt-guard exits nonzero because adapter_failures=103
```

This is not valid comparison evidence because every detector invocation failed closed. A valid run must have:

- `adapter_failures=0`
- model id and revision recorded
- classifier threshold recorded
- identical fixture set recorded
- repeated attempts or a documented deterministic-classifier exception
- utility and false-block results
- failure examples with safe redaction

## Interpretation Rule

Classifier-only safeguards are evaluated as detector gates: malicious detection maps to `block`, and benign detection maps to `allow`. This intentionally separates prompt-attack detection from execution-layer authorization and persistent-taint containment.
