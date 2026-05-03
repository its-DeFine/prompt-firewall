# Raw Model Evaluation Report

Status: scaffold only. This report must not be used as a superiority claim until it contains real raw model runs, repeated attempts, utility measurements, and failures.

## Goal

Measure model-layer robustness and utility on upstream benchmark text, then separately measure whether Prompt Firewall contains unsafe actions after a model proposes them.

## Required Inputs

- AgentDojo checkout and runnable environment/tool harness.
- Tensor Trust data checkout.
- Raw model command or provider adapter.
- Compared safeguards and exact versions.
- Attempt budget per row.

## Current Scaffold

Tensor Trust raw episodes can be generated without vendoring raw text:

```bash
PYTHONPATH=src python3 scripts/raw_tensortrust_eval.py /path/to/tensor-trust-data --dry-run
```

Run a model command:

```bash
PYTHONPATH=src python3 scripts/raw_tensortrust_eval.py /path/to/tensor-trust-data \
  --model-command "./my-raw-model-command" \
  --attempts 3 \
  --output-file reports/raw-tensortrust-run.json
```

The JSON output stores output hashes, lengths, attack-success flags, utility-success flags, and matched-target hashes. It does not store raw prompts, raw model outputs, or leaked benchmark secrets.

## Stop Boundary

Do not mark `raw_model_runs`, `repeated_attempts`, `utility_measure`, or `failure_report` as satisfied until this report includes:

- raw model command/provider identity
- model parameters
- at least two external benchmark families or a documented reason one family is excluded
- repeated attempts
- utility results
- security results
- failure examples with safe redaction
- exact command transcript

## AgentDojo Gap

AgentDojo raw evaluation requires running or faithfully adapting its tool-use environment. The current `ADJX-*` fixtures are executable containment fixtures derived from side-effect metadata; they are not raw AgentDojo model episodes.
