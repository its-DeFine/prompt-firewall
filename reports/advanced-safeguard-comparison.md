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

### Open Hugging Face Classifier Adapter

Adapter status: command adapter scaffolded plus batch Hugging Face evaluator.

Implemented target ids:

- `llama_prompt_guard_2_86m`
- `protectai_deberta_prompt_injection_v2`
- `devndeploy_bert_prompt_injection_detector`
- `neuralchemy_prompt_injection_deberta`

Run:

```bash
python3 -m pip install -e ".[prompt-guard]"
make eval-llama-prompt-guard
make eval-protectai-prompt-injection
make eval-devndeploy-prompt-injection
make eval-neuralchemy-prompt-injection
```

## Private VM Run: 2026-05-03

Private VM identity, IP address, and disk paths are intentionally omitted from this public report.

Repository gates inside the private VM:

```text
make test: 28 passed
make eval: prompt_firewall 103/103 passed; unsafe_allows=0; utility_blocks=0; adapter_failures=0
make provenance-gate: superiority_allowed=False
```

Open classifier results:

```text
protectai_deberta_prompt_injection_v2: 27/103 passed; unsafe_allows=46; utility_blocks=24; adapter_failures=0
devndeploy_bert_prompt_injection_detector: 28/103 passed; unsafe_allows=0; utility_blocks=25; adapter_failures=0
```

Blocked targets:

```text
llama_prompt_guard_2_86m: blocked by gated Hugging Face model access; not evidence
neuralchemy_prompt_injection_deberta: blocked by tokenizer initialization error under the pinned Transformers stack; not evidence
```

The successful open-classifier results are valid fixture-suite comparisons for those two named safeguards. They are not sufficient for a superiority claim because the claim gate still requires more named safeguards, raw model runs, repeated attempts, utility measurement, and failure analysis.

A valid run must have:

- `adapter_failures=0`
- model id and revision recorded
- classifier threshold recorded
- identical fixture set recorded
- repeated attempts or a documented deterministic-classifier exception
- utility and false-block results
- failure examples with safe redaction

## Interpretation Rule

Classifier-only safeguards are evaluated as detector gates: malicious detection maps to `block`, and benign detection maps to `allow`. This intentionally separates prompt-attack detection from execution-layer authorization and persistent-taint containment.
