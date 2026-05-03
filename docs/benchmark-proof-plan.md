# Benchmark Proof Plan

## Purpose

Prompt Firewall should make stronger claims only when those claims are backed by published benchmark methodology and reproducible evidence.

The current v0.1 release is an early reference harness. It contains local synthetic fixtures and synthetic compatibility fixtures. That is useful for mechanism testing, but it is not enough to claim superiority over published systems.

## Proof Standard

A superiority claim requires:

- at least 30 externally sourced fixtures
- at least two external benchmark families
- at least six named compared safeguards
- at least three deployed guardrail comparisons
- at least two research-defense comparisons
- raw model runs, not only Codex CLI product-stack runs
- repeated attack attempts per case
- utility measurement on benign tasks
- a failure report with examples
- identical fixture sets for each compared safeguard

This standard is encoded in `benchmarks/provenance/benchmark-sources.json` and enforced by `scripts/provenance_gate.py`.
Named comparison targets are tracked in `benchmarks/provenance/safeguard-targets.json`.

Run:

```bash
make provenance-gate
```

Current expected result:

```text
fixtures=103 local_synthetic=12 synthetic_compatibility=9 external_import=82 unknown=0
superiority_allowed=False
```

## External Benchmark Targets

### AgentDojo

Source: https://github.com/ethz-spylab/agentdojo

Status: executable fixture subset implemented for injection tasks with concrete side-effect function names.

License: MIT.

Why it matters: AgentDojo is designed for evaluating prompt-injection attacks and defenses in agentic tool-use environments. It is the first target for tool-use containment and utility measurement.

Current importer:

```bash
AGENTDOJO_PATH=/path/to/agentdojo make agentdojo-manifest
```

The importer records upstream commit, suite names, task ids, decorator-declared versions, source version directories, source paths, line numbers, source-file hashes, injection-vector counts, and ground-truth tool function names. It intentionally does not copy raw benchmark prompt or injection text into this repository.

The current executable conversion maps AgentDojo injection tasks with concrete side-effect functions into `ADJX-*` Prompt Firewall fixtures. It skips output-only tasks and tasks whose AgentDojo security check infers side effects without explicit ground-truth function calls.

### Tensor Trust

Source: https://github.com/HumanCompatibleAI/tensor-trust

Status: content fixture subset implemented from Tensor Trust benchmark row metadata.

License: BSD-2-Clause.

Why it matters: Tensor Trust provides prompt-hijacking and prompt-extraction attack data from an adversarial game setting. It is useful for model-layer compromise and content-hijack evaluation.

Current importer:

```bash
TENSORTRUST_CODE_PATH=/path/to/tensor-trust \
TENSORTRUST_DATA_PATH=/path/to/tensor-trust-data \
make tensortrust-manifest
```

The importer records source commits, dataset file hashes, row counts, selected sample ids, row hashes, field hashes, and field lengths. It intentionally does not copy raw attacks, defenses, or access codes into this repository.

Raw Tensor Trust model episodes are scaffolded separately:

```bash
PYTHONPATH=src python3 scripts/raw_tensortrust_eval.py /path/to/tensor-trust-data --dry-run
```

Dry runs emit prompt hashes and lengths. Actual runs require `--model-command` and store output hashes and pass/fail flags, not raw model outputs.

### AgentDyn / Dynamic Environment Attacks

Source: https://github.com/SaFo-Lab/AgentDyn

Status: planned import.

License: MIT.

Why it matters: dynamic environment attacks are closer to delayed or stateful agent behavior. AgentDyn reports 60 open-ended user tasks and 560 injection test cases across Shopping, GitHub, and Daily Life, which is relevant to persistent taint, stored context, and chained attacks.

## Comparison Matrix

Prompt Firewall must be compared against:

- no guard
- prompt-only filtering
- structured separation / StruQ-style current-context separation
- spotlighting-style source marking
- instruction-hierarchy model behavior
- CaMeL-style capability/control-flow mediation
- Prompt Firewall

For a claim against advanced or deployed safeguards, the named target set must include at least:

- Azure Prompt Shields (`azure_prompt_shields`)
- Google Cloud Model Armor (`google_model_armor`)
- Amazon Bedrock Guardrails Prompt Attack Filter (`aws_bedrock_guardrails_prompt_attack`)
- Lakera Guard Prompt Defense (`lakera_guard_prompt_defense`)
- Meta Llama Prompt Guard 2 86M (`llama_prompt_guard_2_86m`)
- CaMeL capability/control-flow mediation (`camel_capability_mediation`)
- StruQ structured queries (`struq_structured_queries`)
- Spotlighting source marking (`spotlighting_source_marking`)
- recent tool-interface firewall benchmark-leader defenses (`tool_interface_firewall_benchmark_leader`)

The Llama Prompt Guard 2 target has a command-adapter scaffold:

```bash
python3 -m pip install -e ".[prompt-guard]"
make eval-llama-prompt-guard
make eval-protectai-prompt-injection
make eval-neuralchemy-prompt-injection
```

Each comparison should report:

- attack success rate
- unsafe action rate
- containment rate
- content-hijack rate
- benign utility completion
- false block rate
- parse failure rate
- cost and latency where model calls are used

## Claim Gate

Allowed now:

```text
Prompt Firewall is an early reference harness and policy design with local synthetic and compatibility fixtures.
```

Blocked now:

```text
Prompt Firewall is proven better than published defenses or benchmark-leading systems.
```

The blocked claim becomes reviewable only after the proof standard above is satisfied. Metadata-only imports do not count as runnable external fixtures, and content-only fixtures are not a substitute for raw model runs over the upstream benchmark text.
