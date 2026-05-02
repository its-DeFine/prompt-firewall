# External Benchmark Metadata

This directory is for reproducible metadata extracted from external prompt-injection benchmarks.

The metadata files here identify upstream commits, task ids, suite names, source paths, line numbers, source-file hashes, and injection-vector counts. They do not vendor raw benchmark prompts, environments, or injection text.

Current status:

- `agentdojo-source-metadata.json`: AgentDojo source metadata generated from a local checkout.

Rows with concrete AgentDojo injection-task side-effect functions are converted into executable `ADJX-*` Prompt Firewall fixtures. Output-only tasks and tasks whose security condition infers side effects without explicit ground-truth function calls remain metadata-only.

The superiority claim gate remains closed until at least two external benchmark families are executable, model runs are recorded, repeated attack attempts are measured, benign utility is reported, and failure cases are published.
