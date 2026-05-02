# External Benchmark Metadata

This directory is for reproducible metadata extracted from external prompt-injection benchmarks.

The metadata files here identify upstream commits, task ids, suite names, source paths, line numbers, source-file hashes, and injection-vector counts. They do not vendor raw benchmark prompts, environments, or injection text.

Current status:

- `agentdojo-source-metadata.json`: AgentDojo source metadata generated from a local checkout.

These metadata rows are not executable Prompt Firewall fixtures yet. The superiority claim gate remains closed until external benchmark rows are converted into runnable fixtures, model runs are recorded, repeated attack attempts are measured, benign utility is reported, and failure cases are published.
