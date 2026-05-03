AGENTDOJO_PATH ?= ../agentdojo
TENSORTRUST_CODE_PATH ?= ../tensor-trust
TENSORTRUST_DATA_PATH ?= ../tensor-trust-data

.PHONY: test eval eval-json model-eval model-eval-json model-eval-cautious model-eval-codex-smoke provenance-gate agentdojo-manifest tensortrust-manifest raw-tensortrust-dry-run

test:
	PYTHONPATH=src python3 -m pytest

eval:
	PYTHONPATH=src python3 -m prompt_firewall.evaluate

eval-json:
	PYTHONPATH=src python3 -m prompt_firewall.evaluate --json

model-eval:
	PYTHONPATH=src python3 -m prompt_firewall.model_eval --fake-model vulnerable

model-eval-cautious:
	PYTHONPATH=src python3 -m prompt_firewall.model_eval --fake-model cautious

model-eval-json:
	PYTHONPATH=src python3 -m prompt_firewall.model_eval --fake-model vulnerable --json

model-eval-codex-smoke:
	PYTHONPATH=src python3 -m prompt_firewall.model_eval \
		--fixture-id PF-002-immediate-email-exfil \
		--fixture-id PF-003-memory-poisoning-later-send \
		--fixture-id ADJ-001-workspace-email-exfil \
		--fixture-id TT-002-prompt-hijacking-output \
		--model-command "python3 scripts/codex_model_command.py"

provenance-gate:
	PYTHONPATH=src python3 scripts/provenance_gate.py

agentdojo-manifest:
	PYTHONPATH=src python3 scripts/agentdojo_manifest.py "$(AGENTDOJO_PATH)" --output benchmarks/external/agentdojo-source-metadata.json

tensortrust-manifest:
	PYTHONPATH=src python3 scripts/tensortrust_manifest.py "$(TENSORTRUST_DATA_PATH)" --code-path "$(TENSORTRUST_CODE_PATH)" --output benchmarks/external/tensortrust-source-metadata.json

raw-tensortrust-dry-run:
	PYTHONPATH=src python3 scripts/raw_tensortrust_eval.py "$(TENSORTRUST_DATA_PATH)" --dry-run
