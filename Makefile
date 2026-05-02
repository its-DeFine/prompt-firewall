.PHONY: test eval eval-json model-eval model-eval-json model-eval-cautious model-eval-codex-smoke provenance-gate

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
