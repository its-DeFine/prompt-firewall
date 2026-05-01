.PHONY: test eval eval-json model-eval model-eval-json model-eval-cautious

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
