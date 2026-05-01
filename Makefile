.PHONY: test eval eval-json

test:
	PYTHONPATH=src python3 -m pytest

eval:
	PYTHONPATH=src python3 -m prompt_firewall.evaluate

eval-json:
	PYTHONPATH=src python3 -m prompt_firewall.evaluate --json
