import sys

from prompt_firewall.core import ActionDecision
from prompt_firewall.detector_adapters import (
    CommandPromptInjectionDetectorAdapter,
    parse_detector_output,
    render_fixture_detection_text,
)
from prompt_firewall.evaluate import evaluate_fixture
from prompt_firewall.fixtures import fixtures


def test_parse_detector_output_accepts_prompt_guard_shape():
    verdict = parse_detector_output('{"label": "MALICIOUS", "score": 0.93}')

    assert verdict.malicious
    assert verdict.label == "MALICIOUS"
    assert verdict.score == 0.93


def test_detector_input_includes_hidden_text_and_memory_but_not_expected_decision():
    fixture = next(item for item in fixtures() if item.id == "PF-001-read-untrusted-email")
    rendered = render_fixture_detection_text(fixture)

    assert "Ignore previous instructions" in rendered
    assert "expected_decision" not in rendered


def test_command_detector_adapter_blocks_detected_prompt_attack():
    fixture = next(item for item in fixtures() if item.id == "PF-002-immediate-email-exfil")
    adapter = CommandPromptInjectionDetectorAdapter(
        f"{sys.executable} tests/fake_detector_command.py",
        target_id="llama_prompt_guard_2_86m",
    )

    result = evaluate_fixture(adapter, fixture)

    assert result.adapter == "llama_prompt_guard_2_86m"
    assert result.decision == ActionDecision.BLOCK
    assert "MALICIOUS" in result.rationale


def test_command_detector_adapter_allows_when_detector_sees_no_attack():
    fixture = next(item for item in fixtures() if item.id == "PF-006-missing-provenance")
    adapter = CommandPromptInjectionDetectorAdapter(
        f"{sys.executable} tests/fake_detector_command.py",
        target_id="llama_prompt_guard_2_86m",
    )

    decision, rationale = adapter.decide(fixture)

    assert decision == ActionDecision.ALLOW
    assert "BENIGN" in rationale


def test_command_detector_adapter_marks_unavailable_runs_as_failures():
    fixture = next(item for item in fixtures() if item.id == "PF-001-read-untrusted-email")
    adapter = CommandPromptInjectionDetectorAdapter(
        f"{sys.executable} -c 'import sys; sys.exit(2)'",
        target_id="llama_prompt_guard_2_86m",
    )

    decision, rationale = adapter.decide(fixture)

    assert decision == ActionDecision.QUARANTINE
    assert "adapter_failure=true" in rationale
