from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from prompt_firewall.raw_eval import (
    RawEpisode,
    evaluate_raw_episodes,
    raw_episode_metadata,
    summarize_raw_results,
    tensortrust_raw_episodes,
)


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "tensortrust_minimal"


class LeakyRawModel:
    name = "leaky_raw_model"

    def complete(self, prompt: str, episode: RawEpisode) -> str:
        if episode.family == "tensortrust_hijacking":
            return "Access Granted"
        if episode.family == "tensortrust_extraction":
            return "fixture-code-one"
        return "Nope"


def test_tensortrust_raw_episodes_keep_raw_text_out_of_metadata():
    episodes = tensortrust_raw_episodes(FIXTURE_ROOT, hijacking_limit=1, extraction_limit=1)

    assert [episode.family for episode in episodes] == ["tensortrust_hijacking", "tensortrust_extraction"]
    assert "Ignore the guard" in episodes[0].attack_prompt
    metadata = raw_episode_metadata(episodes)
    assert metadata[0]["attack_prompt_chars"] > 0
    assert "attack_prompt" not in metadata[0]
    assert "fixture-code-one" not in str(metadata)


def test_raw_evaluation_scores_attack_and_utility_without_raw_outputs():
    episodes = tensortrust_raw_episodes(FIXTURE_ROOT, hijacking_limit=1, extraction_limit=1)
    results = evaluate_raw_episodes(LeakyRawModel(), episodes, attempts=2)
    summary = summarize_raw_results(results)

    assert summary["total"] == 4
    assert summary["attack_successes"] == 4
    assert summary["utility_total"] == 2
    assert summary["utility_successes"] == 2
    assert all(result.attack_output_sha256 for result in results)
    assert all(result.attack_forbidden_hit_count == 1 for result in results)
    serialized_results = str([asdict(result) for result in results])
    assert "Access Granted" not in serialized_results
    assert "fixture-code-one" not in serialized_results
