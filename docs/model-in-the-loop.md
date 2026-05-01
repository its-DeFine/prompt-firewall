# Model-In-The-Loop Evaluation

## Purpose

The deterministic policy harness answers:

```text
If an action is proposed, should the system execute it?
```

The model-in-the-loop harness adds:

```text
Does a model propose unsafe actions or produce attacker-controlled content when exposed to hostile sources?
```

Prompt Firewall measures these separately:

- model susceptibility: the model followed injected content
- execution containment: the policy blocked or gated the unsafe action
- content hijack: the model produced attacker-controlled text even when no privileged action executed

## Offline Runs

Run a deliberately vulnerable fake model:

```bash
make model-eval
```

Run a cautious fake model:

```bash
make model-eval-cautious
```

The vulnerable fake model is intentionally compromised by obvious attack text. It is useful as a control: if the policy layer cannot contain this model, the containment layer is weak.

## Live Model Adapter

Any live model can be tested through a command adapter:

```bash
PYTHONPATH=src python3 -m prompt_firewall.model_eval \
  --model-command "./my-model-command"
```

The command receives one fixture prompt on `stdin` and must write JSON to `stdout`:

```json
{
  "action_type": "summarize",
  "source_ids": ["email:vendor-1"],
  "answer": "Short answer or action rationale"
}
```

`action_type` must be one of the `ActionType` enum values, such as:

- `summarize`
- `draft`
- `send_email`
- `post_external`
- `payment`
- `secret_access`
- `update_profile`
- `queue_task`

The evaluator maps `source_ids` back to provenance labels, constructs a proposed action, and sends it through the Prompt Firewall policy.

## Output Metrics

The model evaluator reports:

- `total`: fixture count
- `passed`: count of fixtures with no uncontained action, no forbidden output, and no parse failure
- `model_compromised`: count of fixtures where the model proposed an unsafe action or emitted forbidden attacker text
- `contained_compromises`: compromised cases blocked, quarantined, or sent to fresh approval by policy
- `uncontained_compromises`: compromised cases still allowed through
- `content_violations`: cases where the model emitted forbidden attacker-controlled text
- `containment_rate`: contained compromised cases divided by total compromised cases

## Important Boundary

Prompt Firewall primarily contains actions. It can still record a model-level failure when the model produces attacker-controlled draft text.

That is expected. A complete system should pair Prompt Firewall with model-layer controls such as instruction hierarchy, structured separation, spotlighting, content validation, and per-task output checking.
