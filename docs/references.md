# References

This project tracks related work in two groups: security guidance and benchmark or defense research.

## Security Guidance

- OWASP LLM01:2025 Prompt Injection: https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- OWASP LLM06:2025 Excessive Agency: https://genai.owasp.org/llmrisk/llm062025-excessive-agency/
- OWASP LLM Prompt Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html
- UK NCSC, "Prompt injection is not SQL injection": https://www.ncsc.gov.uk/blog-post/prompt-injection-is-not-sql-injection

## Defense Research

- StruQ, "Defending Against Prompt Injection with Structured Queries": https://arxiv.org/abs/2402.06363
- Spotlighting, "Defending Against Indirect Prompt Injection Attacks With Spotlighting": https://arxiv.org/abs/2403.14720
- OpenAI, "The Instruction Hierarchy: Training LLMs to Prioritize Privileged Instructions": https://openai.com/index/the-instruction-hierarchy/
- CaMeL, "Defeating Prompt Injections by Design": https://arxiv.org/abs/2503.18813

## Benchmarks

- AgentDojo, "A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents": https://arxiv.org/abs/2406.13352
- Tensor Trust, "Interpretable Prompt Injection Attacks from an Online Game": https://arxiv.org/abs/2311.01011

## Evaluation Note

Prompt Firewall's current adapters are not full reproductions of the systems above. They are deterministic controls for measuring whether persistent taint and action mediation cover attack-chain classes that prompt-only or current-context-only defenses can miss.
