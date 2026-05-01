# Threat Model

## Scope

This document covers prompt injection in agentic systems that read external content, write persistent state, retrieve memory, and call tools.

The central risk is authority confusion: untrusted text is interpreted as an instruction or a reason to take action.

## Assets

- Owner intent: what the human actually authorized.
- Capability tokens: permission to execute a task or action.
- Tool access: mail, files, browser, calendar, shell, payments, code hosting, databases, and APIs.
- Persistent memory: notes, summaries, embeddings, task queues, plans, profiles, and agent handoffs.
- Secrets: credentials, tokens, private data, private system prompts, and internal policy.
- Audit trail: evidence needed to reconstruct why an action happened.

## Attackers

- Direct user attacker: sends malicious instructions in the chat.
- Indirect content attacker: controls email, web pages, documents, images, calendar invites, comments, tickets, or tool output.
- Memory poisoner: plants content that becomes trusted later.
- Peer-agent attacker: influences one agent so it poisons another agent's context.
- Supply-chain attacker: injects malicious content through docs, dependencies, examples, or generated artifacts.

## Attack Surfaces

- Raw prompts.
- Retrieved documents.
- Email bodies, headers, attachments, and quoted text.
- Hidden text, CSS, HTML comments, metadata, OCR text, and zero-width characters.
- Summaries and extracted facts.
- Embeddings and vector search results.
- Long-term memory and profile fields.
- Task queues and deferred action plans.
- Tool outputs passed back into the model.
- Multi-agent handoff packets.

## Primary Attacks

### Immediate Indirect Injection

An external document instructs the model to ignore the user's task and call a tool.

Control: untrusted content is tainted, and tainted context cannot authorize privileged tool calls.

### Persistent Memory Poisoning

An attacker plants text that gets summarized into memory and later retrieved as trusted context.

Control: taint survives transformation. Summaries, embeddings, and extracted facts inherit the taint of their sources.

### Attack Chaining Through Deferred Work

An attacker adds instructions into a task queue or plan, then waits for a future autonomous run.

Control: queued work must bind back to signed owner intent, expiry, and a consumable token.

### Tool Output Injection

A tool returns attacker-controlled content, and the LLM treats it as instructions for the next step.

Control: tool outputs are labeled by provenance and authority. Most tool outputs are data, not instructions.

### Cross-Agent Propagation

One agent stores poisoned context, and another agent retrieves it without provenance.

Control: handoffs carry taint metadata and source provenance. Missing provenance routes to quarantine.

## Security Goals

- Prevent stale, replayed, or forged intent from authorizing actions.
- Prevent untrusted content from becoming trusted through summarization or embedding.
- Require fresh approval for high-risk actions derived from untrusted content.
- Preserve enough provenance to explain why an action was allowed or blocked.
- Make risky behavior fail closed when provenance is missing.

## Non-Goals

- Perfectly detecting every malicious prompt.
- Making an LLM inherently distinguish data from instructions.
- Letting the model self-authorize tool use.
- Treating a clean summary as automatically trustworthy.

