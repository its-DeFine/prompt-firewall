# Persistent Taint Policy v0

## Purpose

This policy prevents prompt injection from becoming durable authority through memory, summaries, embeddings, task queues, or agent handoffs.

## Labels

### `trusted_policy`

System policy shipped by the application owner.

Allowed use: instruction source.

### `owner_instruction`

Current signed user task packet or fresh human approval.

Allowed use: instruction source within its scope, expiry, and token budget.

### `trusted_config`

Application configuration controlled by the operator.

Allowed use: instruction source only for declared configuration fields.

### `untrusted_external`

Content from emails, web pages, documents, tickets, comments, calendars, tool output, OCR, attachments, or other external actors.

Allowed use: data source only.

### `derived_from_untrusted`

Summary, extraction, embedding, classification, memory, plan, or task generated from untrusted content.

Allowed use: data source only.

### `quarantined`

Stored item that may be useful but has missing provenance, suspicious content, risky transformation, or unsafe authority claims.

Allowed use: read-only review.

### `promoted_memory`

A memory item that passed promotion review for a specific use.

Allowed use: data source for declared use. It does not become owner instruction.

## Propagation Rules

1. Derived content inherits all source taint.
2. Summarization does not remove taint.
3. Embedding does not remove taint.
4. Retrieval does not remove taint.
5. Human-visible formatting does not remove taint.
6. Tool output defaults to untrusted unless the tool is explicitly trusted for that field.
7. Missing provenance defaults to `quarantined`.
8. Mixed-source artifacts inherit the highest-risk label present.

## Memory Write Rules

### Rule M1: External Content

External content may be stored only with provenance and taint labels.

Decision: allow to quarantine or tainted memory.

### Rule M2: Extracted Facts

Facts extracted from untrusted content remain `derived_from_untrusted`.

Decision: allow as facts, block as instructions.

### Rule M3: Plans and TODOs

Plans derived from untrusted content cannot enter an autonomous task queue without signed owner intent.

Decision: require fresh approval.

### Rule M4: Profiles and Preferences

External content cannot modify user preferences, agent identity, system policy, tool permissions, or trusted contacts.

Decision: block or require explicit human review.

### Rule M5: Credentials and Secrets

External content cannot request storage, disclosure, rotation, or forwarding of credentials.

Decision: block.

### Rule M6: Missing Provenance

Content with missing source provenance cannot be used to justify tool calls.

Decision: quarantine.

## Promotion Rules

A quarantined or tainted memory may be promoted only when all are true:

- source provenance is present
- intended use is declared
- no authority-expanding instruction is promoted
- high-risk claims have evidence
- promotion is recorded in an audit log
- promotion is scoped to a use case
- promotion expires or has a review date

Promotion does not erase taint history. It creates a reviewed use permission.

## Action Rules

### Rule A1: Read-Only Actions

Read-only analysis over tainted content is allowed when the signed task packet permits the source.

Decision: allow.

### Rule A2: Draft Writes

Drafts based on tainted content are allowed if they do not leave the system or mutate trusted state.

Decision: allow with taint label.

### Rule A3: External Sends

Any external send, post, commit, payment, deletion, permission change, or secret access based on tainted content requires fresh approval.

Decision: require fresh approval.

### Rule A4: Authority Changes

Tainted content cannot change tool permissions, approval gates, trusted keys, trusted contacts, or policy.

Decision: block.

### Rule A5: Deferred Execution

Deferred tasks must carry signed owner intent and token expiry. A memory item cannot itself authorize future execution.

Decision: require signed task packet.

## Audit Requirements

Every memory promotion and action decision records:

- source ids
- taint labels
- transformation chain
- signed task packet hash
- policy rule applied
- decision
- reviewer or approver when present
- timestamp

## Fail-Closed Defaults

When the system cannot determine provenance, authority, token freshness, or allowed use, it blocks or quarantines.

