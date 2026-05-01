# Architecture

Prompt Firewall separates language work from authority.

The LLM may read, summarize, classify, and propose. A deterministic broker decides whether the system may act.

## Components

### Intent Compiler

Transforms raw human input into a canonical task packet:

- goal
- scope
- allowed tools
- forbidden tools
- data sources
- risk level
- expiry
- nonce
- budget limits
- approval gates
- expected deliverable

The packet is signed by the owner or by an approved authorization service.

### Intent Verifier

Verifies:

- signature validity
- current owner key
- nonce freshness
- token expiry
- token consumption state
- requested action within scope

Verification happens outside the LLM.

### Capability Ledger

Tracks consumable tokens:

- session token
- per-tool token
- per-action token
- high-risk approval token

The ledger is online state. Cryptography proves who authorized a packet. The ledger proves whether that authorization is current and unspent.

### Canonical Input Renderer

Converts external content into a reviewable, structured form:

- visible text
- hidden text
- links and link targets
- sender or source metadata
- attachment names and hashes
- extracted OCR text
- comments and metadata
- decoded suspicious blobs
- transformation history

This helps detection and review. It is not the security boundary.

### Taint Engine

Assigns and propagates source labels:

- `owner_instruction`
- `trusted_policy`
- `trusted_config`
- `untrusted_external`
- `tool_output`
- `derived_from_untrusted`
- `quarantined`
- `promoted_memory`

Any transformation of tainted content remains tainted unless it passes a promotion gate.

### Memory Store

Stores content with provenance:

- source id
- source authority
- taint labels
- transformation chain
- creator identity
- creation time
- expiry or review time
- promotion state
- allowed use

Memory records are not just text. They are text plus authority metadata.

### Action Firewall

Evaluates tool calls before execution:

```text
signed_intent
+ token_state
+ requested_tool
+ requested_action
+ action_parameters
+ parameter_provenance
+ taint_sources
+ risk_policy
= allow | block | require_fresh_approval | quarantine
```

The LLM can propose an action. The firewall decides whether it executes.

### Audit Log

Records:

- signed packet hash
- capability token id
- content sources used
- taint labels
- model proposal
- policy decision
- tool call or block reason
- human approval event when present

Audit entries are append-only.

## Control Flow

1. User asks for work.
2. Intent compiler creates a canonical task packet.
3. Owner signs or approves the packet.
4. Capability ledger issues bounded tokens.
5. Agent reads external sources through canonical renderers.
6. Taint engine labels all untrusted content and derived artifacts.
7. Memory writes go to quarantine unless promotion rules pass.
8. LLM proposes actions.
9. Action firewall validates proposed actions against signed intent, token state, and taint.
10. Allowed actions execute through least-privilege tools.
11. Audit log records the evidence.

## Key Rule

Reading hostile content can inform the task. It cannot expand authority.

If an action depends on untrusted content, the system must either:

- stay read-only
- produce a draft for human review
- request fresh approval
- block

