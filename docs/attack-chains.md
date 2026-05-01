# Attack Chains

## Chain 1: Email to Memory to Later Send

1. Attacker sends an email with hidden instructions.
2. Assistant summarizes the email.
3. Summary is stored in memory.
4. Later, a separate task retrieves the memory.
5. Agent sends mail or files based on the poisoned instruction.

Controls:

- canonical renderer exposes hidden content
- summary inherits `derived_from_untrusted`
- memory enters quarantine or tainted storage
- retrieved memory cannot authorize sends
- send requires fresh signed approval

## Chain 2: Web Page to Vector Index to Tool Call

1. Agent crawls a web page.
2. Page contains prompt injection in visible or hidden text.
3. The content is embedded.
4. Search retrieves it for a later task.
5. Model treats retrieved text as policy.

Controls:

- embeddings preserve source taint
- vector search returns text plus provenance
- action firewall sees tainted sources
- authority-changing actions are blocked

## Chain 3: Calendar Invite to Autonomous Run

1. Attacker sends a calendar invite with instructions in the description.
2. Assistant extracts a TODO.
3. TODO is queued for later autonomous execution.
4. Agent runs while the owner is offline.

Controls:

- external calendar fields are `untrusted_external`
- extracted TODO is `derived_from_untrusted`
- autonomous queue requires signed task packet
- expired or missing tokens block execution

## Chain 4: Tool Output to Agent Handoff

1. A tool returns attacker-controlled text.
2. Agent includes it in a handoff to another agent.
3. The next agent treats the handoff as trusted instruction.

Controls:

- tool output gets provenance labels
- handoff packet includes taint metadata
- missing taint metadata routes to quarantine
- receiving agent accepts instruction only from signed owner packet or trusted policy

## Chain 5: User Profile Poisoning

1. External content says the owner prefers to skip approval gates.
2. Agent stores it as a preference.
3. Later actions bypass review.

Controls:

- external content cannot update preferences or policy
- profile writes are privileged memory writes
- approval-gate changes require owner signature

## Chain 6: Documentation Poisoning

1. A dependency README contains malicious agent instructions.
2. Agent indexes the README.
3. Later code-generation task retrieves the poisoned doc.
4. Agent modifies build or deployment config.

Controls:

- dependency docs are untrusted unless vendored and reviewed
- code and deployment mutations require signed scope
- generated diffs require review if influenced by tainted sources

