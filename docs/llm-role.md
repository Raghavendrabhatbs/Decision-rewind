# LLM Role

The LLM is an evidence-grounded explanation layer, not the authority for
decision state or recovery.

For an experiment/event, the backend builds context from persisted historical
and current state, the model version pinned to the experiment, proposed
corrections, counterfactual outputs, affected decisions, explicit provenance
paths, recovery and verification audits, and filtered Universal Logs.

For Precinct6 experiments it also includes the pinned dataset revision, source
label semantics, mapping version, and feature-origin annotations. The original
source record is preserved in SQLite, but AI context receives only a bounded
source-field summary and a capped excerpt of the already-sanitized message.
Precinct6's automated benign/suspicious/malicious labels are not treated as
ground truth for D1–D5; missing decision features are labeled simulated or
unavailable.

Persisted state, frozen-model replay, and deterministic verification are
authoritative. Provenance indicates possible dependency, not proof that an
output changed. Universal Logs are supporting temporal evidence and may be
partial. The LLM can explain evidence but cannot approve or execute recovery,
and must not invent missing state or logs. If no API key is configured, the
application reports that AI is unavailable; it does not fabricate a fallback
answer.
