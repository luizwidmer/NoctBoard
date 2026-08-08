# ADR 0003: Ship deterministic local audit before a transparency service

Status: accepted

The MVP exports deterministic accepted/rejected replay evidence from verified
local Noctweave state. It does not call relay ordering consensus, and it does
not treat `nw.shared-log@1` as a permanent audit database.

The redacted JSONL itself is unsigned and omits the containers/plaintext needed
for replay. Its standalone inspector checks structure and summary counts only;
full local projection verification requires retained authenticated group
history. V1 refuses writes at 3,000 events and has no checkpoint/base-state
recovery if a bypass client forces runtime compaction.

A network transparency sequencer would add equivocation detection, receipts,
and witnesses, but it would also add a new availability/ordering trust domain
and require capability rotation, Merkle consistency, and exact-publication
journaling. Those semantics will be designed explicitly rather than hidden
inside the relay.
