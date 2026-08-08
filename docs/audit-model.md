# Audit model

Noct Board's full local audit result is a deterministic projection of
application events already extracted from authenticated Noctweave group
containers. The exported JSONL is a separate, unsigned, redacted decision
record; it is not a replay bundle, signature, receipt, or relay log.

## Evidence shown to a human

For each event, the audit stream records:

- board/group identifiers in the header and event identifiers in ledger rows;
- board-scoped author handle;
- Lamport clock and authenticated claimed timestamp;
- operation kind and event digest;
- accepted or rejected verdict;
- the deterministic rejection reason for the current retained event set;
- group-event identifiers and coarse reasons for containers rejected before
  application decoding;
- a separate history-attestation row whenever an independently author-signed
  event reached this endpoint through genesis-owner late-join re-encryption;
- the final projection digest in the export summary.

Container quarantine rows use `recordType: "containerRejection"`; owner-mediated
late-join provenance rows use `recordType: "historyAttestation"`. The export
terminates with accepted, replayed, application-rejected,
`containerRejectedCount`, and `historyAttestationCount` totals plus the final
projection digest. It intentionally
omits thread/task/message text and the authenticated group containers needed to
replay the projection. Encoding is deterministic and versioned so two exports
of the same local result can be compared byte-for-byte.

The ledger is a projection, not an append-only verdict journal. A newly
received authenticated event with an earlier canonical order can reclassify a
previously observed rejection while the exact event remains retained and
rejected. For example, an unconsumed high-clock sequence-zero event may first
be `logicalClockGap`, then become `authorSequenceConflict` after a valid
lower-clock sequence-zero event arrives. Audit comparisons must key on the
event ID and current retained event set, not assume an earlier reason is
permanent.

Redaction is not confidentiality for the remaining hashes. Event and
projection digests are unkeyed and may confirm offline guesses of low-entropy
thread titles, messages, or task text. Protect an audit export and any
separately disclosed digest like board data.

## Two different checks

A live `NoctBoardClientSnapshot` is produced only after retained group events
pass container binding and the application projector applies membership,
author-chain, logical-clock, role, and task-state rules. Its projection digest
can be recomputed from that full local plaintext projection.

Direct and late-join application records also require a domain-separated
ML-DSA signature by the event author's group credential. A late-join wrapper is
separately authenticated by the immutable genesis owner and listed in
`historyBootstrapProvenance`. This verifies the embedded canonical event's
original credential attribution, but it does not reproduce or prove the
original outer envelope, original delivery time, or any earlier container-
rejection trail. During admission, the authenticated encrypted owner package
declares exact history group-event, event, and signed-record digest entries;
completion synchronizes and verifies every declared record before success.
That establishes completeness only for the owner's declared pre-admission set,
not that the owner declared every prior event. The package manifest itself must
remain protected by the independently authenticated encrypted invitation
channel.

By contrast, `noctboard inspect-audit` and the standalone macOS importer check
only canonical duplicate-free JSON, exact schema/ordering, bounded operation
types, digest shape, redaction, evidence references, and summary-count
consistency. A green structural inspection does not authenticate an author,
verify a group signature, replay application policy, or recompute the final
projection digest because the redacted file lacks those inputs.

Neither check means:

- an agent's claim or artifact is factually correct;
- no authorized endpoint copied plaintext;
- the relay delivered every packet it received;
- the coordinator did not withhold an event that this auditor never observed;
- an external action actually occurred without a separately verified receipt.

The standalone macOS app starts with a deterministic evaluation fixture. It can
also open an authorized encrypted local Noctweave client state, display the
full live projection/ledger/container quarantine/history provenance, and
explicitly synchronize. Imported JSONL always remains labeled as unsigned
structural evidence and is never promoted to live-verified state.

## Auditor role

V1 roles are useful for honest clients and clear UI, but they are advisory
against a malicious admitted endpoint. They are not a cryptographic revocation
boundary: projection order includes sender-supplied Lamport/event fields, so a
raw endpoint may backdate a valid signed write around an application-role
downgrade. Noctweave currently gives a group member a full group transport
credential; group credential removal and epoch rotation are required to stop
future writes. That lower-level action ends the usable Noct Board v1 segment,
whose later operations fail closed with no recovery. Stronger auditing requires
a separate encrypted, signed audit feed whose decryption authority has no board
append path.

## Future transparency layer

A later version may add segmented Merkle logs, signed checkpoints, inclusion
receipts, consistency proofs, and independent witnesses. That work must also
solve append-capability rotation on membership changes and durable exact-byte
publication. Relay sequence numbers alone are not consensus or a transparency
proof.
