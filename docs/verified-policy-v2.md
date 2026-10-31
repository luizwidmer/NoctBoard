# Verified board policy v2

Noct Board retains the same board UUID, Noctweave group, group-scoped keys, and
`org.noctboard/event:1.0` content capability. The signed inner event uses strict
`schema = org.noctboard/event:2.0`. Its `policy.checkpoint-v2` operation is an
owner-signed policy boundary, never an ordinary member command. The owner is
the immutable genesis Core group owner, regardless of its application role.

## Cutoff proof

A checkpoint carries its Core group epoch and confirmed transcript hash, the
previous checkpoint event digest, the exact active credential frontier vector,
and a digest of the ordered signed Board records preceding it. The vector has
one frontier per active credential. Each frontier names that credential's
authenticated Core sender counter and prefix digest immediately before the
owner's checkpoint envelope. The owner's own pre-event frontier must agree
with the accepted Core receipt for that exact envelope. Board verifies every
signed record and direct Core receipt, then durably pins the checkpoint and
frontiers through `replaceProtectedApplicationEvent` before accepting its
policy. An accepted but unpinned owner checkpoint makes normal reads and
writes fail closed until the original publication is resumed or the received
checkpoint is verified and pinned.

For a direct event, the Core receipt places it before or after each checkpoint
using its epoch and credential counter. The Board projector applies owner
checkpoints in that authenticated interval order. Sender-controlled logical
clocks and timestamps can order ordinary events *within* an interval, but they
cannot move a post-downgrade write across the cutoff. Per-author sequence and
digest continuity still span intervals. A checkpoint whose role change would
violate task or coordinator invariants invalidates the checkpoint chain.

The checkpoint's ordered-record digest binds the exact legacy history the
owner reviewed. A compact inline order may be included for the bounded
late-join case. When it is omitted, existing members reconstruct the order
from their retained, signed records and authenticated Core positions; a
missing record or digest mismatch fails closed. The root labels earlier v1
history as owner-reviewed legacy data: it cannot retroactively prove that an
older sender clock was honest. Direct schema-v1 events after a v2 root are
quarantined, and nonowner checkpoint-shaped traffic is never policy authority.

## In-place migration and admission

`review-legacy-policy` shows an owner the current v1 projection and digest.
`migrate-policy --approved-digest` recomputes that exact projection under the
Board mutation lease, checks checkpoint size and the retained-history window,
rotates the Core metadata epoch to the board's v2 digest, and publishes a fresh
owner root on the *same* group. Every event in the approved retained set must
be present for the root to verify. Already accepted legacy role order remains
an explicit owner decision. The old binary recognizes only v1 metadata and
fails closed after the rotation; all active endpoints should upgrade before
migration. A conservative 16 MiB durable-record headroom check rejects a
near-capacity group before metadata rotation with
`verifiedPolicyCapacityExceeded`; the owner must preserve the state and reduce
Core storage pressure before retrying. Core's 32 MiB aggregate persistence
check is still authoritative, so this check cannot prove that a later epoch
journal or root will fit. A root interrupted after epoch rotation leaves Board
APIs closed until exact pending transport and Core pin recovery succeeds.

Admission still re-encrypts at most 128 exact signed Board records in owner
history wrappers. These wrappers preserve the original Board signature, but
not the old Core receipt. Before the package is returned, the owner publishes
a fresh current-epoch policy snapshot after re-encryption. The late joiner
verifies the exact declared manifest and the new snapshot's signed record
order, then pins the new root before its receipt becomes verified. Histories
beyond the existing 128-record admission bound remain closed to new members.
An admitted raw Core client can also fill the 3,072-event recent window outside
Board's publish API and evict an old direct record. Digest-only reconstruction
then fails closed; restoring availability requires an authenticated durable
archive or a Core retention/quota mechanism, which this version does not have.

## Limits and evidence

The local encrypted Core runtime and owner-signed Board records are required
to verify v2 policy. The redacted audit JSONL is a decision summary and cannot
independently prove receipt counters, pinning, completeness of unseen relay
traffic, or role cutoffs. Keep the runtime and private admission sidecar with
the board state. An admitted endpoint can still send ciphertext and read any
content it already received; credential removal is the group write cutoff.
