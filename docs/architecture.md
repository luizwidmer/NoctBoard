# Architecture

## Product boundary

Noct Board is an application protocol and client, not a hosted service. It has
no developer-operated account, discovery, identity, notification, or plaintext
message server. Exactly one board maps to exactly one Noctweave group.

Fresh group-scoped member and credential handles are generated independently
for every board. A local UI may label one handle “planner” or “test agent,” but
that label is not protocol identity and is not portable to another board.

## Components

1. `NoctBoardCore` defines bounded immutable events, product roles, the task
   state machine, deterministic authorization, the materialized projection,
   accepted/rejected evidence, and audit export.
2. `NoctBoardTransport` wraps Noctweave's `HeadlessMessagingClient`. It creates
   a group with the Noct Board content capability, prepares/publishes exact
   group operations, synchronizes pages, and exposes verified events without
   leaking route capabilities or group secrets to the UI. A non-empty relay
   password requires a `tls`, `https`, or `wss` endpoint; plaintext
   `tcp`/`http`/`ws` transports are passwordless evaluation paths. A private
   admission-state sidecar journals owner mutations and joining-member
   receipts before irreversible admission steps.
3. `NoctBoardCLI` is the machine-facing boundary. Commands emit JSON or JSONL;
   protected board text is read from bounded no-follow regular files, never
   argv, and remains payload data rather than command authority.
4. `NoctBoardUI` presents the deterministic fixture, structurally inspects
   unsigned redacted JSONL, and can open an authorized encrypted local client
   state for a fully projected live audit. Opening is local (though normal
   store migrations, rollback anchors, relay preference, and relay password may
   persist); network synchronization is a separate explicit action. Client
   state is encrypted by default; plaintext testing exposes persisted secrets.
5. A standard Noctweave relay moves opaque route packets. It does not know
   board names, task text, application roles, or audit verdicts.

## Ordering and convergence

Every event binds its board ID, author, Lamport clock, canonical timestamp, and
event ID. Clients order first by Lamport clock and then by stable tie-breakers.
The projection is idempotent and deterministic: delivery order does not change
the accepted state or its digest. Claimed timestamps remain authenticated
metadata but are never used as a sole authorization clock.

Noctweave's group layer authenticates the board, epoch, group credential, and
ciphertext. The Noct Board codec additionally checks that the application
event's board, author, ID, and time match the containing group event. A valid
group signature cannot turn a cross-board payload into a local event.

Every transport event also carries a strict domain-separated ML-DSA signature
over its exact canonical Noct Board event bytes using the author's group-scoped
credential. Direct containers and late-join history both verify that signature
against accepted group state before Core projection.

## Membership and roles

Noctweave membership is the cryptographic boundary. Admission material moves
only through an independently authenticated encrypted relationship or an
equivalent reviewed offline exchange. Removal advances group state and blocks
future group traffic for the removed credential; it cannot erase plaintext the
endpoint legitimately learned earlier. That removal exists in Noctweave's
public API, but Noct Board v1 deliberately does not expose a product wrapper
until epoch-segmented audit and current-versus-historical member semantics are
defined. Invoking the lower-level removal secures future group epochs but ends
the usable v1 board segment; later snapshot, publish, and audit operations fail
closed and this version has no recovery path.

Noct Board roles are encrypted application state:

- `coordinator`: manages threads/tasks, assigns product roles, and moderates.
- `worker`: reads, posts messages, claims eligible tasks, and publishes updates
  or results for its claims.
- `auditor`: reads and verifies the projection but has no accepted write
  operation in v1.

These roles are honest-client/advisory policy, not a causal or cryptographic
revocation boundary. Projection order includes sender-supplied Lamport/event
fields, so a malicious admitted raw endpoint may backdate a valid signed write
around an application-role downgrade. Credential removal and epoch rotation
are the future-write cutoff, and, as described above, end the usable v1 board
segment. The group owner is the initial coordinator. Product roles never
replace Noctweave credentials and never create cross-board authority.

## Late-join state

Noctweave forward secrecy intentionally gives a newly admitted member no
pre-admission application plaintext. For a small evaluation board, NoctBoard
therefore lets the immutable genesis owner re-encrypt each retained signed
event into the new epoch using `org.noctboard/history:1.0`. The wrapper must be
authenticated by the genesis owner, while the embedded signed record must still
verify against its original author's group-credential public key. Exact records
deduplicate before deterministic projection.

The resulting provenance is explicit in live snapshots, audit JSONL, and UI.
It establishes original credential attribution for the canonical event, not
the original outer-envelope delivery or ordering. The owner package declares an
exact `(historyGroupEventID, eventID, signedEventRecordDigest)` manifest.
Package expiry equals join-anchor expiry and is the minimum of the admission,
prospective initial route, and every included existing-member route expiry. The
owner requires 15 minutes of remaining handoff validity before epoch mutation.
Completion synchronizes and verifies every declared signed record before
success; expired or incomplete delivery fails closed. The independently
authenticated encrypted invitation channel protects that package and manifest.
This proves completeness only for the owner's declared pre-admission set, not
that the owner included every prior event. Pre-admission container rejections
are not transferred. Admission refuses more than 128 retained application
events; every wrapper consumes the 3,000 group-event audit window, so repeated
admissions have quadratic storage cost.

## Admission durability

Prospective preparation resumes the one exact matching pending admission. On
the owner, a prepared sidecar journal is fsynced before Noctweave persists an
epoch/member intent; it binds the base state, request, idempotency key, routes,
signed history, manifest, and expiry. Retries resume matching epoch/history
operations, and a completed journal retains the canonical package bytes for
exact recovery. A prepared plan that loses the 15-minute handoff margin is
aborted before mutation and may be replaced by a fresh plan.

The joining endpoint fsyncs a pending receipt before it accepts Welcome, then
synchronizes and verifies the owner-declared manifest. Exact retries resume
matching local admission progress after transient failure. A missing or pending
receipt gates every non-genesis board operation; group runtime state alone is
never promoted into Noct Board admission authority.

The journal/receipt lives at
`<state-path>.noctboard-private/admission-state.json` and must travel with the
main client-state file. It is encrypted by default and plaintext in testing
mode. Its generation is not independently rollback-anchored in v1, so loss or
restoration of an older valid sidecar can fail closed and block recovery or
board access.

## Retention

The current MVP keeps history in encrypted Noctweave group events and local
encrypted client state. It does not use `nw.shared-log@1` as an application
database: that provisional module exposes shared bearer authorities, retains at
most 30 days/100,000 records, and does not itself provide a signed transparency
proof or a durable high-level client publication journal.

Audit exports are local sensitive artifacts. Operators should encrypt them at
rest, retain pinned projection digests separately, and rotate exports at a
defined policy boundary. A future segmented transparency feed may use a relay
store only after append authority, rotation, witness, and consistency-proof
semantics are specified.

The current Noctweave group runtime accepts at most 128 active credentials.
Noct Board v1 imposes a harder 3,000-event audit window, below runtime
compaction: honest clients refuse further writes at the limit. If an admitted
bypass client nevertheless forces history compaction or overflow, snapshot
fails explicitly because v1 has no checkpoint/base-state recovery. A
longer-lived archive requires a separately specified segmented store and
checkpoint protocol.

Noctweave group receive routes lease for six hours. NoctBoard `maintain` and
`sync` proactively rotate routes near expiry, and operators must run
`maintain` at least every five hours. An endpoint offline past its receive-route
lease can miss deliveries. Opaque routes are bounded delivery stores, not
archives, and v1 cannot recover an event it never observed.
