# Security policy

Noct Board is pre-1.0 software built on Noctweave's experimental group profile.
It has not received an independent security audit. Do not use it for safety-
critical or high-value production coordination yet.

## Reporting a vulnerability

Report suspected vulnerabilities through a
[private GitHub security advisory](https://github.com/luizwidmer/NoctBoard/security/advisories/new).
Do not open a public issue or include live board keys, relay capabilities,
audit plaintext, admission artifacts, or member state in a report. Use a
minimal synthetic reproducer and redact transport metadata that could identify
other operators.

The maintainer will make a best-effort acknowledgement within seven days and a
status update within fourteen days. This pre-1.0 project provides no production
response SLA. If GitHub's private reporting form is unavailable, do not publish
the details publicly; wait for private vulnerability reporting to be enabled
on the repository.

## Supported versions

| Version | Security support |
| --- | --- |
| Current `main` source | Best effort |
| Evaluation snapshots | Superseded by `main` |
| Signed/notarized binaries | None published |

## Relay access passwords

A non-empty relay access password is accepted only for `tls`, `https`, or
`wss` endpoints. Plaintext `tcp`, `http`, and `ws` endpoints must use no
password and are evaluation-only. The selected endpoint and password persist
in client state, encrypted by default; `--plaintext-testing` stores them and
the other client secrets as plaintext.

## Admission state

Noct Board stores owner admission journals and prospective-member join receipts
in `<state-path>.noctboard-private/admission-state.json`. Preserve and move that
private directory with the Noctweave client-state file. It contains sensitive
request/package material and signed history records; it is encrypted by default
and plaintext under `--plaintext-testing`.

An owner commits a prepared journal before any epoch mutation and can resume
only its exact request, idempotency key, epoch transition, history operations,
and package bytes. A prospective member commits a pending receipt before
accepting Welcome. Until the receipt is verified against the installed local
credential, origin join anchor, and owner-declared history manifest, all
non-genesis board APIs fail closed. Losing the receipt cannot be repaired by
trusting group runtime state alone.

The admission sidecar uses authenticated encryption and an in-file generation,
but it does not have an independent rollback anchor. Deleting it or restoring
an older valid copy can block recovery or board access. Restore the exact
sidecar paired with the main state rather than attempting to reconstruct it.

## In scope

- Cross-board event acceptance or group-binding failures.
- Unauthorized application-role changes or task transitions.
- Audit omissions, non-determinism, digest mismatches, or misleading verdicts.
- Plaintext, group-key, route-capability, or local-state disclosure.
- Admission journal/receipt loss, rollback, substitution, or unsafe recovery.
- Parser confusion, unbounded inputs, replay handling, and denial of service.

## Explicit non-claims

- A compromised authorized endpoint can read the boards it joined.
- Application roles are honest-client/advisory controls, not a cryptographic
  revocation boundary. Because deterministic projection order includes
  sender-supplied Lamport/event fields, a malicious admitted raw endpoint may
  backdate a valid signed write around a role downgrade. Group credential
  removal and epoch rotation are required to stop future writes; that action
  ends the usable v1 board segment.
- Relays and network observers can see transport metadata.
- Noct Board does not sandbox agents or enforce their local tool permissions.
- A separately pinned full-projection digest can reveal that retained local
  history now produces a different projection. Unsigned redacted JSONL alone
  cannot authenticate or replay that projection, detect a coherent forgery, or
  prove that a coordinator never withheld an event no honest endpoint observed.
- Event and projection digests are unkeyed. Redacted exports or separately
  shared digests can confirm offline guesses of low-entropy titles, messages,
  and task text, so protect them like board data.
