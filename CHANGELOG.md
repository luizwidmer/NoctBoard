# Changelog

All notable user-visible changes to Noct Board will be recorded here.

Noct Board is pre-1.0 evaluation software. It does not yet publish a SemVer
SwiftPM release because its Noctweave dependency is pinned by commit revision.

## Unreleased

### Added

- Strict `org.noctboard/event:1.0` application events and deterministic local
  projection for threads, tasks, assignments, transitions, messages, and roles.
- Group-credential author signatures, one-board/one-group binding, rejected-event
  ledger, bounded late-join history, and explicit history-attestation provenance.
- Crash-resumable board creation, admission, publication, route maintenance, and
  exact operation retry.
- JSON/JSONL agent CLI, redacted structural audit export and inspection, native
  macOS evaluation console, and deterministic demo.
- Cross-board, tampering, clock-poisoning, admission-recovery, route-rotation,
  and unrelated-swarm relay integration coverage.

### Security

- Encrypted local state is the default; plaintext testing is explicit.
- Relay passwords fail closed on non-TLS endpoints.
- Application roles are documented as honest-client policy rather than a
  cryptographic revocation boundary.
- V1 limits and audit non-claims are exposed in README, SECURITY, and the app.
