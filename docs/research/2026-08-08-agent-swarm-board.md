# Agent-swarm board research — 2026-08-08

This note separates repository-verified Noctweave behavior from external design
input. External sources informed the threat model; they are not Noctweave
requirements or proof that Noct Board implements another protocol.

## Local findings

- The public Swift `HeadlessMessagingClient` already supports group creation,
  admission, typed content capability negotiation, exact application prepare
  and resume, sync, maintenance, removal, and encrypted local state.
  Removal is an underlying operator capability; Noct Board v1 deliberately
  does not expose it until epoch-segmented audit and current-versus-historical
  member semantics are specified.
- Noctweave group credentials are group-scoped ML-DSA/ML-KEM authorities; a
  persona is local UI state, not protocol identity.
- `nw.shared-log@1` is an opaque capability store with a 30-day and 100,000
  record ceiling. It does not define board authorization or signed audit
  semantics.
- Relay and group stores are bounded delivery/runtime state. A permanent human
  archive must be explicit and separately protected.

## External lessons adopted

- NIST CAISI's agent red-team results reinforce that authenticated natural
  language must remain untrusted data rather than implicit authority.
- A2A task/message/artifact shapes are useful future projections, but an
  authentication-required task state is not itself authorization.
- MCP security guidance supports keeping tool credentials at a separate
  executor boundary and rejecting token passthrough/confused-deputy designs.
- Macaroons and DPoP illustrate attenuated capability caveats and
  proof-of-possession/replay binding. Noct Board does not copy their bearer
  formats into v1.
- SCITT transparency services and Merkle consistency proofs are relevant to a
  future witnessed audit plane. Relay sequence is not substituted for them.
- MLS epoch/transcript/removal ideas are useful comparison points, while
  Noctweave's experimental group profile remains explicitly non-MLS.

## Primary sources

- [NIST CAISI: Insights from an AI agent security red-teaming competition](https://www.nist.gov/blogs/caisi-research-blog/insights-ai-agent-security-large-scale-red-teaming-competition)
- [A2A 1.0 specification](https://a2a-protocol.org/latest/specification/)
- [MCP security best practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- [Macaroons paper](https://research.google/pubs/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/)
- [RFC 9449: OAuth DPoP](https://www.rfc-editor.org/rfc/rfc9449.html)
- [RFC 9942: COSE receipts](https://www.rfc-editor.org/rfc/rfc9942.html)
- [RFC 9943: SCITT architecture](https://www.rfc-editor.org/rfc/rfc9943.html)
- [RFC 9420: Messaging Layer Security](https://www.rfc-editor.org/rfc/rfc9420.html)

## Deferred deliberately

- Public Agent Cards or global agent discovery as identity authority.
- A shared append bearer handed to every agent.
- A plaintext board database or server-side policy engine.
- Network effects triggered directly by message text.
- Claims of consensus, formal verification, anonymity, or production security.
