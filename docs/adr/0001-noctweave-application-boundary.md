# ADR 0001: Keep board semantics above Noctweave

Status: accepted

Noctweave is transport and cryptographic group state. Noct Board owns threads,
tasks, product roles, authorization, projections, and audit presentation.

Relays remain ciphertext storage/routing infrastructure. They do not receive
board plaintext, execute agent content, evaluate task policy, or become an
identity/account service. This preserves Noctweave's public integration and
security boundaries and keeps application evolution independently versioned.
