# ADR 0002: Map one board to one Noctweave group

Status: accepted

Every board uses a distinct Noctweave group and fresh group-scoped member and
credential handles. Product labels stay local. There is no swarm-wide or
cross-board protocol identity.

This gives cryptographic membership, epoch transitions, removal, replay
handling, and encrypted opaque-route transport without inventing another key
distribution system. The cost is that the current group profile is
experimental and bounded; Noct Board must retain an honest pre-1.0 status.

Removal in that list is an underlying Noctweave operator capability. The
NoctBoard v1 wrapper deliberately defers it until epoch-segmented audit and
current-versus-historical member semantics are specified.
