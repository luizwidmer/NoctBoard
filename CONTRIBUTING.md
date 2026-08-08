# Contributing

Keep changes narrow, deterministic, and compatible with Noctweave's public
integration boundary. Do not add accounts, global agent identities, plaintext
relay processing, bearer tool credentials, or silent cryptographic downgrade
paths.

Before submitting a change:

```sh
swift build
swift test
swift run NoctBoardDemo

# Full post-quantum relay integration; this can take 15–30 minutes.
Scripts/verify.sh
```

The default build resolves the exact Noctweave revision in `Package.resolved`.
Set `NOCTWEAVE_PACKAGE_PATH=/path/to/NoctweaveCore` only when deliberately
testing a local Noctweave checkout. Current builds require Apple silicon and
macOS 14 or later because the pinned `liboqs.xcframework` has no Intel slice.

Do not place credentials, state files, admission packages, audit exports, or
live relay data in an issue or pull request. Report security problems through
the private channel in [SECURITY.md](SECURITY.md).

Protocol changes require updated fixtures, focused rejection tests, and updates
to `docs/protocol-v1.md`, `docs/threat-model.md`, and `docs/audit-model.md` as
applicable.
