<a id="v1-fixture-generation"></a>

<h1 align="center">Noct Board v1 fixtures</h1>

<p align="center"><strong>Deterministic examples for projection and audit consumers.</strong></p>

<p align="center">
  <a href="#overview">Overview</a> ·
  <a href="#getting-started">Getting started</a> ·
  <a href="#reference">Reference</a> ·
  <a href="#related-documentation">Related docs</a>
</p>

## Overview

These fixtures come from the demo executable, not from live board state.
Use them to exercise projection and redacted-audit readers without importing
real board credentials.

## Getting started

From the **Noct Board repository root**:

```sh
swift run noctboard demo
swift run noctboard export-demo-audit -
```

## Reference

Expected projection digest:

```text
6b43a954bd77ed90289d1502b14584e6edc1300ddf1361a2f50536f811dbc2f0
```

The audit has seven accepted application events, two rejected application
events, one container rejection, zero history attestations, and no board
plaintext. Transport tests separately construct signed-event and late-join
history records because fixture private keys must never be mistaken for live
board credentials.

## Related documentation

| Read | For |
| --- | --- |
| [Project overview](../../README.md) | Setup and evaluation boundaries |
| [Audit model](../../docs/audit-model.md) | Evidence semantics and limits |
| [CLI guide](../../CLI_GUIDE.md) | Export and inspect an audit |
