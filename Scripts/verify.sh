#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Luiz Widmer
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail

NOCTBOARD_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$NOCTBOARD_ROOT"

NOCTBOARD_SWIFT_FLAGS=(--disable-automatic-resolution)
# --offline requires existing lockfile/checkouts instead of re-resolving them.
if (( $# > 1 )) || [[ $# == 1 && "${1:-}" != "--offline" ]]; then
  echo "Usage: Scripts/verify.sh [--offline]" >&2
  exit 2
fi

NOCTBOARD_EXPECTED_NOCTWEAVE_REVISION="7ffaff6b74d8ede577a130f1d88275a3066d0fd3"

for NOCTBOARD_PIN_FILE in Package.swift Package.resolved; do
  if ! grep -Fq "${NOCTBOARD_EXPECTED_NOCTWEAVE_REVISION}" "${NOCTBOARD_PIN_FILE}"; then
    echo "${NOCTBOARD_PIN_FILE} does not contain the expected Noctweave revision." >&2
    exit 2
  fi
done

if [[ -n "${NOCTWEAVE_PACKAGE_PATH:-}" && ! -f "${NOCTWEAVE_PACKAGE_PATH}/Package.swift" ]]; then
  echo "NOCTWEAVE_PACKAGE_PATH does not contain Package.swift: ${NOCTWEAVE_PACKAGE_PATH}" >&2
  exit 2
fi

if [[ -n "${NOCTWEAVE_PACKAGE_PATH:-}" ]]; then
  NOCTBOARD_LOCAL_NOCTWEAVE_REVISION="$(git -C "${NOCTWEAVE_PACKAGE_PATH}" rev-parse HEAD 2>/dev/null || true)"
  if [[ "${NOCTBOARD_LOCAL_NOCTWEAVE_REVISION}" != "${NOCTBOARD_EXPECTED_NOCTWEAVE_REVISION}" && "${NOCTBOARD_ALLOW_UNPINNED_NOCTWEAVE:-0}" != "1" ]]; then
    echo "Local Noctweave revision must equal ${NOCTBOARD_EXPECTED_NOCTWEAVE_REVISION}." >&2
    echo "Set NOCTBOARD_ALLOW_UNPINNED_NOCTWEAVE=1 only for deliberate dependency development." >&2
    exit 2
  fi
  if [[ -n "$(git -C "${NOCTWEAVE_PACKAGE_PATH}" status --porcelain --untracked-files=no -- . 2>/dev/null)" && "${NOCTBOARD_ALLOW_UNPINNED_NOCTWEAVE:-0}" != "1" ]]; then
    echo "Local Noctweave checkout has tracked changes; publication verification requires the clean public pin." >&2
    exit 2
  fi
else
  if [[ $# == 0 ]]; then
    swift package resolve
  fi
  git diff --exit-code -- Package.resolved
fi

swift build "${NOCTBOARD_SWIFT_FLAGS[@]}"
swift test "${NOCTBOARD_SWIFT_FLAGS[@]}"
NOCTBOARD_RUN_RELAY_INTEGRATION=1 swift test "${NOCTBOARD_SWIFT_FLAGS[@]}" -c release
swift run "${NOCTBOARD_SWIFT_FLAGS[@]}" -c release NoctBoardDemo
git diff --check
