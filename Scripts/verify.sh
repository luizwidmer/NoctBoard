#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Luiz Widmer
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail

NOCTBOARD_EXPECTED_NOCTWEAVE_REVISION="41a874fc68dc87898f7406b23d290b308364442b"

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
  swift package resolve
  git diff --exit-code -- Package.resolved
fi

swift build
swift test
NOCTBOARD_RUN_RELAY_INTEGRATION=1 swift test -c release
swift run -c release NoctBoardDemo
git diff --check
