#!/usr/bin/env bash
set -euo pipefail

readonly expected_audit_version="cargo-audit-audit 0.22.2"
readonly lockfile="src-tauri/Cargo.lock"

if ! command -v cargo-audit >/dev/null 2>&1; then
  echo "cargo-audit is required; install exactly 0.22.2 with --locked" >&2
  exit 1
fi

actual_audit_version="$(cargo audit --version)"
if [[ "$actual_audit_version" != "$expected_audit_version" ]]; then
  echo "expected $expected_audit_version, found $actual_audit_version" >&2
  exit 1
fi

cargo audit --file "$lockfile"
