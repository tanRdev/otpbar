#!/usr/bin/env bash
set -euo pipefail

readonly expected_audit_version="cargo-audit-audit 0.22.2"
readonly manifest="src-tauri/Cargo.toml"
readonly lockfile="src-tauri/Cargo.lock"
readonly ignored_quick_xml="quick-xml@0.37.5"

if ! command -v cargo-audit >/dev/null 2>&1; then
  echo "cargo-audit is required; install exactly 0.22.2 with --locked" >&2
  exit 1
fi

actual_audit_version="$(cargo audit --version)"
if [[ "$actual_audit_version" != "$expected_audit_version" ]]; then
  echo "expected $expected_audit_version, found $actual_audit_version" >&2
  exit 1
fi

# These two advisories are ignored only for quick-xml 0.37.5, which is locked
# behind the Windows-only tauri-winrt-notification crate. otpbar ships macOS
# artifacts. Fail closed if the version or reverse-dependency chain changes so
# the exception cannot silently begin covering an applicable dependency.
ignored_chain="$(
  cargo tree \
    --manifest-path "$manifest" \
    --target all \
    --invert "$ignored_quick_xml" \
    --prefix none
)"
readonly expected_chain='quick-xml v0.37.5
tauri-winrt-notification v0.7.2
notify-rust v4.18.0
tauri-plugin-notification v2.3.3'
if [[ "$(printf '%s\n' "$ignored_chain" | wc -l | tr -d ' ')" != "5" ]]; then
  echo "RustSec exception dependency chain changed; refusing to audit with ignores" >&2
  exit 1
fi
if [[ "$(printf '%s\n' "$ignored_chain" | sed '$d')" != "$expected_chain" ]]; then
  echo "RustSec exception dependency chain changed; refusing to audit with ignores" >&2
  exit 1
fi
ignored_root="$(printf '%s\n' "$ignored_chain" | tail -n 1)"
case "$ignored_root" in
  "otpbar v1.0.0 ("*"/src-tauri)") ;;
  *)
    echo "RustSec exception is no longer rooted only in otpbar; refusing ignores" >&2
    exit 1
    ;;
esac

for shipped_target in aarch64-apple-darwin x86_64-apple-darwin; do
  applicable_chain="$(
    cargo tree \
      --manifest-path "$manifest" \
      --target "$shipped_target" \
      --invert "$ignored_quick_xml" \
      --prefix none \
      2>/dev/null
  )"
  if [[ -n "$applicable_chain" ]]; then
    echo "RustSec exception became reachable on $shipped_target; refusing ignores" >&2
    exit 1
  fi
done

audit_report="$(mktemp "${TMPDIR:-/tmp}/otpbar-cargo-audit.XXXXXX")"
trap 'rm -f "$audit_report"' EXIT
set +e
cargo audit --file "$lockfile" --json >"$audit_report"
audit_exit=$?
set -e

# cargo-audit exits 1 when it successfully reports vulnerabilities. Any other
# status is an execution failure, even if it happened to emit parseable JSON.
if [[ "$audit_exit" -ne 1 ]]; then
  echo "expected cargo-audit to report the two reviewed records; exit was $audit_exit" >&2
  exit 1
fi

node scripts/validate-rust-audit.mjs "$audit_report"
