# OTPBar current-state audit

**Date:** 2026-07-23
**Audited revision:** `6f2659b` plus the uncommitted working tree present at
the start of the audit
**Scope:** product behavior, security/privacy, Rust/Tauri architecture,
React/UI architecture, UX/accessibility, tests, CI, release, and documentation

## Executive assessment

OTPBar has a coherent product idea and a small enough surface to modernize
without a rewrite. It also has several release-blocking correctness and
security defects. The current architecture concentrates most behavior in one
polling loop and exposes shared state as a bag of mutexes; the UI then mirrors
backend commands without owning a reliable desktop-session model. This makes
the dangerous edge cases—overlapping clipboard writes, authorization
lifecycle, repeated unread messages, and destructive state reconciliation—the
least testable parts of the product.

Do not ship the current working tree as a production update. Stabilize the
security and lifecycle invariants first, deepen the core modules behind small
interfaces, and redesign the popover on top of those trustworthy states.

## Quality-gate baseline

| Gate | Result | Notes |
|---|---|---|
| `npm run build` | Pass | TypeScript and Vite build; 213.95 kB JS before gzip |
| `cargo test` | Pass | 22 integration tests; 0 unit tests in crate targets |
| strict `cargo clippy --all-targets -- -D warnings` | Fail | `unused_mut` in `oauth_integration_test.rs:64` |
| `npm audit --omit=dev` | Pass | No reported production dependency vulnerabilities |
| Frontend lint | Missing | No `lint` script; CI suppresses the failure |
| Frontend tests | Missing | No unit, integration, accessibility, or E2E suite |
| Native E2E | Missing | No automated tray/window/auth/clipboard coverage |
| Release workflow | Fail by inspection | Uses absent `electron-builder` in a Tauri repository |
| Local release verifier | Fail by inspection | Calls nonexistent `npm run dist` |

## Release blockers

### RB-01 — Clipboard expiry can destroy newer or unrelated clipboard data

**Files:** `src-tauri/src/main.rs:390-409, 460-494`

Both automatic and manual copy paths spawn independent timers that
unconditionally replace the clipboard with an empty string. An older timer can
erase a newer OTP, and any timer can erase content the user copied from another
application after OTPBar wrote its code.

**Required disposition:** replace both implementations with one Clipboard Lease
module. A lease must be cancellable/replaced, must clear only if it is still the
active lease, and must verify that OTPBar still owns the clipboard contents.

### RB-02 — Native OAuth omits required protections

**Files:** `src-tauri/src/gmail.rs:105-111`,
`src-tauri/src/oauth_server.rs:156-189`, `src-tauri/src/main.rs:428-458`

The authorization request has no PKCE challenge and no `state`; the callback
validates neither. It uses a fixed `localhost:8234` redirect, does not
URL-decode callback values, and reflects the provider's error string into HTML
without escaping it. The Gmail client also treats a distributed
`client_secret` as part of the desktop configuration even though an installed
application cannot keep it confidential.

RFC 8252 requires PKCE for public native clients, recommends a high-entropy
`state`, and recommends loopback IP literals with an ephemeral port. Google's
installed-app guidance describes PKCE and requires CSRF protection.

**Required disposition:** implement Authorization as a state machine that owns
PKCE, state, redirect URI, callback lifetime, cancellation, token exchange,
refresh, Keychain persistence, and sign-out. Bind before returning success,
use `127.0.0.1` or `[::1]` with an ephemeral port where supported, HTML-escape
all callback output, and return structured errors.

### RB-03 — Unread messages can be repeatedly copied and notified

**Files:** `src-tauri/src/main.rs:238-337`

Gmail returns up to 25 unread messages, but duplicate detection checks only the
10 entries retained for display. Once an OTP falls out of that list, the same
still-unread Gmail message can be rediscovered on every poll. OTPBar has
read-only Gmail scope and cannot rely on marking messages read.

**Required disposition:** separate the Seen Message ledger from Recent Codes.
Seen-message retention and recent-code display retention need independent,
explicit policies and tests.

### RB-04 — Distribution automation does not describe this project

**Files:** `.github/workflows/release.yml`, `verify-build.sh`

The tag workflow runs `npx electron-builder`, but OTPBar uses Tauri and does not
depend on electron-builder. It expects `dist/*.dmg`, while the README documents
Tauri's bundle path. The local verification script calls nonexistent
`npm run dist`. The build workflow declares a top-level `description` key that
must be validated against the GitHub Actions schema.

**Required disposition:** replace release automation with a signed/notarized
Tauri build, exercise the exact artifact in CI, and make the local verifier call
the same gates. Test installation and update behavior on a clean macOS runner.

### RB-05 — Tauri's CSP protection is disabled

**File:** `src-tauri/tauri.conf.json:30-32`

`"csp": null` disables a containment layer that Tauri documents as protection
against webview injection. This amplifies the impact of frontend injection and
is especially inappropriate while the local OAuth response has an HTML
injection path.

**Required disposition:** define the narrowest production CSP compatible with
local assets and Tauri IPC; define explicit capabilities and verify command
exposure.

## High-priority correctness findings

### C-01 — Polling has no stop/restart lifecycle

`is_polling` is set once and never reset. Sign-out clears credentials but leaves
the loop alive, so it continues attempting unauthenticated reads and prevents a
clean lifecycle restart. Polling should be owned by the OTP Intake module and
be cancellable on sign-out, shutdown, and authorization replacement.

### C-02 — Long-lived mutex guards block unrelated operations

`start_auth` holds `gmail_client` while the user is in the browser for up to
five minutes. Polling holds the same mutex across the Gmail list request and up
to 25 sequential detail requests. Status and sign-out commands can stall behind
network or user latency.

### C-03 — Durable history races with startup intake

History loading and Gmail restoration/poll startup are separate spawned tasks.
A newly detected code can be inserted and then overwritten by the delayed
history assignment. Durable state must load before intake starts.

### C-04 — History has conflicting policies and weak durability

The live list truncates to 10, disk storage truncates to 50, and Privacy reports
50 retained forever. Startup can load more entries than the live list normally
shows. Writes are non-atomic and unversioned; parse and write failures are
reduced to empty/default state or logs.

### C-05 — Gmail status and MIME handling lose correctness

Only a list-level 429 receives a distinct error. Other HTTP failures are parsed
as success-model JSON, detail failures are skipped, and partial fetches look
successful. MIME extraction takes the first non-empty body without considering
content type or charset. The final generic six-digit pattern can match dates,
orders, phone fragments, or quoted older messages.

### C-06 — Destructive history state is not reconciled

The clear-history command clears backend memory and disk but emits no new code
snapshot. The React app retains its old list. The behavior is reproduced in
the [dogfood report](../audit/dogfood/report.md).

### C-07 — Preference writes can fail while the command reports success

`save_preferences` returns `()`, logs write failures, and lets setter commands
return success. Clipboard timeout is memory-only, while auto-copy preferences
are persisted. Configuration has no single validation, migration, or failure
contract.

## Security and privacy findings

### S-01 — OTP history is plaintext and retained indefinitely

The product describes itself as privacy-focused, but OTPs, senders, providers,
timestamps, and Gmail message IDs are stored in a plaintext JSON file and the
dashboard reports retention as “Forever.” This may be an acceptable explicit
product choice, but it cannot remain an accidental default.

### S-02 — Privacy reporting masks uncertainty

Privacy duplicates scopes, Keychain item names, file policy, and retention
constants from the modules that own them. Keychain errors are converted to
`false`, which can present a reassuring but incorrect state. Privacy should be a
projection of authoritative module metadata and support partial/unavailable
values.

### S-03 — Sign-out silently couples account and local-history deletion

Sign-out deletes credentials and all recent/history codes. The UI does not
explain this destructive coupling or request confirmation. Account
disconnection and local-data deletion should be distinct user intents unless
the product deliberately specifies otherwise.

### S-04 — OAuth callback tests do not verify the security contract

There are no tests for PKCE, state mismatch, callback URL decoding, HTML
escaping, bind failure, concurrent authorization, cancellation, or Keychain
failure. Existing tests use fixed ports and sleeps; two named tests do not
assert the values implied by their names.

## Product and UX findings

The full evidence set is in the [dogfood report](../audit/dogfood/report.md).

### U-01 — The shell is visually quiet but operationally ambiguous

The main state does not show the connected account, monitoring health, last
successful sync, rate-limit/offline status, or auto-copy status. An empty list
and a stalled poller look the same.

### U-02 — Navigation consumes the narrow header

At 320 px, Settings, Privacy, Logout, and Quit sit as four equal text buttons
beside the title. They are visually undifferentiated, 24.5 px high, and leave no
room for connection or monitoring status. A compact primary view should keep
frequent actions prominent and move infrequent account/app actions into a
secondary menu.

### U-03 — Typography is too small and low-contrast for core state

The interface relies on 10–12 px labels and reduced-opacity foreground colors
over a transparent gradient. Automated contrast evaluation is inconclusive
because the effective background depends on desktop content; production must
test worst-case wallpapers and Increase Contrast/Reduce Transparency modes.

### U-04 — The only exposed setting is incomplete and inaccessible

The Auto-copy switch has no accessible name. Backend commands exist for
provider-specific auto-copy and clipboard timeout but the UI exposes neither.
The settings view has no save/error status beyond replacing the whole view.

### U-05 — Copy success and failure are unreliable

Manual copy errors are only logged to the console. The countdown is independently
reconstructed in each CodeCard instead of observing clipboard ownership.
Multiple cards can therefore show UI states that disagree with the real
clipboard.

### U-06 — Privacy emphasizes implementation trivia over user control

It exposes clipped filesystem paths, raw OAuth scope URLs, token presence, and
a history-size progress bar, but offers no retention choice, Reveal in Finder,
copy value, disconnect-without-delete, or delete-without-disconnect flow.

### U-07 — Error handling discards usable modules

If either startup request fails, the complete app shell is replaced by a
generic retry screen. Authentication, Quit, Settings, and diagnostics disappear
even when they remain usable. Module failures should degrade locally.

### U-08 — Missing production states

There is no designed state for authorization cancellation, missing OAuth
configuration, offline mode, permission denial, rate limiting/backoff, stale
monitoring, partial Gmail failure, clipboard ownership loss, storage failure,
update availability, or unsupported macOS versions.

## Architecture findings and target deepening opportunities

The repository has no `CONTEXT.md` and no ADRs. Establish domain language before
changing module seams.

1. **OTP Intake module**
   - Own poll lifecycle, backoff, message acceptance, deduplication, policy
     decisions, and output publication.
   - Concentrates bugs and tests now spread through `main.rs`.
2. **Authorization module**
   - Own restore, sign-in, cancel, sign-out, PKCE/state, callback lifetime,
     token refresh, and credential storage.
3. **Email Interpretation module**
   - Normalize MIME email into a domain representation and classify it as a
     Detected OTP or a reason for rejection.
4. **Recent Code History module**
   - Own ordering, capacity, durable schema, migration, atomic writes,
     corruption, clearing, and actual policy metadata.
5. **Seen Message Ledger module**
   - Track Gmail messages independently from the display list so read-only
     polling is idempotent.
6. **Clipboard Lease module**
   - Own copy, replacement, cancellation, expiry, content ownership, and
     authoritative status events.
7. **Settings module**
   - Own defaults, validation, persistence, migrations, and coherent snapshots
     consumed by intake and clipboard modules.
8. **Desktop Session module**
   - Replace the shallow TypeScript invoke mirror with one frontend state model
     that reconciles command results and events through a typed contract.
9. **Privacy Projection module**
   - Compose non-secret metadata from owning modules instead of duplicating
     constants or swallowing failures.

These changes increase **locality** by putting each invariant in one
implementation and increase **leverage** by giving Tauri commands, React, and
tests a smaller interface. The interface—not internal functions—becomes the
test surface.

## Test and quality-system gaps

- No end-to-end intake tests for dedupe, ordering, backoff, sign-out lifecycle,
  per-provider policy, notifications, events, or partial mailbox failure.
- No realistic Gmail fixture tests for multipart/alternative, nested MIME,
  HTML-only mail, charset/base64 failure, pagination, or status mapping.
- OTP tests are positive-heavy; no adversarial false-positive corpus or
  multi-candidate ranking.
- No history/settings tests for capacity, migration, corruption, atomicity, IO
  failure, or persistence error propagation.
- No clipboard race tests with a fake clock and clipboard adapter.
- No frontend tests for partial startup, event cleanup, auth/logout failure,
  clear-history reconciliation, settings rollback, or copy status.
- No automated accessibility, keyboard, reduced-motion, reduced-transparency,
  high-contrast, or native VoiceOver coverage.
- CI has no effective frontend lint gate and does not prove the release
  artifact can launch or install.

## Documentation and product-contract gaps

- README says 10 recent codes while Privacy reports a 50-entry disk history.
- The advertised macOS 10.13 minimum is not demonstrated by CI or a release
  compatibility matrix.
- Quick Start requires every user to create Google credentials; the product
  does not define how distributed builds receive a client ID or how OAuth app
  verification is handled.
- Project structure and architecture notes do not describe the current privacy,
  settings, backoff, persistence, or release behavior.
- There is no privacy policy, data-handling statement, threat model, support
  path, release signing/notarization guide, or recovery guide.

## Recommended sequence

1. Freeze release and record product/security decisions.
2. Fix Authorization, Clipboard Lease, Seen Message Ledger, CSP, and release
   automation.
3. Establish domain language and deepen Intake, Interpretation, History,
   Settings, Desktop Session, and Privacy Projection.
4. Add deterministic backend, contract, frontend, accessibility, and native E2E
   gates.
5. Redesign the menubar experience around authoritative monitoring,
   authorization, and clipboard states.
6. Migrate durable data, ship a signed beta, validate on supported macOS
   versions, then promote.

## Primary external references

- [RFC 8252: OAuth 2.0 for Native Apps](https://www.rfc-editor.org/info/rfc8252/)
- [Google OAuth 2.0 for iOS and desktop apps](https://developers.google.com/identity/protocols/oauth2/native-app)
- [Tauri Content Security Policy](https://v2.tauri.app/security/csp/)
