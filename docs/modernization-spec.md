# OTPBar v2 modernization specification

**Status:** Approved for implementation

**Date:** 2026-07-23

**Scope:** macOS 13+, Gmail-only, React 19 + Tauri 2

**Inputs:** [current-state audit](current-state-audit.md), [dogfood report](../audit/dogfood/report.md), and [domain language](../CONTEXT.md)

## 1. Executive decision record

OTPBar v2 is a security-first modernization, not a rewrite. The current release is frozen until the five release blockers in the audit are closed. Work proceeds in this order: secure Authorization and clipboard behavior; make ingestion and local state deterministic; establish the typed Desktop Session; redesign the popover; then sign, notarize, and validate the shipped artifact.

The binding product decisions are:

- Gmail is the only Mailbox implementation in v2; a narrow Mailbox seam permits later adapters without speculative framework code.
- History is local, encrypted, capped at 50 Recent Codes, defaults to 7 days, and supports Off, 1 day, 7 days, or 30 days. Legacy plaintext is migrated and securely removed on successful migration. There is no cloud sync.
- Auto-copy is off until explicit onboarding consent. After consent, a global setting and Provider overrides are allowed.
- The popover is adaptive from the current 320 × 420 footprint toward a 360 × 500 target, bounded to the active screen.
- Native OAuth is a public-client Authorization Code flow with PKCE, state, and an ephemeral loopback IP callback. No distributed secret is confidential.
- v2 supports macOS 13 and later. Windows, Linux, mobile, additional mailbox vendors, cloud sync, and a React/Tauri rewrite are excluded.

The durable rationale is recorded in [ADRs](adr/). Security and correctness requirements are release gates, not backlog preferences.

## 2. Product definition and domain language

OTPBar is a compact macOS menubar utility for people who receive one-time passcodes in Gmail and want quick access without surrendering control of sensitive local data or their clipboard.

The canonical vocabulary is defined in [CONTEXT.md](../CONTEXT.md). Particularly:

- **Provider** means the service a code is for, not Gmail.
- **Seen Message** means a Message already considered, not a Gmail read/unread flag.
- **History** is retained user data; **Recent Code** is a presented item within that policy.
- **Clipboard Lease** is authoritative ownership, not a visual countdown.
- **Desktop Session** is the single coherent product state consumed by the UI.

Success means a user can tell, within the popover, which Mailbox is authorized, whether monitoring is trustworthy, what OTPBar did with the clipboard, and how to recover from a failure.

## 3. Current-state audit

The [audit](current-state-audit.md) is the evidence baseline. The current product cannot be released because:

1. clipboard expiry can delete a newer or unrelated clipboard value;
2. OAuth lacks PKCE, state, safe callback handling, and a public-client model;
3. still-unread Messages can repeatedly trigger copies and notifications;
4. release automation builds the wrong technology;
5. Tauri CSP is disabled.

Correctness is further weakened by an unstoppable poll loop, locks held across network/user latency, startup races, conflicting History policies, lossy Gmail/MIME handling, stale destructive-state UI, and preference writes that report false success. Privacy claims contradict plaintext indefinite retention and conceal uncertainty. The existing shell omits operational state, has undersized/unlabelled controls, and fails as a whole when one module fails.

The [dogfood report](../audit/dogfood/report.md) provides reproducible UI evidence for stale History, an unnamed Auto-copy control, undersized controls, an ambiguous empty state, whole-shell startup failure, and unrecoverable truncated privacy values.

## 4. Target user journeys and production states

### 4.1 Journeys

**First launch.** The shell opens without credentials, explains read-only Gmail access and local data handling, checks OS/configuration support, and offers **Connect Gmail**. Authorization is a cancellable step. After success, onboarding asks separately for Auto-copy consent; declining leaves monitoring and manual copy fully functional. The user chooses History retention, defaulting to 7 days.

**Healthy monitoring.** The main view shows the authorized Gmail address, Monitoring Health, last successful check, next/retry context when relevant, and Auto-copy state. With no Recent Codes it explains that monitoring is healthy and offers a compact recovery hint.

**Code arrival.** An accepted Detected OTP appears once, newest first. A notification contains Provider context but not the code. Auto-copy occurs only if consent and effective policy allow it. The UI announces the arrival and copy outcome without stealing focus.

**Manual copy and expiry.** Copy creates/replaces one Clipboard Lease and exposes its remaining lifetime. Expiry clears only if OTPBar still owns exactly that value. Copying elsewhere ends ownership and the UI changes to “Clipboard changed”; it never clears the new content.

**Missing code.** The user can check now, inspect Monitoring Health, and see actionable offline, rate-limit, partial-fetch, or stale states. A failed Message never masquerades as a healthy full check.

**Settings and privacy.** Settings expose global Auto-copy, Provider overrides, lease duration, History retention, notification preference, and start-at-login if supported. Privacy reports authoritative access, storage, retention, and health metadata with unknown values shown as unknown. Paths are selectable/copyable and revealable in Finder.

**Disconnect and delete.** Disconnecting Gmail revokes local credentials and stops monitoring but preserves History. Deleting History requires confirmation and leaves Authorization intact. A combined “Disconnect and delete local data” action is explicit and confirmed.

**Update.** A signed update can be announced without blocking code access. Install is user-initiated; failure preserves the running version and gives a support path.

### 4.2 Complete production-state contract

| Area | States the UI must represent | Required action or message |
|---|---|---|
| Compatibility | supported; unsupported macOS; missing build configuration | Continue; explain macOS 13 floor; developer/release remediation |
| Onboarding and consent | first launch; consent unknown; consent granted; consent declined; revisit | Explain Gmail access, History, and Auto-copy separately; require an explicit choice before Auto-copy can run; preserve full manual-copy/monitoring use after decline; let the user revisit consent from Settings |
| Authorization | unknown/restoring; disconnected; starting; awaiting browser; exchanging; connected; cancelled; denied; callback invalid; configuration missing; credential store unavailable; refresh required; failed | Never blank the shell; offer cancel/retry/disconnect as applicable |
| Monitoring Health | stopped; checking; healthy; stale; offline; rate-limited with retry time; partially degraded; permission denied; unavailable | Show last success, affected scope, and safe recovery |
| Intake | idle; fetching; no new Messages; new Detected OTP; rejected candidates; partial fetch | Publish a coherent session revision; do not repeat effects |
| History | loading; ready empty; ready populated; retention Off; migrating; clearing; storage unavailable; corrupted/quarantined; write failed | Preserve usable modules and expose retry/recovery |
| Clipboard Lease | idle; copying; owned with expiry; replaced; expired and cleared; ownership lost; permission denied; write failed; clear failed | One authoritative status; never imply ownership after loss |
| Notification permission | unknown/not requested; requesting; granted; denied; unavailable/error | Ask only from a user action with preflight context; show the OS result; after denial keep intake usable and link to System Settings; on unavailable/error explain that notification delivery is degraded and offer retry when safe |
| Settings | loading; ready; saving; saved; validation failed; persistence failed | Optimistic UI must roll back or reconcile from returned snapshot |
| Privacy | loading; ready; partially unknown; unavailable | Label uncertainty; never convert errors into reassuring falsehoods |
| Connectivity | online; offline; restored | Preserve local functions and automatically resume bounded checks |
| Update | unknown; current; available; downloading; ready; install failed; unsupported release | Non-blocking status and recovery |
| Desktop Session | booting; usable; degraded; terminating | Quit and diagnostics remain available in every usable/degraded state |

## 5. Target experience and visual system

### 5.1 Information architecture

The primary view contains, in order: compact identity/health header; newest Recent Codes; contextual empty/error content; and a single secondary menu. Manual copy is the primary action. Settings, Privacy, Disconnect, and Quit move out of equal-weight header buttons into the menu. Destructive actions remain visually and spatially separated.

The popover starts at the smallest usable size and may adapt up to roughly 360 × 500, never exceeding the current screen's visible frame. Long content scrolls inside a stable shell; the menubar anchor and primary status remain visible. The design is compact and native-feeling, with restrained opaque/vibrant materials that remain legible against worst-case light and dark wallpapers. It must not use a generic gradient, card dashboard, or ornamental glassmorphism.

### 5.2 Visual and interaction requirements

- **UX-01:** Monitoring Health and authorized Mailbox identity are visible on the main view without navigation.
- **UX-02:** Every state in section 4.2 has designed copy, status treatment, and at least one valid next action when recovery is possible.
- **UX-03:** The UI uses a 4 px base spacing rhythm, no core text below 12 px, body text at least 13 px, and primary values at least 14 px.
- **UX-04:** Interactive targets are at least 28 × 28 CSS px; primary and destructive controls are at least 32 px high with 8 px minimum separation.
- **UX-05:** Success feedback persists for at least 2 seconds; transient errors persist until dismissed or superseded by a confirmed success.
- **UX-06:** Destructive History and combined disconnect/delete operations require a confirmation that names what is retained and removed.
- **UX-07:** Module failures degrade locally. Account, Quit, settings navigation, and unaffected Recent Codes remain available.
- **UX-08:** Exact privacy paths and values are selectable, copyable, and available via Reveal in Finder where a local path exists.
- **UX-09:** The History list shows no more than 50 items and virtualizes or incrementally renders if measurement shows frame degradation.

### 5.3 Accessibility requirements

- **A11Y-01:** All controls have programmatic names, roles, values/states, and visible focus indicators; the Auto-copy control exposes its checked state.
- **A11Y-02:** The entire app is operable by keyboard with logical order, Escape/back behavior, no focus traps, and focus restored to the invoking control.
- **A11Y-03:** Text and icons meet WCAG 2.2 AA contrast against measured effective backgrounds, including Increase Contrast and Reduce Transparency.
- **A11Y-04:** Status changes use polite live announcements; errors are associated with their controls; OTP values are not unexpectedly announced in notifications.
- **A11Y-05:** Reduced Motion eliminates non-essential motion. Text remains usable at 200% zoom and the popover adapts without clipping.
- **A11Y-06:** VoiceOver on macOS can identify Authorization, Monitoring Health, each Provider/code/time, copy status, setting, menu item, confirmation, and error.

## 6. Functional and performance requirements

### 6.1 Authorization and lifecycle

- **FR-01:** Restore credentials before monitoring starts. At most one Authorization attempt exists; a new attempt cancels and closes the prior callback.
- **FR-02:** Sign-out cancels intake and token work within 1 second, removes credentials, publishes disconnected state, and allows a clean reauthorization without restart.
- **FR-03:** Disconnect, delete History, and combined disconnect/delete are distinct intents and idempotent.
- **FR-04:** No mutex/lock is held while waiting for browser interaction, network I/O, clipboard I/O, or durable storage.

### 6.2 Mailbox, interpretation, and intake

- **FR-05:** The Gmail adapter uses read-only scope, requests bounded pages, maps every non-2xx response into a typed error, and distinguishes permission, authentication, rate-limit, offline, server, malformed, and partial-fetch outcomes.
- **FR-06:** A check returns a completeness marker. Any failed Message detail fetch produces partial Monitoring Health and is eligible for bounded retry; it is not marked Seen until the acceptance/rejection decision completes.
- **FR-07:** Interpretation supports nested multipart messages, prefers decoded `text/plain` then sanitized text from `text/html`, respects declared charset when supported, rejects invalid encoding explicitly, and excludes quoted/replied content where possible.
- **FR-08:** Detection ranks candidates using message context and Provider patterns. The generic numeric fallback requires OTP language proximity and accepts 4–8 digits; dates, phone fragments, currency, order/tracking numbers, and quoted older codes form a mandatory negative corpus.
- **FR-09:** The Seen Message ledger is independent of History and presentation capacity. A successfully considered Gmail Message causes at most one notification and one Auto-copy effect across restarts while its ledger entry is retained.
- **FR-10:** Seen Messages are retained for 30 days with a 10,000-entry hard cap, pruning oldest entries after each committed check. This policy is internal idempotency state and is unaffected by History Off or History clearing.
- **FR-11:** Intake has one cancellable owner, uses an 8-second healthy interval with ±10% jitter, exponential backoff from 15 seconds to 15 minutes, honors `Retry-After`, resets after a successful complete check, and stops on disconnect/shutdown.
- **FR-12:** Recent Codes are newest first, uniquely keyed by source Message, capped at 50, immediately filtered by retention, and published as a complete snapshot after every mutation.

### 6.3 History, settings, notification, and clipboard

- **FR-13:** History defaults to encrypted 7-day retention and offers only Off, 1, 7, or 30 days. Off removes durable Recent Codes and prevents future History writes without clearing the Seen Message ledger.
- **FR-14:** Every durable mutation is atomic and returns a typed success snapshot or error; commands never report success after a failed write.
- **FR-15:** Auto-copy is ineligible until onboarding records explicit consent. Thereafter effective policy is `global enabled AND provider override`, where a missing Provider override inherits global and an explicit false disables that Provider.
- **FR-16:** Provider overrides cannot enable Auto-copy when global Auto-copy is off or consent is absent. Revoking consent disables and removes all overrides.
- **FR-17:** Manual copy is always available for a visible Recent Code. Both manual and automatic copy use the same Clipboard Lease service.
- **FR-18:** A new copy cancels/replaces the active Clipboard Lease. Expiry clears only if lease identity is active and current clipboard content exactly matches the value OTPBar wrote; otherwise it publishes ownership lost and does not mutate the clipboard.
- **FR-19:** Lease duration is validated to 15, 30, or 60 seconds, default 30. Shutdown cancels the timer but does not clear clipboard content unless the same ownership check succeeds.
- **FR-20:** Notifications are opt-in at the OS level, never contain the OTP value, and occur once per Detected OTP. Permission denial is visible but does not affect intake.
- **FR-21:** Clearing History publishes one Desktop Session snapshot showing the empty state before the command resolves.

### 6.4 Desktop Session contract

- **FR-22:** The frontend receives a versioned full Desktop Session snapshot at startup and monotonic revisioned domain events thereafter. Event application is idempotent; a revision gap triggers snapshot refresh.
- **FR-23:** Commands use a discriminated success/error envelope with stable machine codes, user-safe messages, retryability, and optional field context. Rust and TypeScript types are generated or contract-tested from one schema.
- **FR-24:** Event listeners are registered once and disposed on unmount/reload. Command results reconcile through the same session reducer as events.
- **FR-25:** Privacy is a projection of metadata from Authorization, History, Settings, Seen Message, and Clipboard owners. Unknown/unavailable is preserved and secrets/OTP values are excluded.

### 6.5 Performance and reliability

- **PERF-01:** On supported hardware, tray click to interactive cached shell is ≤200 ms at p95; cold launch to interactive shell is ≤1.5 seconds at p95, excluding Authorization/network completion.
- **PERF-02:** A complete Gmail check of 25 Messages finishes within 5 seconds at p95 on a 100 ms-latency test network and uses at most 4 concurrent detail requests.
- **PERF-03:** Local settings/History commands complete within 100 ms at p95 for 50 Recent Codes; encrypted store migration completes within 2 seconds or reports progress/failure.
- **PERF-04:** Idle CPU averages <1% over 5 minutes between checks and steady-state memory remains <120 MB on the oldest supported macOS test host.
- **PERF-05:** No network, storage, or browser wait blocks another command for more than 100 ms. Intake retries are cancellable and do not multiply after sleep/wake or reconnect.

## 7. Security and privacy requirements

- **SEC-01:** Authorization uses a fresh PKCE verifier/challenge and at least 128 bits of unpredictable state per attempt. Callback state is compared in constant time before code exchange.
- **SEC-02:** The callback binds `127.0.0.1` or `[::1]` on port `0` before the browser opens, accepts only the expected path/method/host, URL-decodes parameters once, limits request size/time, serves one terminal callback, and then closes.
- **SEC-03:** Callback HTML uses fixed templates with context-correct escaping and no remote assets. Provider errors are mapped to safe text; raw values are never reflected.
- **SEC-04:** OTPBar is a public client. A client ID may be build configuration; no client secret is logged, stored as a secret, or required as proof of client identity.
- **SEC-05:** Access/refresh credentials reside in macOS Keychain with the narrowest practical accessibility. Logs expose neither credentials, Authorization codes, PKCE verifier, OTP values, raw Message bodies, nor raw Message IDs.
- **SEC-06:** History encryption uses an authenticated-encryption construction with a random nonce per write and a non-exportable random key stored in Keychain. Ciphertext has versioned associated metadata; authentication failure never yields partial plaintext.
- **SEC-07:** Successful plaintext migration atomically commits encrypted History, verifies it can be read, removes `code_history.json`, and fsyncs the containing directory where supported. On failure, plaintext remains in place, intake does not overwrite it, and the UI reports recovery steps.
- **SEC-08:** No OTPBar History, settings, telemetry, Message content, or clipboard content is cloud-synced or sent outside the Gmail API and OS services required by the feature. v2 adds no analytics.
- **SEC-09:** Tauri production CSP defaults to self-only local assets, disallows remote scripts/styles and unsafe evaluation, and permits only IPC/resources proven necessary. Capabilities expose each command/plugin only to the main window and minimum permission set.
- **SEC-10:** Disconnect removes all OAuth credentials; delete History removes encrypted and legacy History; “delete all local data” additionally removes settings, consent, Seen Message ledger, encryption key, and cached metadata. Each operation verifies and reports partial failure.
- **SEC-11:** Logs use structured machine codes and redacted identifiers. Support bundles require explicit user action, preview their contents, and exclude secrets and OTPs.
- **SEC-12:** Release artifacts are Developer ID signed, hardened-runtime enabled, notarized, stapled, and verified before publication. Update metadata is signed and transported over TLS.

Threats explicitly covered are callback interception/CSRF, distributed-secret misconception, token disclosure, local History disclosure/tampering, webview injection, clipboard races, repeated-message side effects, log leakage, and malicious/invalid update artifacts.

## 8. Target architecture

The application remains React + Tauri. Tauri commands are thin adapters; domain modules own invariants and expose narrow interfaces. Side effects are injected behind testable ports.

| Module | Owns | Conceptual interface |
|---|---|---|
| Authorization | attempt state, PKCE/state, callback lifetime, token refresh, credential persistence, disconnect | `restore`, `begin`, `cancel`, `disconnect`, `status`; emits Authorization changes |
| Mailbox (Gmail adapter) | Gmail query, paging, status mapping, raw Message retrieval | `identity`, `list_candidates(cursor)`, `fetch_message(id)`, `refresh_access`; returns typed completeness/errors |
| Email Interpretation | MIME normalization, candidate ranking, Provider inference, rejection reason | `interpret(Message) -> Detected OTP | Rejection` with no network/storage |
| OTP Intake | monitoring lifecycle, scheduling/backoff, acceptance transaction, effects | `start`, `check_now`, `stop`; coordinates Mailbox, ledger, History, notification, Auto-copy |
| Seen Message Ledger | durable idempotency identities and pruning | `contains`, `record_decision`, `prune`, `metadata` |
| Recent Code History | encryption, ordering, retention/capacity, migration, atomic mutation | `load`, `append`, `clear`, `set_retention`, `snapshot`, `metadata` |
| Clipboard Lease | copy ownership, replacement, expiry, status | `copy(value, source, duration)`, `cancel`, `status`; uses clock/clipboard ports |
| Settings | defaults, consent, validation, persistence, migrations | `load`, `update(expected_revision, patch)`, `reset`, `snapshot` |
| Privacy Projection | non-secret, uncertainty-preserving composition | `snapshot` from owner metadata; performs no independent storage reads |
| Desktop Session | authoritative frontend projection and revision stream | `snapshot`, command envelopes, domain events; reducer mirrors contract in React |

An intake acceptance is one logical transaction: interpret Message; determine Seen status; record the decision; append History if enabled; publish the new session; then perform eligible notification/Auto-copy effects with idempotency keys. A storage failure prevents the Message from being committed as Seen and surfaces degraded health, so effects cannot be silently repeated as “success.”

Network concurrency is bounded outside shared state locks. Module state uses actors/owned tasks or brief critical sections; cancellation tokens define shutdown, sign-out, replacement Authorization, sleep/wake, and app exit.

## 9. Data model and migrations

### 9.1 Versioned records

Durable files use an envelope containing `schema_version`, `written_at`, and the module payload. Writes use a same-directory temporary file, file sync, atomic rename, and directory sync where supported. Corrupt files are moved to a timestamped quarantine location, never silently replaced.

**Settings v2**

- `schema_version`
- `revision`
- `onboarding.auto_copy_consent`: `unknown | declined | granted`
- `auto_copy.global_enabled`
- `auto_copy.provider_overrides`: map of stable Provider key to boolean
- `clipboard_lease_seconds`: `15 | 30 | 60`
- `history_retention_days`: `0 | 1 | 7 | 30`
- `notifications_enabled`

**Encrypted History v2 plaintext payload**

- `schema_version`, `revision`
- `entries[]`: opaque ID, code, sender display, Provider key/display, received timestamp, source Message digest
- entries are ordered newest first, filtered by current time, and limited to 50 before encryption

The ciphertext envelope contains format version, algorithm identifier, key identifier, nonce, ciphertext, and associated-data version. It never duplicates plaintext metadata other than what is required to decrypt/version safely.

**Seen Message ledger v1**

- `schema_version`, `revision`
- entries: keyed digest of Mailbox identity plus Message identity, decision (`detected | rejected`), decision timestamp
- no OTP, sender, subject, or body
- pruned at 30 days and 10,000 entries

Keyed digests prevent local ledger inspection from trivially revealing raw Gmail IDs. The ledger key is stored in Keychain and separate from the History encryption key.

### 9.2 Upgrade sequence

1. Establish compatibility and load/migrate Settings. Legacy missing consent becomes `unknown`, forcing Auto-copy off; legacy `auto_copy_enabled=true` is not treated as consent.
2. Restore/generate Keychain keys.
3. Detect legacy `code_history.json`; parse and validate every entry, apply 7-day/50-entry policy, encrypt to the v2 store, read back and compare, then remove plaintext.
4. Load/prune encrypted History and ledger.
5. Restore Authorization.
6. Publish the first usable Desktop Session.
7. Start intake only after all prior steps succeed or have produced an explicit degraded state.

Unknown future schema versions are read-only failures with an “update required” state. v2 does not support downgrading durable data; a downgrade guide instructs users to delete local data after confirmation. Migration is restart-safe and idempotent. Keychain failure never causes plaintext fallback.

## 10. Verification strategy and quality gates

Tests are behavior-first and deterministic: fake clocks, clipboard, Keychain, filesystem fault injection, HTTP fixtures, and event collectors replace sleeps and live accounts wherever possible.

| Layer | Required coverage |
|---|---|
| Rust unit | PKCE/state, callback parsing/escaping, Authorization transitions; lease replacement/ownership races; retention/capacity; ledger pruning/idempotency; settings validation; backoff/cancellation; privacy uncertainty |
| Fixture/contract | Nested MIME, charset/base64 failures, HTML-only, quoted replies, adversarial numeric corpus; Gmail pagination and every HTTP mapping; Rust/TypeScript schema compatibility |
| Integration | startup ordering, migration success/failure/restart, sign-out/restart, repeated unread Message, partial fetch retry, effects after durable acceptance, clear/reconcile, CSP/capability allow/deny |
| Frontend | every section 4.2 state, revision gap refresh, partial startup, settings rollback, clear History, copy ownership loss, listener cleanup, confirmations |
| Accessibility | automated axe with zero serious/critical violations; keyboard snapshots; contrast checks; reduced motion/transparency; manual VoiceOver checklist |
| Native E2E | tray open/close, bounded adaptive window, OAuth callback lifecycle with fake provider, clipboard ownership against another app, sleep/wake, offline recovery, notification denial |
| Security | secret/log scan, CSP tests, malicious callback inputs, corrupted/tampered ciphertext, dependency audit, capability inventory |
| Release | clean macOS 13 and current macOS install/launch, signing/notarization/staple verification, update from previous signed beta, DMG checksum |

Mandatory CI gates:

1. frontend format/lint, TypeScript, tests, and production build;
2. `cargo fmt --check`, strict clippy for all targets/features, unit/integration tests;
3. contract/schema and security tests;
4. accessibility automation;
5. Tauri production build on macOS;
6. release workflow schema validation;
7. signed artifact verification in the protected release job.

Coverage thresholds are 90% branch coverage for Authorization, Clipboard Lease, Seen Message Ledger, History, and Settings, and 80% overall for new Rust and TypeScript modules. Thresholds supplement, not replace, named behavior cases.

Performance gates use a pinned fixture workload with 20 warm runs and fail when p95 exceeds section 6.5 by more than 10%. Flake retries are prohibited for deterministic tests; a flaky native E2E is quarantined only with a linked issue and cannot cover a release blocker.

## 11. Delivery and rollout plan

**M0 — Contract and freeze.** Land this specification, ADRs, domain model, execution plan, and issue traceability. Keep distribution frozen.

**M1 — Security foundation.** Add test infrastructure; implement Clipboard Lease, Authorization public-client flow, CSP/capabilities, redacted errors, and secure storage primitives. Exit: RB-01, RB-02, and RB-05 tests pass.

**M2 — Deterministic data and intake.** Implement Settings, encrypted History/migration, Seen Message Ledger, MIME interpretation, Gmail status mapping, and cancellable intake. Exit: repeated unread Messages cannot repeat effects; startup/migration and partial failures are deterministic.

**M3 — Desktop Session and complete UX.** Introduce the typed contract/reducer, then redesign the adaptive popover, settings/privacy/onboarding, all production states, and accessibility. Exit: every section 4.2 state is covered by frontend tests and VoiceOver review.

**M4 — Distribution hardening.** Replace release automation; add signing, hardened runtime, notarization, update verification, macOS 13/current compatibility, operational/privacy/support docs, and local verifier parity. Exit: a signed beta installs and updates on clean hosts.

**M5 — Beta and promotion.** Ship to an opt-in cohort with no analytics. Collect user-reported failures and local redacted diagnostics only with consent. Hold at least 7 days; rollback on data loss, clipboard ownership violation, credential exposure, repeat Auto-copy, crash-free launch below 99.5%, or Authorization success below 95% in the manual test cohort. Promote only after all definition-of-done gates pass.

Rollback preserves previous signed binaries. Data migrations are forward-only; rollback instructions disconnect monitoring and preserve encrypted v2 data until the user upgrades again or explicitly deletes it.

## 12. Acceptance criteria, non-goals, and definition of done

### 12.1 Non-goals

- Mailbox providers other than Gmail, Gmail write scope, or marking Messages read
- Windows, Linux, mobile, or macOS earlier than 13
- Cloud sync, accounts hosted by OTPBar, analytics, or remote OTP processing
- React, Tauri, styling-stack, or language rewrite
- Machine-learning OTP classification
- Automatic update installation without user initiation
- Unlimited History or recovery of codes outside the selected retention window

### 12.2 Definition of done

OTPBar v2 is done only when:

- all requirements in this document are implemented and linked to passing tests;
- all RB, C, S, U, and dogfood findings in section 13 are closed with evidence;
- no code path can clear clipboard content it no longer owns;
- OAuth security tests cover PKCE, state, loopback binding, parsing, escaping, cancellation, concurrency, and credential failures;
- repeated unread Messages produce at most one accepted effect across restart;
- encrypted History honors Off/1/7/30 days and 50 entries, and verified migration removes plaintext;
- every production state is designed, keyboard-operable, and represented in tests;
- automated accessibility has zero serious/critical violations and manual VoiceOver passes on macOS 13 and current;
- performance requirements pass on the defined hosts;
- CI has no ignored lint/test failures and the local verifier runs the same gates;
- a clean machine installs, launches, authorizes, detects, copies safely, disconnects, deletes data, updates, and uninstalls the signed/notarized artifact;
- README, privacy/data-handling statement, threat model, support/recovery guide, signing/notarization guide, architecture map, compatibility matrix, and current screenshots are published;
- repository secrets scan is clean, release checksums are published, and GitHub release evidence identifies the tested commit/artifact.

## 13. Finding-to-requirement traceability

Tests below are named behavior suites to be created by the [implementation plan](implementation-plan.md).

| Finding | Requirement(s) | Required test evidence | Milestone |
|---|---|---|---|
| RB-01 | FR-17–19 | `clipboard_lease_ownership`, native cross-app clipboard E2E | M1 |
| RB-02 | FR-01–04, SEC-01–05 | `authorization_security`, malicious callback integration | M1 |
| RB-03 | FR-09–12 | `repeated_unread_idempotency`, restart integration | M2 |
| RB-04 | SEC-12, definition of done | `release_artifact`, clean install/update matrix | M4 |
| RB-05 | SEC-09 | `csp_capabilities` allow/deny integration | M1 |
| C-01 | FR-01–02, FR-11 | `intake_lifecycle` sign-out/restart/sleep-wake | M2 |
| C-02 | FR-04, PERF-05 | concurrent command latency test | M1/M2 |
| C-03 | section 9.2 | `startup_ordering` with delayed storage | M2 |
| C-04 | FR-12–14, SEC-06–07 | History policy, atomicity, corruption, migration suites | M2 |
| C-05 | FR-05–08 | Gmail status fixtures, MIME corpus, negative OTP corpus | M2 |
| C-06 | FR-21–24 | `clear_history_reconciliation` frontend/integration | M3 |
| C-07 | FR-14, FR-23 | `settings_persistence_failure` rollback/contract | M2/M3 |
| S-01 | FR-13, SEC-06–08 | encrypted store inspection and retention tests | M2 |
| S-02 | FR-25 | `privacy_projection_uncertainty` | M2/M3 |
| S-03 | FR-03, SEC-10, UX-06 | disconnect/delete intent integration and confirmation UI | M2/M3 |
| S-04 | SEC-01–05 | full `authorization_security` matrix | M1 |
| U-01 | UX-01–02 | healthy/stale/offline/rate-limit UI states | M3 |
| U-02 | section 5.1, UX-04 | header/menu layout and pointer-target tests | M3 |
| U-03 | UX-03, A11Y-03–05 | contrast, zoom, transparency, typography review | M3 |
| U-04 | FR-15–16, FR-19, A11Y-01 | settings behavior + accessible-name tests | M3 |
| U-05 | FR-17–19, UX-05 | manual-copy error and lease-event frontend tests | M1/M3 |
| U-06 | FR-13, FR-25, UX-06, UX-08 | privacy controls, selectable/revealable values | M3 |
| U-07 | UX-07, FR-22–24 | partial startup/module failure tests | M3 |
| U-08 | section 4.2, UX-02 | production-state fixture matrix | M3/M4 |
| ISSUE-001 | FR-21–24 | `clear_history_reconciliation` | M3 |
| ISSUE-002 | A11Y-01 | axe `button-name` and VoiceOver | M3 |
| ISSUE-003 | UX-03–04 | computed target/typography measurements | M3 |
| ISSUE-004 | UX-01–02 | empty healthy/stale snapshot tests | M3 |
| ISSUE-005 | UX-07 | partial startup snapshot tests | M3 |
| ISSUE-006 | UX-08 | copy/select/reveal privacy tests | M3 |
| Architecture 1 — OTP Intake ownership | FR-09–12, FR-20 | `intake_lifecycle`, effect-idempotency, and backoff suites | M2 / task 11 |
| Architecture 2 — Authorization ownership | FR-01–04, SEC-01–05 | `authorization_security` state-machine and integration suites | M1 / task 5 |
| Architecture 3 — Email Interpretation boundary | FR-07–08 | MIME fixture and adversarial classification corpus | M2 / task 10 |
| Architecture 4 — Recent Code History ownership | FR-12–14, SEC-06–07 | History policy, corruption, atomicity, and migration suites | M2 / task 8 |
| Architecture 5 — Seen Message Ledger ownership | FR-09–10 | ledger retention, restart, and repeated-unread suites | M2 / task 9 |
| Architecture 6 — Clipboard Lease ownership | FR-17–19 | fake-clock ownership race suite and native cross-app E2E | M1 / tasks 3–4 |
| Architecture 7 — Settings ownership | FR-14–16, FR-19 | defaults, validation, migration, revision, and persistence-failure suites | M2 / task 7 |
| Architecture 8 — Desktop Session ownership | FR-22–24 | cross-language contract and reducer reconciliation suites | M3 / tasks 13–14 |
| Architecture 9 — Privacy Projection ownership | FR-25 | authoritative metadata and partial-uncertainty projection suites | M2–M3 / task 12 |
| Test gap 1 — Intake E2E coverage | FR-09–12, FR-20 | dedupe, ordering, backoff, sign-out, Provider policy, notification, event, and partial-Mailbox integration matrix | M2 / task 11 |
| Test gap 2 — Realistic Gmail/MIME fixtures | FR-05–08 | multipart/alternative, nested MIME, HTML-only, charset/base64, pagination, and status-mapping fixtures | M2 / task 10 |
| Test gap 3 — Adversarial OTP corpus | FR-08 | positive ranking plus dates, orders, phones, currency, tracking, multi-candidate, and quoted-code negatives | M2 / task 10 |
| Test gap 4 — History/Settings durability tests | FR-13–16, SEC-06–07 | capacity, retention, migration, corruption, atomicity, I/O failure, validation, and error-propagation suites | M2 / tasks 7–8 |
| Test gap 5 — Clipboard race tests | FR-17–19 | fake-clock replacement, external ownership loss, expiry, denial, and clear-failure suite | M1 / tasks 3–4 |
| Test gap 6 — Frontend state tests | FR-21–24, UX-07 | partial startup, listener cleanup, auth/logout failure, clear reconciliation, settings rollback, and copy-status suites | M3 / task 14 |
| Test gap 7 — Accessibility coverage | A11Y-01–06 | axe, keyboard, reduced-motion/transparency, high-contrast, zoom, and native VoiceOver gates | M3 / task 18 |
| Test gap 8 — CI and artifact verification | section 10, SEC-12 | mandatory lint/test gates plus packaged install, launch, signing, notarization, and update checks | M1–M4 / tasks 1, 19–20 |
| Documentation gap 1 — conflicting Recent Code counts | FR-12–13, section 12.2 | README claim-to-schema review and clean-checkout docs test | M4 / task 21 |
| Documentation gap 2 — unsupported macOS 10.13 claim | section 1, section 12.1 | macOS 13/current compatibility matrix and README link check | M4 / tasks 19, 21 |
| Documentation gap 3 — distributed OAuth configuration undefined | SEC-04, section 12.2 | public-client build configuration, OAuth verification, and clean-setup documentation review | M4 / tasks 20–21 |
| Documentation gap 4 — stale project structure/architecture notes | section 8, section 12.2 | architecture-to-module/link review against the shipped tree | M4 / task 21 |
| Documentation gap 5 — missing privacy, threat, support, release, and recovery guides | SEC-08–12, section 12.2 | docs/link/claim review plus signing/notarization and recovery drills | M4 / tasks 20–21 |

Every row is release-blocking until its required evidence is linked from the implementing pull request or release checklist.
