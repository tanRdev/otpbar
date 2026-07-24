# OTPBar v2 modernization specification

**Status:** Approved for implementation

**Date:** 2026-07-23

**Scope:** macOS 13+, Gmail-only, React 19 + Tauri 2

**Inputs:** [current-state audit](current-state-audit.md), [dogfood report](../audit/dogfood/report.md), and [domain language](../CONTEXT.md)

## 1. Executive decision record

OTPBar v2 is a security-first modernization, not a rewrite. The current release is frozen until the five release blockers in the audit are closed. Work proceeds in this order: secure Authorization and clipboard behavior; make ingestion and local state deterministic; establish the typed Desktop Session; redesign the popover; then sign, notarize, and validate the shipped artifact.

The binding product decisions are:

- Gmail is the only Mailbox implementation in v2; a narrow Mailbox seam permits later adapters without speculative framework code.
- History is local, encrypted, capped at 50 entries, defaults to 7 days, and supports Off, 1 day, 7 days, or 30 days. Legacy plaintext is deleted after verified encrypted migration. APFS/SSD snapshots and copy-on-write mean secure erasure cannot be guaranteed. There is no cloud sync.
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
- **History** is durable retained user data; **Recent Code** is a Desktop Session presentation that may also be backed by History.
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

**Healthy monitoring.** The main view shows the Mailbox Identity, Monitoring Health, last successful check, next/retry context when relevant, and Auto-copy state. With no Recent Codes it explains that monitoring is healthy and offers a compact recovery hint.

**Code arrival.** An accepted Detected OTP appears once, newest first. A notification contains Provider context but not the code. Auto-copy occurs only if consent and effective policy allow it. The UI announces the arrival and copy outcome without stealing focus.

**Manual copy and expiry.** Copy creates/replaces one Clipboard Lease and exposes its remaining lifetime. Expiry clears only if OTPBar still owns exactly that value. Copying elsewhere ends ownership and the UI changes to “Clipboard changed”; it never clears the new content.

**Missing code.** The user can check now, inspect Monitoring Health, and see actionable offline, rate-limit, partial-fetch, or stale states. A failed Message never masquerades as a healthy full check.

**Settings and privacy.** Settings expose global Auto-copy, Provider overrides, lease duration, History retention, notifications, and Start at Login. Notifications default to not requested and off; the permission prompt follows only an explicit onboarding or Settings action after Authorization. Start at Login defaults off. Privacy reports authoritative access, storage, retention, and health metadata with unknown values shown as unknown. Paths are selectable/copyable and revealable in Finder.

**Disconnect and delete.** Disconnect revokes local credentials and stops monitoring but preserves History. Deleting History requires confirmation and leaves Authorization intact. A combined “Disconnect and delete local data” action is explicit and confirmed.

**Update.** A signed update can be checked, downloaded, installed, and relaunched without blocking code access. Signed metadata and payload are verified before install. Install is user-initiated; offline and verification failures preserve the running version and expose retry/support.

**Diagnostics.** From a degraded state, the user can create and preview a redacted support bundle before saving or sharing it. The bundle never contains OTPs, credentials, raw Message IDs, Message bodies, or Mailbox Identity.

### 4.2 Complete production-state contract

| Area | States the UI must represent | Required action or message |
|---|---|---|
| Compatibility | supported; unsupported macOS; missing build configuration | Continue; explain macOS 13 floor; developer/release remediation |
| Onboarding and consent | first launch; consent unknown; consent granted; consent declined; revisit | Explain Gmail access, History, and Auto-copy separately; require an explicit choice before Auto-copy can run; preserve full manual-copy/monitoring use after decline; let the user revisit consent from Settings |
| Authorization | unknown/restoring; disconnected; starting; awaiting browser; exchanging; connected; cancelled; denied; callback invalid; configuration missing; credential store unavailable; refresh required; failed | Never blank the shell; offer cancel/retry/disconnect as applicable |
| Monitoring Health | stopped; checking; healthy; stale; offline; rate-limited with retry time; partially degraded; permission denied; unavailable | Show last success, affected scope, and safe recovery |
| Intake | idle; fetching; no new Messages; new Detected OTP; rejected candidates; partial fetch | Publish a coherent session revision; do not repeat effects |
| History | loading; ready empty; ready populated; retention Off; migrating; clearing; storage unavailable; corrupted/unreadable; write failed | Preserve usable modules and expose retry/recovery |
| Clipboard Lease | idle; copying; owned with expiry; replaced; expired and cleared; ownership lost; permission denied; write failed; clear failed | One authoritative status; never imply ownership after loss |
| Notification permission | unknown/not requested; requesting; granted; denied; unavailable/error | Ask only from a user action with preflight context; show the OS result; after denial keep intake usable and link to System Settings; on unavailable/error explain that notification delivery is degraded and offer retry when safe |
| Start at Login | off; enabling; on; disabling; unavailable/error | Default off; reconcile the setting with the macOS registration result; on error retain the prior state and offer retry |
| Settings | loading; ready; saving; saved; validation failed; persistence failed | Optimistic UI must roll back or reconcile from returned snapshot |
| Privacy | loading; ready; partially unknown; unavailable | Label uncertainty; never convert errors into reassuring falsehoods |
| Connectivity | online; offline; restored | Preserve local functions and automatically resume bounded checks |
| Update | unknown; checking; current; available; downloading; verifying; ready; installing; relaunching; offline; metadata invalid; download failed; install failed; unsupported release | Keep the current version usable; require user initiation for download/install; expose retry and support without bypassing signature verification |
| Diagnostics | idle; collecting; preview ready; saving; saved; collection failed; save failed | Collect only after explicit action; show the exact redacted preview before save/share; preserve retry and cancel |
| Desktop Session | booting; usable; degraded; terminating | Quit and diagnostics remain available in every usable/degraded state |

## 5. Target experience and visual system

### 5.1 Information architecture

The primary view contains, in order: compact identity/health header; newest Recent Codes; contextual empty/error content; and a single secondary menu. Manual copy is the primary action. Settings, Privacy, Disconnect, and Quit move out of equal-weight header buttons into the menu. Destructive actions remain visually and spatially separated.

The popover starts at the smallest usable size and may adapt up to roughly 360 × 500, never exceeding the current screen's visible frame. Long content scrolls inside a stable shell; the menubar anchor and primary status remain visible. The design is compact and native-feeling, with restrained opaque/vibrant materials that remain legible against worst-case light and dark wallpapers. It must not use a generic gradient, card dashboard, or ornamental glassmorphism.

### 5.2 Visual and interaction requirements

- **UX-01:** Monitoring Health and Mailbox Identity are visible on the main view without navigation.
- **UX-02:** Every state in section 4.2 has designed copy, status treatment, and at least one valid next action when recovery is possible.
- **UX-03:** The UI uses a 4 px base spacing rhythm, no core text below 12 px, body text at least 13 px, and primary values at least 14 px.
- **UX-04:** Interactive targets are at least 28 × 28 CSS px; primary and destructive controls are at least 32 px high with 8 px minimum separation.
- **UX-05:** Success feedback persists for at least 2 seconds; transient errors persist until dismissed or superseded by a confirmed success.
- **UX-06:** Destructive History and combined disconnect/delete operations require a confirmation that names what is retained and removed.
- **UX-07:** Module failures degrade locally. Authorization, Quit, settings navigation, and unaffected Recent Codes remain available.
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
- **FR-02:** Disconnect cancels intake and token work within 1 second, removes credentials, publishes disconnected state, and allows a clean reauthorization without restart.
- **FR-03:** Disconnect, delete History, and combined disconnect/delete are distinct intents and idempotent.
- **FR-04:** No mutex/lock is held while waiting for browser interaction, network I/O, clipboard I/O, or durable storage.

### 6.2 Mailbox, interpretation, and intake

- **FR-05:** The Gmail adapter uses read-only scope, requests bounded pages, maps every non-2xx response into a typed error, and distinguishes permission, authentication, rate-limit, offline, server, malformed, and partial-fetch outcomes.
- **FR-06:** A check returns a completeness marker. Any failed Message detail fetch produces partial Monitoring Health and is eligible for bounded retry; it is not marked Seen until the acceptance/rejection decision completes.
- **FR-07:** Interpretation supports nested multipart messages, prefers decoded `text/plain` then sanitized text from `text/html`, respects declared charset when supported, rejects invalid encoding explicitly, and excludes quoted/replied content where possible.
- **FR-08:** Detection ranks candidates using message context and Provider patterns. The generic numeric fallback requires OTP language proximity and accepts 4–8 digits; dates, phone fragments, currency, order/tracking numbers, and quoted older codes form a mandatory negative corpus.
- **FR-09:** The Seen Message ledger is independent of History and presentation capacity. Accepting a Message atomically persists its Seen identity and any eligible external-effect intents before the Detected OTP is published.
- **FR-10:** Seen Messages are retained for 30 days with a 10,000-entry hard cap, pruning oldest entries after each committed check. This policy is internal idempotency state and is unaffected by History Off or History clearing.
- **FR-11:** Intake has one cancellable owner, uses an 8-second healthy interval with ±10% jitter, exponential backoff from 15 seconds to 15 minutes, honors `Retry-After`, resets after a successful complete check, and stops on disconnect/shutdown.
- **FR-12:** Recent Codes are an in-memory Desktop Session projection, newest first, uniquely keyed by source Message, and capped at 10. With retention enabled, startup projects the latest 10 unexpired History entries and then merges current-session arrivals. With History Off, accepted codes remain visible/copyable for 15 minutes, are never restored after app exit, and expire from the projection automatically.

### 6.3 History, settings, notification, and clipboard

- **FR-13:** History defaults to encrypted 7-day retention, has a 50-entry durable cap, and offers only Off, 1, 7, or 30 days. Off removes durable History entries and prevents future History writes without clearing the encrypted Seen Message ledger or the current 15-minute Recent Code projection.
- **FR-14:** Acceptance is one atomic update of a single versioned encrypted state snapshot: add the Seen Message identity, add the History entry when retention is not Off, and add eligible pending Auto-copy/notification intents to the effect outbox. The update uses a same-directory temporary file, file sync, atomic replace, and parent-directory sync. Any failure commits none of acceptance and publishes no Recent Code.
- **FR-15:** Auto-copy is ineligible until onboarding records explicit consent. Thereafter effective policy is `global enabled AND provider override`, where a missing Provider override inherits global and an explicit false disables that Provider.
- **FR-16:** Provider overrides cannot enable Auto-copy when global Auto-copy is off or consent is absent. Revoking consent disables and removes all overrides.
- **FR-17:** Manual copy is always available for a visible Recent Code. Both manual and automatic copy use the same Clipboard Lease service.
- **FR-18:** A new copy cancels/replaces the active Clipboard Lease. Expiry clears only if lease identity is active and current clipboard content exactly matches the value OTPBar wrote; otherwise it publishes ownership lost and does not mutate the clipboard.
- **FR-19:** Lease duration is validated to 15, 30, or 60 seconds, default 30. Shutdown cancels the timer but does not clear clipboard content unless the same ownership check succeeds.
- **FR-20:** Notifications default disabled with permission `unknown/not requested`. Only an explicit onboarding or Settings action after Authorization may request permission; the setting becomes enabled only after the OS reports granted. Denial leaves intake usable and links to System Settings; unavailable/error remains retryable. Notification content never contains the OTP value.
- **FR-21:** Clearing History atomically removes durable History entries, clears the current Recent Code projection, leaves Seen Messages and effect intents unchanged, and publishes one empty Desktop Session snapshot before the command resolves.

### 6.4 Desktop Session contract

- **FR-22:** The frontend receives a versioned full Desktop Session snapshot at startup and monotonic revisioned domain events thereafter. Event application is idempotent; a revision gap triggers snapshot refresh.
- **FR-23:** Commands use a discriminated success/error envelope with stable machine codes, user-safe messages, retryability, and optional field context. Rust and TypeScript types are generated or contract-tested from one schema.
- **FR-24:** Event listeners are registered once and disposed on unmount/reload. Command results reconcile through the same session reducer as events.
- **FR-25:** Privacy is a projection of metadata from Authorization, History, Settings, Seen Message, and Clipboard owners. Unknown/unavailable is preserved and secrets/OTP values are excluded.
- **FR-26:** Start at Login is a v2 setting owned by Settings and a macOS desktop integration. It defaults off; enable/disable commands persist success only after the OS registration result and return the reconciled authoritative state.
- **FR-27:** The Update module checks signed metadata, downloads, verifies, installs, and relaunches only after explicit user action. Offline, malformed/unsigned metadata, download, verification, install, and relaunch failures preserve the current version and expose typed retry.
- **FR-28:** Diagnostics creates a local, redacted, previewable support bundle only after explicit user action. The preview is exactly the content saved/shared and excludes OTPs, credentials, Authorization codes, PKCE material, raw Message IDs, Message bodies, and Mailbox Identity.
- **FR-29:** The effect outbox transitions `pending → claimed → completed`. Claim is persisted atomically before calling the external effect. Pending items may be claimed after restart; claimed items are never retried after restart, making notification and Auto-copy best-effort at-most-once attempts. Completion is persisted after the attempt regardless of success, erases the sensitive payload, and retains only redacted outcome metadata; completed tombstones expire after 24 hours. On restart, interrupted claimed items are completed and scrubbed before intake. Manual copy is user-initiated and never enters the outbox.

### 6.5 Performance and reliability

- **PERF-01:** On the performance baseline, tray click to interactive warm shell is ≤200 ms at p95 and process launch to interactive cold shell is ≤1.5 seconds at p95, excluding Authorization/network completion. “Warm” means the process and decrypted state are already resident with the popover hidden; “cold” means the process is absent, the prior run exited cleanly, and the encrypted state exists, without purging OS filesystem caches.
- **PERF-02:** A complete Gmail check of 25 Messages finishes within 5 seconds at p95 against the local fixture server shaped to 100 ms round-trip latency, 20 Mbps downstream, 5 Mbps upstream, and 0% packet loss, using at most 4 concurrent detail requests.
- **PERF-03:** Local settings/History commands complete within 100 ms at p95 for 50 History entries; encrypted store migration completes within 2 seconds or reports progress/failure.
- **PERF-04:** Idle CPU averages <1% over 5 minutes between checks and steady-state memory remains <120 MB on the oldest supported macOS test host.
- **PERF-05:** No network, storage, or browser wait blocks another command for more than 100 ms. Intake retries are cancellable and do not multiply after sleep/wake or reconnect.

The reproducible performance baseline is an Apple M1 with 8 GB RAM running macOS 13.7 on AC power with Low Power Mode off, using a signed-equivalent release build and no unrelated foreground workload. Each launch metric uses 5 unreported warmups followed by 30 measured runs; p95 is the nearest-rank value (rank `ceil(0.95 × 30) = 29`) from ascending results. Test scripts record commit, build profile, machine/OS, power state, fixture version, network-shaping command, and raw samples. CI must include a documented macOS 13 runner or equivalent self-hosted host for compatibility; `macos-latest` alone is insufficient.

## 7. Security and privacy requirements

- **SEC-01:** Authorization uses a fresh PKCE verifier/challenge and at least 128 bits of unpredictable state per attempt. Callback state is compared in constant time before code exchange.
- **SEC-02:** The callback binds `127.0.0.1` or `[::1]` on port `0` before the browser opens, accepts only the expected path/method/host, URL-decodes parameters once, limits request size/time, serves one terminal callback, and then closes.
- **SEC-03:** Callback HTML uses fixed templates with context-correct escaping and no remote assets. Provider errors are mapped to safe text; raw values are never reflected.
- **SEC-04:** OTPBar is a public client. A client ID may be build configuration; no client secret is logged, stored as a secret, or required as proof of client identity.
- **SEC-05:** Access/refresh credentials reside in macOS Keychain with the narrowest practical accessibility. Logs expose neither credentials, Authorization codes, PKCE verifier, OTP values, raw Message bodies, nor raw Message IDs.
- **SEC-06:** The atomic state store uses authenticated encryption with a random nonce per snapshot and an application-readable random 256-bit symmetric key stored in macOS Keychain. Ciphertext has versioned associated metadata; authentication failure never yields partial plaintext. Keychain access is required, and loss of the key makes the encrypted store unrecoverable; OTPBar does not imply Secure Enclave or non-exportability.
- **SEC-07:** Successful plaintext migration atomically commits the encrypted state snapshot, reads it back and compares the migrated model, then deletes `code_history.json` and syncs the parent directory where supported. On failure, plaintext remains in place, intake does not overwrite it, and the UI reports recovery steps. APFS/SSD snapshots and copy-on-write mean deletion cannot guarantee secure erasure. An unreadable new store is deleted only after confirmation; it cannot be recovered without the Keychain key.
- **SEC-08:** No OTPBar History, settings, telemetry, Message content, or clipboard content is cloud-synced or sent outside the Gmail API and OS services required by the feature. v2 adds no analytics.
- **SEC-09:** Tauri production CSP defaults to self-only local assets, disallows remote scripts/styles and unsafe evaluation, and permits only IPC/resources proven necessary. Capabilities expose each command/plugin only to the main window and minimum permission set.
- **SEC-10:** Disconnect removes all OAuth credentials; delete History atomically removes History entries from the encrypted snapshot and deletes legacy plaintext if present; “delete all local data” additionally removes settings, consent, Seen Message ledger, effect outbox, encryption key, and cached metadata. Each operation verifies and reports partial failure.
- **SEC-11:** Logs use structured machine codes and redacted identifiers. Diagnostics bundles require explicit user action, show the exact content before save/share, and exclude OTPs, credentials, Authorization/PKCE material, raw Message IDs, Message bodies, and Mailbox Identity.
- **SEC-12:** Release artifacts are Developer ID signed, hardened-runtime enabled, notarized, stapled, and verified before publication. Update metadata is signed and transported over TLS.

Threats explicitly covered are callback interception/CSRF, distributed-secret misconception, token disclosure, local History disclosure/tampering, webview injection, clipboard races, repeated-message side effects, log leakage, and malicious/invalid update artifacts.

## 8. Target architecture

The application remains React + Tauri. Tauri commands are thin adapters; domain modules own invariants and expose narrow interfaces. Side effects are injected behind testable ports.

| Module | Owns | Conceptual interface |
|---|---|---|
| Authorization | attempt state, PKCE/state, callback lifetime, token refresh, credential persistence, disconnect | `restore`, `begin`, `cancel`, `disconnect`, `status`; emits Authorization changes |
| Mailbox (Gmail adapter) | Gmail query, paging, status mapping, raw Message retrieval | `identity`, `list_candidates(cursor)`, `fetch_message(id)`, `refresh_access`; returns typed completeness/errors |
| Message Interpretation | MIME normalization, candidate ranking, Provider inference, rejection reason | `interpret(Message) -> Detected OTP | Rejection` with no network/storage |
| OTP Intake | monitoring lifecycle, scheduling/backoff, and acceptance requests | `start`, `check_now`, `stop`; submits one acceptance mutation and publishes only committed results |
| Atomic State Store | versioned encryption, History, Seen Message ledger, effect outbox, atomic acceptance, migration/recovery | `load`, `accept`, `claim_effect`, `complete_effect`, `mutate_policy`, `delete_data`, `metadata` |
| Effect Dispatcher | best-effort at-most-once automatic attempts | claims pending intent before external call; records completed outcome; never retries claimed intent after restart |
| Clipboard Lease | copy ownership, replacement, expiry, status | `copy(value, source, duration)`, `cancel`, `status`; uses clock/clipboard ports |
| Settings | defaults, consent, notifications, Start at Login, validation, persistence, migrations | `load`, `update(expected_revision, patch)`, `reset`, `snapshot`; delegates OS-owned settings before commit |
| Notification Permission | OS permission request/result and recovery | `status`, `request_from_user_action`, `open_system_settings` |
| Desktop Integration | Start at Login registration and reconciliation | `status`, `set_enabled`; reports unavailable/error without false success |
| Privacy Projection | non-secret, uncertainty-preserving composition | `snapshot` from owner metadata; performs no independent storage reads |
| Desktop Session | authoritative frontend projection and revision stream | `snapshot`, command envelopes, domain events; reducer mirrors contract in React |
| Update | signed metadata check, download, verification, install, relaunch | `check`, `download`, `install_and_relaunch`, `retry`, `status` |
| Diagnostics | redacted support-bundle collection and exact preview | `collect`, `preview`, `save`; never uploads automatically |

An intake acceptance is one atomic encrypted snapshot replacement. It adds the Seen Message identity, adds a History entry when retention is not Off, and adds pending intents for each eligible notification/Auto-copy attempt. If serialization, encryption, temporary write, file sync, replace, or parent-directory sync fails, no acceptance is committed and no Recent Code or external effect is published. After verified commit, intake publishes the Recent Code into the Desktop Session.

The Effect Dispatcher changes one intent from `pending` to `claimed` in a committed snapshot before calling the external adapter, then commits `completed` with a redacted success/failure outcome. After a crash, pending intents may be claimed; claimed intents are finalized without retry. The result is best-effort at-most-once attempts: a crash between claim and external completion may lose an effect but can never duplicate it. Manual copy bypasses the outbox because each attempt is explicitly user-initiated.

Network concurrency is bounded outside shared state locks. Module state uses actors/owned tasks or brief critical sections; cancellation tokens define shutdown, disconnect, replacement Authorization, sleep/wake, and app exit.

## 9. Data model and migrations

### 9.1 Atomic encrypted state snapshot

One encrypted file is the acceptance consistency boundary. Each replacement writes a same-directory temporary file, syncs it, atomically replaces the current file, and syncs the parent directory. The ciphertext envelope contains format version, authenticated-encryption algorithm, key identifier, random nonce, ciphertext, and associated-data version; it duplicates no sensitive plaintext metadata. The decrypted snapshot contains:

- `schema_version`, `revision`, and `written_at`;
- `history[]`: opaque ID, code, sender display, Provider key/display, received timestamp, source Message digest; newest first, policy-expired entries removed, maximum 50;
- `seen_messages[]`: keyed digest of Mailbox Identity plus Message identity, decision (`detected | rejected`), and decision timestamp; no OTP, sender, subject, body, or raw Message ID; 30-day/10,000-entry limits;
- `effect_outbox[]`: opaque intent ID, accepted snapshot revision, kind (`auto_copy | notification`), minimum required payload while pending/claimed, and state (`pending | claimed | completed`); completion scrubs payload, keeps only redacted outcome metadata, and expires its tombstone after 24 hours;
- settings needed to evaluate acceptance consistently: History retention, Auto-copy consent/global policy/Provider overrides, and notification-enabled state.

Other UI-only settings may live in a separately versioned atomic settings file if required by platform integration, but History, Seen Message ledger, acceptance policy inputs, and effect outbox are always committed in the same encrypted acceptance snapshot. A Settings update that changes an acceptance policy must update this snapshot before it is reported successful.

The application-readable encryption key is a random 256-bit symmetric key stored in macOS Keychain. Keychain access is required. Key loss, Keychain denial, authentication failure, an unknown future schema, or a corrupt snapshot produces a read-only recovery state: intake stays stopped, the original file is preserved, and the user may retry Keychain access, update OTPBar, save redacted diagnostics, or confirm deletion of the unreadable new store. OTPBar never silently quarantines or replaces unrecoverable encrypted state.

### 9.2 Settings schema and projections

The authoritative settings model contains:

- `schema_version` and `revision`;
- `onboarding.auto_copy_consent`: `unknown | declined | granted`;
- `auto_copy.global_enabled` and Provider overrides;
- `clipboard_lease_seconds`: `15 | 30 | 60`;
- `history_retention_days`: `0 | 1 | 7 | 30`;
- `notifications.permission`: `unknown | requesting | granted | denied | unavailable`;
- `notifications.enabled`, default `false`, valid as `true` only while permission is `granted`;
- `start_at_login`, default `false`, reconciled with the macOS registration owner before persistence.

Recent Codes are not a durable table. At restart with retention enabled, the Desktop Session projects the 10 newest unexpired History entries. With History Off, restart begins with no Recent Codes; current-session accepted codes remain for 15 minutes, maximum 10, and disappear at app exit.

### 9.3 Upgrade sequence

1. Establish compatibility and load/migrate Settings. Legacy missing consent becomes `unknown`, forcing Auto-copy off; legacy `auto_copy_enabled=true` is not treated as consent.
2. Restore or generate the application-readable 256-bit Keychain key.
3. Detect legacy `code_history.json`; parse and validate every entry, apply 7-day/50-entry policy, write the atomic encrypted snapshot, read it back and compare the full migrated model, then delete plaintext and sync the parent directory.
4. Load/prune the encrypted snapshot and resolve pending/claimed outbox recovery before new intake.
5. Restore Authorization.
6. Publish the first usable Desktop Session.
7. Start intake only after all prior steps succeed or have produced an explicit degraded state.

If migration fails before verified encrypted commit, legacy plaintext stays intact and intake remains stopped. If it fails after encrypted commit but before legacy deletion, restart verifies the encrypted snapshot again and retries deletion without duplicating entries. If deletion succeeds, secure erasure is not promised because APFS/SSD snapshots and copy-on-write may retain blocks. Unknown future schemas and missing keys are read-only failures. v2 downgrade is unsupported; confirmed local-data deletion is the only downgrade recovery. Keychain failure never causes plaintext fallback.

### 9.4 Crash-boundary acceptance recovery

| Crash/failure boundary | Durable result | Restart behavior |
|---|---|---|
| Before temporary snapshot write or during write/sync | Prior snapshot remains authoritative | Message is unaccepted and eligible for a later intake retry; no UI/effect |
| After temp sync but before atomic replace | Prior snapshot remains authoritative; orphan temp is non-authoritative | Remove temp after validation; retry Message later |
| After atomic replace, including parent-directory sync uncertainty | Read back current snapshot and revision | If new revision verifies, acceptance is committed and publishes once; otherwise preserve files and enter recovery |
| After acceptance commit but before Desktop Session publication | Acceptance, Seen identity, History if enabled, and pending intents exist | With retention enabled, rebuild Recent Codes from History; with History Off, the code is not restored after process exit; never reaccept the Message |
| Before outbox claim commit | Intent remains pending | May claim once after restart |
| After claim commit but before/during external call | Intent is claimed | Never retry; finalize as interrupted/unknown |
| After external call but before completion commit | Intent is claimed | Never retry; finalize as interrupted/unknown, accepting possible lost status but no duplicate attempt |
| After completion commit | Intent is completed | Never retry |

Fault-injection tests must stop the process at every row, reopen the store, and prove snapshot integrity, Seen/History agreement, Recent Code restart semantics, and at-most-once external attempts.

## 10. Verification strategy and quality gates

Tests are behavior-first and deterministic: fake clocks, clipboard, Keychain, filesystem fault injection, HTTP fixtures, and event collectors replace sleeps and live Mailboxes wherever possible.

| Layer | Required coverage |
|---|---|
| Rust unit | PKCE/state and Authorization transitions; callback parsing/escaping; lease replacement/ownership races; state-snapshot encryption/atomicity; acceptance/outbox transitions; retention/capacity; ledger pruning; settings/notification/Start at Login validation; backoff/cancellation; update states; diagnostics redaction; privacy uncertainty |
| Fixture/contract | Nested MIME, charset/base64 failures, HTML-only, quoted replies, adversarial numeric corpus; Gmail pagination and every HTTP mapping; Rust/TypeScript schema compatibility |
| Integration | every section 9.4 crash boundary, migration success/failure/restart/key loss, disconnect/restart, repeated unread Message, partial fetch retry, at-most-once effect attempt, notification permission, Start at Login OS reconciliation, clear/reconcile, signed update, CSP/capability allow/deny |
| Frontend | every section 4.2 state, revision gap refresh, partial startup, settings rollback, History Off 15-minute projection/restart, clear History, copy ownership loss, update/relaunch flow, diagnostics preview, listener cleanup, confirmations |
| Accessibility | automated axe with zero serious/critical violations; keyboard snapshots; contrast checks; reduced motion/transparency; manual VoiceOver checklist |
| Native E2E | tray open/close, bounded adaptive window, OAuth callback lifecycle with fake provider, clipboard ownership against another app, sleep/wake, offline recovery, explicit notification permission/denial, Start at Login relaunch |
| Security | secret/log/diagnostics scan, CSP tests, malicious callback inputs, corrupted/tampered ciphertext, missing Keychain key recovery, signed-update rejection, dependency audit, capability inventory |
| Release | clean macOS 13 and current macOS install/launch, signing/notarization/staple verification, signed-metadata update from previous beta, download/install/relaunch and rollback, DMG checksum |

Mandatory CI gates:

1. frontend format/lint, TypeScript, tests, and production build;
2. `cargo fmt --check`, strict clippy for all targets/features, unit/integration tests;
3. contract/schema and security tests;
4. accessibility automation;
5. Tauri production build on macOS;
6. release workflow schema validation;
7. signed artifact verification in the protected release job.

Coverage thresholds are 90% branch coverage for Authorization, Clipboard Lease, Seen Message Ledger, History, and Settings, and 80% overall for new Rust and TypeScript modules. Thresholds supplement, not replace, named behavior cases.

Performance gates use the exact baseline, state definitions, fixture server, network shaping, 5 warmups, 30 measurements, and nearest-rank calculation in section 6.5. A documented equivalent self-hosted macOS 13 host may substitute only when its hardware/power metadata is recorded; results from `macos-latest` do not establish compatibility or the baseline. Flake retries are prohibited for deterministic tests; a flaky native E2E is quarantined only with a linked issue and cannot cover a release blocker.

## 11. Delivery and rollout plan

**M0 — Contract and freeze.** Land this specification, ADRs, domain model, execution plan, and issue traceability. Keep distribution frozen.

**M1 — Security foundation.** Add test infrastructure; implement Clipboard Lease, the split Authorization core/callback/Google adapters, CSP/capabilities, redacted errors, and the encrypted atomic state-store primitive. Exit: RB-01, RB-02, and RB-05 tests pass.

**M2 — Deterministic data and intake.** Implement Settings, notification permission, Start at Login, encrypted History/migration, Seen Message Ledger, effect outbox/dispatcher, split Gmail transport/MIME/classification, and split intake scheduler/acceptance/effects. Exit: every crash boundary passes, repeated unread Messages cannot repeat effect attempts, History Off semantics pass, and startup/migration/partial failures are deterministic.

**M3 — Desktop Session and complete UX.** Introduce the typed contract/reducer, Update and Diagnostics modules, then redesign the adaptive popover, settings/privacy/onboarding, all production states, and accessibility. Exit: every section 4.2 state is covered by frontend tests and VoiceOver review.

**M4 — Distribution hardening.** Replace release automation; add signing, hardened runtime, notarization, signed update metadata and end-to-end download/install/relaunch, macOS 13/current compatibility, operational/privacy/support docs, and local verifier parity. Exit: a signed beta installs and updates on clean hosts and produces a verified redacted Diagnostics bundle.

**M5 — Beta and promotion.** Ship to an opt-in cohort with no analytics. Collect user-reported failures and local redacted diagnostics only with consent. Hold at least 7 days; rollback on data loss, clipboard ownership violation, credential exposure, repeat Auto-copy, crash-free launch below 99.5%, or Authorization success below 95% in the manual test cohort. Promote only after all definition-of-done gates pass.

Rollback preserves previous signed binaries. Data migrations are forward-only; rollback instructions disconnect monitoring and preserve encrypted v2 data until the user upgrades again or explicitly deletes it.

## 12. Acceptance criteria, non-goals, and definition of done

### 12.1 Non-goals

- Mailbox providers other than Gmail, Gmail write scope, or marking Messages read
- Windows, Linux, mobile, or macOS earlier than 13
- Cloud sync, OTPBar-hosted identities, analytics, or remote OTP processing
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
- every section 9.4 crash boundary preserves atomic acceptance, and repeated unread Messages produce at most one Auto-copy/notification attempt across restart;
- the encrypted atomic snapshot keeps Seen Message, History, and outbox consistent; History honors Off/1/7/30 days and 50 entries; Recent Codes honor 15-minute/10-item History Off semantics; verified migration deletes plaintext without claiming guaranteed secure erasure;
- notification permission and Start at Login defaults, transitions, OS reconciliation, and recovery pass on macOS 13/current;
- every production state is designed, keyboard-operable, and represented in tests;
- automated accessibility has zero serious/critical violations and manual VoiceOver passes on macOS 13 and current;
- performance requirements pass using the documented M1/macOS 13.7 baseline, raw samples, network shaping, and nearest-rank calculation;
- CI has no ignored lint/test failures and the local verifier runs the same gates;
- a clean machine installs, launches, authorizes, detects, copies safely, disconnects, deletes data, updates, and uninstalls the signed/notarized artifact;
- signed Update metadata verification, download/install/relaunch, offline/error/retry, and rollback pass from the prior beta;
- Diagnostics preview/save redaction tests prove the exact bundle excludes OTPs, credentials, raw Message IDs, Message bodies, and Mailbox Identity;
- README, privacy/data-handling statement, threat model, support/recovery guide, signing/notarization/update guide, architecture map, compatibility matrix, and current screenshots are published;
- repository secrets scan is clean, release checksums are published, and GitHub release evidence identifies the tested commit/artifact.

## 13. Finding-to-requirement traceability

Tests below are named behavior suites to be created by the [implementation plan](implementation-plan.md).

| Finding | Requirement(s) | Required test evidence | Milestone |
|---|---|---|---|
| RB-01 | FR-17–19 | `clipboard_lease_ownership`, native cross-app clipboard E2E | M1 / tasks 7–8, 32 |
| RB-02 | FR-01–04, SEC-01–05 | Authorization core, callback, and fake-Google integration | M1 / tasks 9–11 |
| RB-03 | FR-09–14, FR-29 | repeated-unread plus every crash/outbox boundary | M2 / tasks 6, 20–21 |
| RB-04 | SEC-12, FR-27 | signed artifact and clean install/update matrix | M4 / tasks 28, 32–33 |
| RB-05 | SEC-09 | CSP/capability allow/deny in production bundle | M1 / task 12 |
| C-01 | FR-01–02, FR-11 | intake disconnect/restart/sleep-wake lifecycle | M2 / task 19 |
| C-02 | FR-04, PERF-05 | concurrent command latency | M1–M2 / tasks 11, 16, 19 |
| C-03 | section 9.3 | delayed-store startup and migration ordering | M2 / tasks 4, 19 |
| C-04 | FR-12–14, SEC-06–07 | snapshot, History, migration, corruption, and Off semantics | M1–M2 / tasks 3–5 |
| C-05 | FR-05–08 | Gmail status, MIME, and adversarial classification fixtures | M2 / tasks 16–18 |
| C-06 | FR-21–24 | clear-History reducer reconciliation | M3 / task 24 |
| C-07 | FR-14, FR-23 | Settings persistence failure and rollback | M2–M3 / tasks 13, 24 |
| S-01 | FR-13–14, SEC-06–08 | encrypted snapshot inspection, retention, key-loss tests | M1–M2 / tasks 3–5 |
| S-02 | FR-25 | Privacy Projection uncertainty | M2 / task 22 |
| S-03 | FR-03, SEC-10, UX-06 | disconnect/delete separation and confirmation | M3 / task 27 |
| S-04 | SEC-01–05 | complete Authorization security matrix | M1 / tasks 9–11 |
| U-01 | UX-01–02 | healthy/stale/offline/rate-limit UI states | M3 / task 25 |
| U-02 | section 5.1, UX-04 | header/menu and pointer-target tests | M3 / tasks 25, 31 |
| U-03 | UX-03, A11Y-03–05 | contrast, zoom, transparency, typography | M3 / task 31 |
| U-04 | FR-15–16, FR-19–20, A11Y-01 | Settings behavior, permission, accessible names | M3 / task 27 |
| U-05 | FR-17–19, UX-05 | manual-copy and lease-event frontend tests | M1–M3 / tasks 7–8, 26 |
| U-06 | FR-13, FR-25, UX-06, UX-08 | Privacy controls and exact path actions | M3 / task 27 |
| U-07 | UX-07, FR-22–24 | partial startup/module failure | M3 / task 24 |
| U-08 | section 4.2, UX-02 | complete production-state fixture matrix | M3–M4 / tasks 23–31 |
| ISSUE-001 | FR-21–24 | clear-History reconciliation | M3 / task 24 |
| ISSUE-002 | A11Y-01 | axe `button-name` and VoiceOver | M3 / task 31 |
| ISSUE-003 | UX-03–04 | computed target/type measurements | M3 / task 31 |
| ISSUE-004 | UX-01–02 | healthy/stale empty snapshots | M3 / task 25 |
| ISSUE-005 | UX-07 | partial startup snapshots | M3 / task 24 |
| ISSUE-006 | UX-08 | copy/select/reveal Privacy tests | M3 / task 27 |
| Architecture 1 — OTP Intake ownership | FR-09–12, FR-20, FR-29 | lifecycle, atomic acceptance, at-most-once effects | M2 / tasks 19–21 |
| Architecture 2 — Authorization ownership | FR-01–04, SEC-01–05 | state/PKCE, callback, credentials/Google suites | M1 / tasks 9–11 |
| Architecture 3 — Message Interpretation boundary | FR-07–08 | MIME and adversarial classification corpora | M2 / tasks 17–18 |
| Architecture 4 — History ownership and Recent Code projection | FR-12–14, SEC-06–07 | snapshot, migration, History/Recent Code projection | M1–M2 / tasks 3–5, 20 |
| Architecture 5 — Seen Message Ledger ownership | FR-09–10, FR-14 | ledger retention and acceptance consistency | M2 / tasks 6, 20 |
| Architecture 6 — Clipboard Lease ownership | FR-17–19 | fake-clock races and native cross-app E2E | M1 / tasks 7–8, 32 |
| Architecture 7 — Settings ownership | FR-14–16, FR-19–20, FR-26 | defaults, policy sync, permission, Start at Login | M2 / tasks 13–15 |
| Architecture 8 — Desktop Session ownership | FR-22–24 | contract and reducer reconciliation | M3 / tasks 23–24 |
| Architecture 9 — Privacy Projection ownership | FR-25, FR-28 | uncertainty and Diagnostics-safe metadata | M2–M3 / tasks 22, 30 |
| Test gap 1 — Intake E2E coverage | FR-09–12, FR-20, FR-29 | dedupe, ordering, backoff, disconnect, policy, partial Mailbox, effects | M2 / tasks 19–21 |
| Test gap 2 — Realistic Gmail/MIME fixtures | FR-05–08 | pagination/status plus multipart/charset/HTML fixtures | M2 / tasks 16–17 |
| Test gap 3 — Adversarial OTP corpus | FR-08 | ranking and false-positive negative corpus | M2 / task 18 |
| Test gap 4 — History/Settings durability tests | FR-13–16, SEC-06–07 | retention, migration, atomicity, I/O, validation, policy sync | M1–M2 / tasks 3–5, 13 |
| Test gap 5 — Clipboard race tests | FR-17–19 | replacement, ownership loss, expiry, denial, clear failure | M1 / tasks 7–8 |
| Test gap 6 — Frontend state tests | FR-21–24, UX-07 | partial startup, listeners, Authorization/disconnect, clear, rollback, copy | M3 / task 24 |
| Test gap 7 — Accessibility coverage | A11Y-01–06 | axe, keyboard, motion/transparency, contrast, zoom, VoiceOver | M3 / task 31 |
| Test gap 8 — CI and artifact verification | section 10, SEC-12 | mandatory gates and packaged install/sign/notarize/update | M1–M4 / tasks 1, 32–33 |
| Documentation gap 1 — conflicting Recent Code counts | FR-12–13 | README claim-to-schema/clean-checkout review | M4 / task 34 |
| Documentation gap 2 — unsupported macOS 10.13 claim | section 1, section 6.5 | macOS 13 compatibility matrix and README check | M4 / tasks 32, 34 |
| Documentation gap 3 — distributed OAuth configuration undefined | SEC-04 | public-client deployment and Google verification guide | M4 / tasks 11, 34 |
| Documentation gap 4 — stale project structure/architecture notes | section 8 | architecture-to-shipped-tree review | M4 / task 34 |
| Documentation gap 5 — missing privacy, threat, support, release, and recovery guides | SEC-08–12, FR-27–28 | docs claims, signed update, Diagnostics and recovery drills | M4 / tasks 30, 33–34 |
| Refinement — atomic acceptance/outbox | FR-09, FR-14, FR-29, section 9.4 | process-stop fault injection at every boundary | M2 / tasks 20–21 |
| Refinement — History Off session semantics | FR-12–13 | 15-minute/max-10/no-restart plus durable Seen tests | M2–M3 / tasks 5–6, 26 |
| Refinement — notification ownership | FR-20 | explicit request, grant/deny/revoke/System Settings | M2–M3 / tasks 14, 27 |
| Refinement — Start at Login ownership | FR-26 | default/reconcile/failure/native launch | M2–M3 / tasks 15, 27, 32 |
| Refinement — signed Update | FR-27, SEC-12 | metadata rejection and download/install/relaunch/rollback | M3–M4 / tasks 28–29, 33 |
| Refinement — Diagnostics privacy | FR-28, SEC-11 | exact preview/save canary redaction | M3–M4 / tasks 30, 34 |
| Refinement — encryption key loss/deletion limits | SEC-06–07 | missing-key recovery and confirmed deletion | M1 / tasks 3–4 |
| Refinement — reproducible performance | PERF-01–05 | documented baseline, raw samples, nearest-rank p95 | M4 / task 32 |

Every row is release-blocking until its required evidence is linked from the implementing pull request or release checklist.
