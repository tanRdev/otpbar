# OTPBar v2 implementation plan

This backlog implements the [modernization specification](modernization-spec.md). Tasks are dependency-ordered and each is one reviewable conventional commit. Every behavior task begins with the named failing test, implements only that boundary, then runs affected and global gates.

## 1. Establish enforceable quality gates

**Objective:** Make frontend, Rust, contract, security, and workflow failures blocking.

**Expected files/modules:** `package.json`, lint/test configuration, test support, `.github/workflows/build.yml`, `verify-build.sh`.

**Behavior-first tests:** Frontend reducer and Rust fake-clock smoke tests fail before runners exist; intentional lint/workflow-schema failures fail the gate.

**Acceptance criteria:** Format, lint, typecheck, test, strict all-target clippy, build, and workflow validation commands exist with no ignored failures.

**Dependencies:** Specification approval.

**Risk:** Medium—keep tooling changes separate from product behavior.

## 2. Define errors, ports, clocks, and redaction

**Objective:** Give deep modules typed failure and injectable side-effect boundaries.

**Expected files/modules:** `domain/error.rs`, `ports.rs`, `clock.rs`, `redaction.rs`.

**Behavior-first tests:** Error envelopes are stable/safe; redaction excludes OTPs, credentials, Authorization/PKCE material, raw Message IDs, bodies, and Mailbox Identity.

**Acceptance criteria:** Only ports required by later tasks are introduced; no feature behavior changes.

**Dependencies:** 1.

**Risk:** Medium—avoid a speculative framework.

## 3. Build the encrypted atomic state-store primitive

**Objective:** Implement the single versioned snapshot and crash-safe replacement protocol.

**Expected files/modules:** `state_store/crypto.rs`, `state_store/io.rs`, Keychain key port, fault-injection fixtures.

**Behavior-first tests:** Random 256-bit Keychain key, random nonce, authenticated round trip/tamper failure; pre-replace failures are uncommitted; replace success plus parent-fsync error blocks recovery and immediate read-back is forbidden; same-process fsync retry success then expected-new read-back; original successful barrier plus prior/unreadable/mismatch recovers; crash-before-retry restart loads surviving prior/new/unreadable.

**Acceptance criteria:** Parent-directory fsync is the durability barrier. A failed barrier cannot be resolved by read-back or publish/effects; only a later successful barrier permits expected-new verification. Restart may accept surviving prior anew or adopt surviving new while canceling effects. No Secure Enclave/non-exportability claim.

**Dependencies:** 2.

**Risk:** Critical—cryptography and durability require focused review.

## 4. Implement state migration and key-loss recovery

**Objective:** Migrate legacy plaintext without data loss or false secure-erasure claims.

**Expected files/modules:** `state_store/migration.rs`, recovery states/UI contract fixtures.

**Behavior-first tests:** Verified migrate/read-back/delete; failure before commit preserves plaintext; crash after commit resumes deletion; missing key/tamper/unknown schema stays read-only; deletion of unreadable new store requires confirmation.

**Acceptance criteria:** Migration is restart-safe; intake stays stopped during recovery; docs/UI disclose APFS/SSD deletion limits and downgrade requires confirmed local-data deletion.

**Dependencies:** 3.

**Risk:** Critical—key loss is unrecoverable.

## 5. Implement History and Recent Code projection policies

**Objective:** Separate durable History from the bounded Desktop Session projection.

**Expected files/modules:** `state_store/history.rs`, `recent_codes.rs`.

**Behavior-first tests:** History Off/1/7/30 and 50-entry cap; enabled restart restores latest 10 unexpired entries; Off shows current arrivals 15 minutes/max 10 and restores none after exit; expiry and clear publish coherent snapshots.

**Acceptance criteria:** Recent Codes are never a second durable store; all restart semantics match FR-12/13; History commands update and test their Tauri capabilities.

**Dependencies:** 3.

**Risk:** High—confusing History with presentation recreates the audit defect.

## 6. Implement the Seen Message ledger

**Objective:** Persist idempotency independently from History retention.

**Expected files/modules:** `state_store/seen_messages.rs`.

**Behavior-first tests:** Same Mailbox Identity/Message is seen after restart; different Mailboxes do not collide; rejected Messages persist; History Off/clear does not alter ledger; 30-day/10,000-entry pruning.

**Acceptance criteria:** Only keyed identities, decision, and time persist; no raw Message ID or content.

**Dependencies:** 3.

**Risk:** High—bad identity either duplicates effects or suppresses valid Messages.

## 7. Implement Clipboard Lease core

**Objective:** Make clipboard ownership replaceable and safe.

**Expected files/modules:** `clipboard_lease.rs`, fake clipboard/clock.

**Behavior-first tests:** Old expiry cannot clear replacement; external change loses ownership without mutation; an atomic fake adapter clears a matching active lease once; an adapter without atomic compare-and-clear fails closed and reports degraded expiry; cancel/shutdown/denial/failure are typed.

**Acceptance criteria:** One active lease maximum; only an adapter-owned atomic compare-and-clear may clear; adapters without atomic ownership proof relinquish the lease and leave content unchanged.

**Dependencies:** 2.

**Risk:** Critical—directly closes RB-01.

## 8. Route manual copy through Clipboard Lease

**Objective:** Remove direct/manual clipboard timers without coupling to automatic effects.

**Expected files/modules:** Tauri copy command/adapter, command integration tests.

**Behavior-first tests:** Repeated user copies replace leases and cancel stale timers; errors return safely; exit never clears unrelated data; the Tauri adapter's missing atomic primitive produces a redacted degraded event and leaves content unchanged.

**Acceptance criteria:** Manual copy remains user-initiated and never enters the effect outbox; no read-then-clear or direct clear remains elsewhere; fail-closed expiry is disclosed; the command capability is updated and allow/deny tested in this commit.

**Dependencies:** 7.

**Risk:** High—current command wiring is shared state.

## 9. Implement Authorization state and PKCE core

**Objective:** Model one cancellable public-client Authorization attempt without transport.

**Expected files/modules:** `authorization/core.rs`, PKCE/state generator, fake ports.

**Behavior-first tests:** Fresh verifier/challenge and 128-bit state; constant-time mismatch; cancellation, timeout, denial, concurrent replacement, disconnect/restart transitions.

**Acceptance criteria:** Pure state transitions cover section 4.2; no browser/network wait or client secret.

**Dependencies:** 2.

**Risk:** Critical—security state machine.

## 10. Implement the loopback callback adapter

**Objective:** Safely receive one native OAuth callback.

**Expected files/modules:** `authorization/loopback.rs`, callback integration fixtures.

**Behavior-first tests:** Bind IP literal port 0 before success; strict path/method/host; one decode; size/time limits; one terminal callback; escaped fixed HTML; bind/cancel/concurrency failures.

**Acceptance criteria:** Listener lifecycle is owned and closes deterministically; no raw provider string is reflected.

**Dependencies:** 9.

**Risk:** Critical—hostile local input.

## 11. Implement credential and Google Authorization adapters

**Objective:** Connect the core to browser, token exchange/refresh, Keychain, and Gmail identity.

**Expected files/modules:** `authorization/google.rs`, `authorization/credentials.rs`, fake provider integration.

**Behavior-first tests:** Build Authorization URL; exchange/refresh mappings; Keychain write/read/delete failure; Mailbox Identity restore; disconnect and clean reauthorization; no lock across I/O.

**Acceptance criteria:** Public client needs only build-time client ID; full fake-provider journey passes before live Gmail; Authorization commands update and test least-privilege capabilities.

**Dependencies:** 9, 10.

**Risk:** Critical—credential disclosure and lifecycle.

## 12. Restrict Tauri CSP and capabilities

**Objective:** Minimize webview and IPC authority.

**Expected files/modules:** `tauri.conf.json`, capabilities, command registration tests.

**Behavior-first tests:** Remote/unsafe scripts fail; only the main window and declared commands/plugins succeed.

**Acceptance criteria:** Narrow non-null CSP and least-privilege inventory pass in a production bundle.

**Dependencies:** 1; coordinate command names after 8 and 11.

**Risk:** High—packaged behavior can differ from development.

## 13. Implement Settings and acceptance-policy synchronization

**Objective:** Own defaults, validation, consent, and policy inputs shared with acceptance.

**Expected files/modules:** `settings.rs`, settings migration, atomic snapshot policy adapter.

**Behavior-first tests:** Consent unknown/off, 7-day History, 30-second lease, notifications false/unknown, Start at Login false; legacy enabled Auto-copy is not consent; revisions, invalid values, write failure, consent revocation; policy update reaches acceptance snapshot before success.

**Acceptance criteria:** Only Off/1/7/30 and 15/30/60 are valid; no command reports false success; Settings commands update and test capabilities.

**Dependencies:** 3.

**Risk:** High—split persistence must not create policy skew.

## 14. Implement notification permission ownership

**Objective:** Make permission request and enabled state explicit and recoverable.

**Expected files/modules:** `notifications/permission.rs`, Settings adapter.

**Behavior-first tests:** Default unknown/false; reject request before Authorization or without user action; requesting→granted enables; denial remains disabled and exposes System Settings; unavailable/error/retry; external revocation reconciles false.

**Acceptance criteria:** OS result is authoritative; denial never blocks intake; permission commands update and test capabilities.

**Dependencies:** 11, 13.

**Risk:** Medium—OS prompt cannot be undone programmatically.

## 15. Implement Start at Login desktop integration

**Objective:** Own macOS registration as a first-class v2 setting.

**Expected files/modules:** `desktop/start_at_login.rs`, Settings adapter.

**Behavior-first tests:** Default off; request failure; successful OS mutation; read-back old/new/failure; Desktop Session adopts observed value before persistence; persistence failure reports degraded/retry without claiming prior OS state; crash at request/mutation/read-back/persist; launch adopts external drift without mutating macOS.

**Acceptance criteria:** macOS registration is authoritative; launch adopts observed state; persistence follows read-back; commands update/test capabilities.

**Dependencies:** 13.

**Risk:** Medium—packaged registration differs from development.

## 16. Implement Gmail Mailbox transport

**Objective:** Isolate Gmail query, pagination, bounded fetch, and status semantics.

**Expected files/modules:** `mailbox/gmail.rs`, HTTP fixtures.

**Behavior-first tests:** Paging; four-request concurrency; Authorization/credential, permission, rate-limit/Retry-After, offline, server, and malformed mappings; partial detail fetch and completeness.

**Acceptance criteria:** Read-only scope; no interpretation logic; every non-2xx is typed.

**Dependencies:** 11.

**Risk:** High—silent partial success.

## 17. Implement MIME Message normalization

**Objective:** Convert transport payloads into deterministic Message content.

**Expected files/modules:** `interpretation/mime.rs`, fixture corpus.

**Behavior-first tests:** Nested multipart, plain-over-HTML, HTML-only sanitization, charset/base64 failure, attachment exclusion, quoted reply removal.

**Acceptance criteria:** Pure/no I/O; invalid content returns an explicit rejection reason.

**Dependencies:** 2.

**Risk:** High—real-world MIME complexity.

## 18. Implement OTP classification and Provider inference

**Objective:** Rank candidates while controlling false positives.

**Expected files/modules:** `interpretation/classifier.rs`, positive/adversarial corpus.

**Behavior-first tests:** Contextual 4–8 digit positives; multi-candidate ranking; dates, phones, currency, orders, tracking, and quoted older codes negatives; Provider inference/unknown.

**Acceptance criteria:** Generic numeric fallback requires OTP-language proximity; every rejection is explainable.

**Dependencies:** 17.

**Risk:** High—false positives can leak unrelated numbers.

## 19. Implement intake scheduler and Monitoring Health

**Objective:** Own one cancellable monitoring lifecycle without acceptance effects.

**Expected files/modules:** `intake/scheduler.rs`, backoff/health tests.

**Behavior-first tests:** Start only after migration/Authorization; stop within 1 second on disconnect/shutdown; clean restart; 8-second ±10% jitter; Retry-After; 15-second-to-15-minute backoff; reset; partial/stale/offline/sleep-wake.

**Acceptance criteria:** One owner/task; no wait under shared lock; no duplicate schedule; check/start/stop command changes update and test capabilities.

**Dependencies:** 16, 18.

**Risk:** High—lifecycle races.

## 20. Implement atomic Message acceptance and effect outbox

**Objective:** Resolve Seen Message, optional History, and payload-free effect metadata as one snapshot commit.

**Expected files/modules:** `state_store/acceptance.rs`, `state_store/outbox.rs`, crash harness.

**Behavior-first tests:** Every section 9.4 boundary; failures before replace are uncommitted; failed post-replace barrier blocks immediate read-back/publication/effects; same-process barrier retry must succeed before expected-new-only verification; original barrier mismatch recovers; crash-before-retry surviving prior may reaccept, surviving new is authoritative with effects canceled, unreadable recovers; History Off and payload-free durability.

**Acceptance criteria:** Indeterminate durability never masquerades as rollback/success. In-process recovery retries the barrier, not read-back; verified expected new is the only publish path. Restart follows surviving authenticated revision and never replays effects; no partial acceptance or durable sensitive effect payload is representable.

**Dependencies:** 3, 5, 6, 13, 14, 19.

**Risk:** Critical—defines duplicate/lost-effect semantics.

## 21. Implement automatic effect dispatcher and adapters

**Objective:** Execute best-effort at-most-once Auto-copy and notification attempts.

**Expected files/modules:** `effects/dispatcher.rs`, Auto-copy/notification adapters, integration fixtures.

**Behavior-first tests:** Current-process in-memory OTP survives only through claim/attempt; claim commits before call; restart cancels pending/claimed without execution; no replay; 5-minute active metadata expiry; 24-hour tombstone pruning; clear/delete cancels metadata and memory before History; clipboard uses Lease; notification omits OTP.

**Acceptance criteria:** Durable store contains metadata only; claim durability barrier and expected-new verification complete before the external call; crash may lose an attempt and never replays it; successful delete guarantees no later matching effect; manual copy is excluded.

**Dependencies:** 7, 14, 20.

**Risk:** Critical—external effects cannot be transactional.

## 22. Build the Privacy Projection

**Objective:** Compose authoritative non-secret metadata without masking uncertainty.

**Expected files/modules:** `privacy.rs`, owner metadata interfaces.

**Behavior-first tests:** Keychain/state/permission unavailable stays unknown; retention/capacity/Authorization scope match owners; clear and disconnect remain separate; no secret/content fields.

**Acceptance criteria:** Projection owns no duplicate constants and performs no independent storage reads; commands update and test capabilities.

**Dependencies:** 4–6, 11, 13–15, 20.

**Risk:** Medium—privacy copy must not overpromise.

## 23. Define the typed Desktop Session contract

**Objective:** Freeze snapshots, events, commands, and every production state before UI/module integration.

**Expected files/modules:** `contracts/`, Rust DTOs, generated/validated TypeScript.

**Behavior-first tests:** Every section 4.2 state round-trips, including complete History, Update, Diagnostics/beta, Start at Login degraded, and storage-recovery states; stable safe errors; monotonic revisions; gap refresh; unknown future enum; no sensitive fields.

**Acceptance criteria:** One frozen public schema source includes all later owners; Rust/TypeScript compatibility gate; later tasks conform without extension; contract/capability command names align.

**Dependencies:** 11, 13–15, 20–22.

**Risk:** High—wide compile-time surface.

## 24. Implement the Desktop Session reducer and resilient shell

**Objective:** Reconcile command/event state and preserve usable modules.

**Expected files/modules:** `src/session/`, `App.tsx`, listener hooks.

**Behavior-first tests:** Partial boot; duplicate/gap events; one listener/cleanup; clear reconciliation; settings rollback; failed Authorization; enabled/Off restart projections.

**Acceptance criteria:** Components own no competing Authorization, Recent Code, or Clipboard Lease truth.

**Dependencies:** 23.

**Risk:** High—temporary dual state.

## 25. Build onboarding, Authorization, and health UI

**Objective:** Deliver consent-first onboarding and trustworthy monitoring.

**Expected files/modules:** onboarding/Authorization/health components, shell menu, adaptive window.

**Behavior-first tests:** Compatibility/configuration; all Authorization/consent/health states; explicit notification request after Authorization; adaptive bounds.

**Acceptance criteria:** Mailbox Identity and Monitoring Health are primary; decline preserves manual copy/monitoring; Disconnect terminology is consistent.

**Dependencies:** 24.

**Risk:** Medium—dense menubar content.

## 26. Build Recent Codes and Clipboard Lease UI

**Objective:** Present session codes and authoritative copy ownership.

**Expected files/modules:** code list/card and lease status/live region.

**Behavior-first tests:** Enabled restart; History Off 15-minute/max-10/no-restart; manual/automatic copy, replacement, expiry, ownership loss, failure.

**Acceptance criteria:** No card-local timer; list never exceeds 10; manual copy remains available.

**Dependencies:** 24.

**Risk:** Medium—avoid exposing codes in announcements.

## 27. Build the complete History view

**Objective:** Expose every retained History entry independently from Recent Codes.

**Expected files/modules:** History route/view, search, row actions, empty/loading/error states.

**Behavior-first tests:** Load/search Provider, Message Origin, and code; copy/delete one; clear all; all 50 entries; delete failure; retention Off hides navigation and direct entry is empty/inaccessible.

**Acceptance criteria:** Recent Codes remain capped at 10; History renders up to 50; destructive actions cancel matching effects first; commands/capabilities update together.

**Dependencies:** 24, 26.

**Risk:** High—must not leak session-only codes into History.

## 28. Build Settings, Privacy, notification, and Start at Login UI

**Objective:** Expose every approved control and destructive consequence.

**Expected files/modules:** Settings/Privacy screens, permission and registration controls, confirmations.

**Behavior-first tests:** Consent/policy; notification grant/deny; Start at Login request→read-back→observed UI→persist, persistence degradation/retry, restart drift adoption; retention; disconnect/delete; paths.

**Acceptance criteria:** macOS state is authoritative; no false rollback claim; destructive copy names retained/removed data.

**Dependencies:** 24.

**Risk:** High—permission/platform/destructive semantics.

## 29. Implement the Update backend

**Objective:** Conform signed metadata check, download, verification, install, and relaunch to the frozen contract.

**Expected files/modules:** `update/`, updater configuration, fake feed, capability declaration.

**Behavior-first tests:** Current/available; offline/retry; malformed/unsigned/wrong-key metadata; download corruption/failure; install failure; relaunch handoff; allow/deny capability.

**Acceptance criteria:** No verification bypass; user action gates download/install; no contract extension.

**Dependencies:** 12, 23.

**Risk:** Critical—supply chain and install path.

## 30. Build Update UI

**Objective:** Render the frozen Update contract without extending it.

**Expected files/modules:** Update status/action components.

**Behavior-first tests:** Every predeclared Update state; initiation; progress; offline/verification/install error/retry; unsupported release.

**Acceptance criteria:** Current version stays usable; unsafe update cannot be forced; contract remains unchanged.

**Dependencies:** 24, 29.

**Risk:** High—state spans relaunch.

## 31. Implement Diagnostics, preview, and local beta counters

**Objective:** Conform Diagnostics to the frozen contract and keep all collection local/consensual.

**Expected files/modules:** `diagnostics/`, preview/save UI, counter store, capability declaration.

**Behavior-first tests:** Exact preview/save; prohibited-field canaries; no upload; opt-in/out; launches and previous-run crash markers; aggregate-only explicit export; counting across restart; allow/deny capability.

**Acceptance criteria:** No OTP, credential, Message ID/body, Mailbox Identity, or automatic submission; saved/exported bytes exactly match preview.

**Dependencies:** 2, 22–24.

**Risk:** Critical—support/beta evidence can become surveillance.

## 32. Apply the visual system and accessibility pass

**Objective:** Make all screens native-feeling, distinctive, compact, and WCAG 2.2 AA.

**Expected files/modules:** CSS/tokens/primitives, accessibility tests/checklist.

**Behavior-first tests:** Axe; names/states; keyboard/focus; targets/type; contrast; zoom; motion/transparency; VoiceOver, including History/Update/Diagnostics.

**Acceptance criteria:** No serious/critical violations, undersized core text, generic dashboard treatment, or inaccessible state.

**Dependencies:** 25–28, 30–31.

**Risk:** Medium—land after behavior stabilizes.

## 33. Add native lifecycle E2E

**Objective:** Prove native lifecycle and OS integrations independently from benchmarks.

**Expected files/modules:** packaged-app harness and macOS 13/current CI jobs.

**Behavior-first tests:** Tray/window, callback, cross-app clipboard, sleep/wake, notification denial, Start at Login request/read-back/restart/drift, Update handoff.

**Acceptance criteria:** Deterministic readiness replaces fixed sleeps; macOS 13 evidence is explicit.

**Dependencies:** 12, 19, 21, 29, 32.

**Risk:** High—native flake.

## 34. Build reproducible performance benchmark infrastructure

**Objective:** Enforce the exact M1/macOS 13.7 performance baseline.

**Expected files/modules:** fixture server, network shaping, benchmark scripts, raw-sample schema.

**Behavior-first tests:** Validate cold/warm setup, 5 warmups/30 samples, nearest-rank calculation, machine/power/build metadata, shaping parameters, regression failure.

**Acceptance criteria:** Raw samples reproduce p95; `macos-latest` is not baseline evidence.

**Dependencies:** 19, 21, 32.

**Risk:** High—host variance.

## 35. Build artifact signing and notarization

**Objective:** Produce and verify the actual Tauri artifact.

**Expected files/modules:** release workflow, entitlements, artifact verifier, release guide.

**Behavior-first tests:** Workflow schema/version/secrets/Tauri paths; codesign, hardened runtime, notarization, stapling, checksum, clean install/launch.

**Acceptance criteria:** No Electron references; protected job tests the exact published artifact.

**Dependencies:** 12, 33–34.

**Risk:** Critical—Apple credentials and distribution.

## 36. Publish the signed Update feed

**Objective:** Generate signed metadata for the verified artifact as a separate release step.

**Expected files/modules:** feed workflow, updater key/config, publication guide.

**Behavior-first tests:** Correct artifact/version/checksum; valid signature; missing/wrong key; tampered metadata/artifact; atomic publication.

**Acceptance criteria:** Only task 35's verified artifact is referenced; feed failure cannot publish a release as update-ready.

**Dependencies:** 29, 35.

**Risk:** Critical—supply-chain metadata.

## 37. Verify prior-beta update installation

**Objective:** Prove download, install, relaunch, and failure recovery from the previous signed beta.

**Expected files/modules:** clean-host update matrix and rollback evidence.

**Behavior-first tests:** Valid update; offline/retry; invalid metadata/payload rejection; interrupted download; install/relaunch failure; current version preservation/rollback.

**Acceptance criteria:** Exact signed feed/artifact from tasks 35–36 passes macOS 13/current.

**Dependencies:** 30, 35–36.

**Risk:** Critical—destructive cross-version path.

## 38. Publish product, privacy, architecture, and showcase docs

**Objective:** Align public claims and maintainer guidance with v2.

**Expected files/modules:** README, privacy/threat/architecture/support/recovery docs, compatibility matrix, screenshots.

**Behavior-first tests:** Links/commands/claims; canary scan; macOS/OAuth; History view/Off, commit recovery, effect privacy, Update, Diagnostics/beta disclosure.

**Acceptance criteria:** Canonical terms and synthetic portfolio-quality assets; no automatic-analytics claim.

**Dependencies:** 32, 35–37.

**Risk:** Medium—claims/assets can drift or leak.

## 39. Run the controlled opt-in beta

**Objective:** Produce auditable crash-free evidence without automatic analytics.

**Expected files/modules:** release-captain ledger/template, tester instructions, aggregate export verifier.

**Behavior-first tests:** Consent required; opt-out; active marker set at launch/cleared on clean exit; prior-active marker increments one crash; counters-only export; release-captain out-of-band cohort slot replaces prior submission instead of double-counting; threshold calculation.

**Acceptance criteria:** At least 200 launches from at least 10 testers, `crashes / launches ≤ 0.005` (at most 1 crash at 200 launches), zero security/data-loss incidents, explicit exports only, and 7-day observation.

**Dependencies:** 31, 35–38.

**Risk:** High—small samples and privacy.

## 40. Final capability audit, traceability, and promotion

**Objective:** Prove one immutable artifact and its complete command authority.

**Expected files/modules:** generated command/capability inventory, release evidence, issue/milestone, release notes.

**Behavior-first tests:** Enumerate every command against exactly one least-privilege declaration; deny orphan permissions/commands; all gates, crash boundaries, clean journeys, migration/recovery, beta ledger.

**Acceptance criteria:** Inventory is exact, every traceability row links evidence, published checksums match, and no exception remains.

**Dependencies:** 1–39.

**Risk:** Critical—exceptions block promotion.

## Commit and ownership guidance

- Keep Authorization 9–11, interpretation 16–18, and intake/effects 19–21 in separate reviews.
- Tasks 3–6 and 20 share one snapshot schema but separate invariants.
- Every task that adds or changes a Tauri command updates its least-privilege capability declaration and allow/deny test in the same commit; task 40 audits the final inventory.
- The public Desktop Session contract freezes in task 23 with History, Update, and Diagnostics/beta states; later tasks conform without extension.
- Every pull request lists requirements, crash/migration impact, capabilities, named tests, screenshots for UI work, and rollback notes.
