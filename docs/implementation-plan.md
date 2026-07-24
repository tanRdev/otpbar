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

**Behavior-first tests:** Random 256-bit Keychain key, random nonce, authenticated round trip/tamper failure, temp-write/file-sync/replace/parent-sync failures, read-back revision verification.

**Acceptance criteria:** One application-readable Keychain key protects one snapshot; every failure preserves the last verified snapshot; no Secure Enclave/non-exportability claim.

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

**Acceptance criteria:** Recent Codes are never a second durable store; all restart semantics match FR-12/13.

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

**Behavior-first tests:** Old expiry cannot clear replacement; external change loses ownership without mutation; matching active lease clears once; cancel/shutdown/denial/failure are typed.

**Acceptance criteria:** One active lease maximum; exact-content and lease-identity checks precede clear.

**Dependencies:** 2.

**Risk:** Critical—directly closes RB-01.

## 8. Route manual copy through Clipboard Lease

**Objective:** Remove direct/manual clipboard timers without coupling to automatic effects.

**Expected files/modules:** Tauri copy command/adapter, command integration tests.

**Behavior-first tests:** Repeated user copies replace leases; errors return safely; exit never clears unrelated data.

**Acceptance criteria:** Manual copy remains user-initiated and never enters the effect outbox; no direct clear remains elsewhere.

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

**Acceptance criteria:** Public client needs only build-time client ID; full fake-provider journey passes before live Gmail.

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

**Acceptance criteria:** Only Off/1/7/30 and 15/30/60 are valid; no command reports false success.

**Dependencies:** 3.

**Risk:** High—split persistence must not create policy skew.

## 14. Implement notification permission ownership

**Objective:** Make permission request and enabled state explicit and recoverable.

**Expected files/modules:** `notifications/permission.rs`, Settings adapter.

**Behavior-first tests:** Default unknown/false; reject request before Authorization or without user action; requesting→granted enables; denial remains disabled and exposes System Settings; unavailable/error/retry; external revocation reconciles false.

**Acceptance criteria:** OS result is authoritative; denial never blocks intake.

**Dependencies:** 11, 13.

**Risk:** Medium—OS prompt cannot be undone programmatically.

## 15. Implement Start at Login desktop integration

**Objective:** Own macOS registration as a first-class v2 setting.

**Expected files/modules:** `desktop/start_at_login.rs`, Settings adapter.

**Behavior-first tests:** Default off; enable/disable success; OS failure retains prior value; external state drift reconciles; unavailable/retry; launch-at-login smoke.

**Acceptance criteria:** Settings is updated only after the OS result; UI receives authoritative state.

**Dependencies:** 13.

**Risk:** Medium—packaged registration differs from development.

## 16. Implement Gmail Mailbox transport

**Objective:** Isolate Gmail query, pagination, bounded fetch, and status semantics.

**Expected files/modules:** `mailbox/gmail.rs`, HTTP fixtures.

**Behavior-first tests:** Paging; four-request concurrency; authentication/permission/rate-limit/Retry-After/offline/server/malformed mappings; partial detail fetch and completeness.

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

**Acceptance criteria:** One owner/task; no wait under shared lock; no duplicate schedule.

**Dependencies:** 16, 18.

**Risk:** High—lifecycle races.

## 20. Implement atomic Message acceptance and effect outbox

**Objective:** Commit Seen Message, optional History, and pending effects as one snapshot.

**Expected files/modules:** `state_store/acceptance.rs`, `state_store/outbox.rs`, crash harness.

**Behavior-first tests:** Every section 9.4 boundary; no commit/no publication on each write/sync/replace failure; History Off still commits Seen/outbox; acceptance commit precedes Recent Code publication; pending→claimed→completed persistence.

**Acceptance criteria:** No partial acceptance state is representable; claimed is durable before external call; claimed is never retried after restart.

**Dependencies:** 3, 5, 6, 13, 14, 19.

**Risk:** Critical—defines duplicate/lost-effect semantics.

## 21. Implement automatic effect dispatcher and adapters

**Objective:** Execute best-effort at-most-once Auto-copy and notification attempts.

**Expected files/modules:** `effects/dispatcher.rs`, Auto-copy/notification adapters, integration fixtures.

**Behavior-first tests:** Pending resumes; claim commits before call; crash after claim/before call and after call/before completion never retries; startup completes interrupted claims; success/failure completion scrubs payload; 24-hour tombstone pruning; policy creates correct intents; clipboard uses Lease; notification omits OTP.

**Acceptance criteria:** A crash may lose an attempt but never duplicates it; manual copy is excluded.

**Dependencies:** 7, 14, 20.

**Risk:** Critical—external effects cannot be transactional.

## 22. Build the Privacy Projection

**Objective:** Compose authoritative non-secret metadata without masking uncertainty.

**Expected files/modules:** `privacy.rs`, owner metadata interfaces.

**Behavior-first tests:** Keychain/state/permission unavailable stays unknown; retention/capacity/Authorization scope match owners; clear and disconnect remain separate; no secret/content fields.

**Acceptance criteria:** Projection owns no duplicate constants and performs no independent storage reads.

**Dependencies:** 4–6, 11, 13–15, 20.

**Risk:** Medium—privacy copy must not overpromise.

## 23. Define the typed Desktop Session contract

**Objective:** Version snapshots, events, commands, and every production state.

**Expected files/modules:** `contracts/`, Rust DTOs, generated/validated TypeScript.

**Behavior-first tests:** Every section 4.2 state round-trips; stable safe errors; monotonic revisions; gap refresh; unknown future enum; no sensitive fields.

**Acceptance criteria:** One schema source; Rust/TypeScript compatibility gate; domain internals do not leak.

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

## 27. Build Settings, Privacy, notification, and Start at Login UI

**Objective:** Expose every approved control and destructive consequence.

**Expected files/modules:** Settings/Privacy screens, permission and registration controls, confirmations.

**Behavior-first tests:** Consent/policy; notification request/grant/deny/System Settings; Start at Login reconciliation; retention; save failures; unknown privacy; disconnect/delete separation; path actions.

**Acceptance criteria:** OS-owned settings never imply success early; destructive copy names retained/removed data.

**Dependencies:** 24.

**Risk:** High—permission/destructive semantics.

## 28. Implement the Update backend

**Objective:** Own signed metadata check, download, verification, install, and relaunch.

**Expected files/modules:** `update/`, updater configuration and fake feed.

**Behavior-first tests:** Current/available; offline/retry; malformed/unsigned/wrong-key metadata; download corruption/failure; install failure; relaunch handoff; current version preserved.

**Acceptance criteria:** No verification bypass; user action gates download/install; stable typed states.

**Dependencies:** 2, 12; final feed depends on 33.

**Risk:** Critical—supply-chain and destructive install path.

## 29. Build Update UI

**Objective:** Expose non-blocking check/download/install/relaunch and recovery.

**Expected files/modules:** update status/action components and Desktop Session extension.

**Behavior-first tests:** Every Update state; explicit initiation; progress; offline/verification/install error and retry; unsupported release.

**Acceptance criteria:** Existing code access remains usable; unsafe update cannot be forced through UI.

**Dependencies:** 24, 28.

**Risk:** High—state spans process relaunch.

## 30. Implement Diagnostics collection and preview

**Objective:** Produce a redacted support bundle the user can inspect exactly.

**Expected files/modules:** `diagnostics/`, preview/save UI, redaction fixtures.

**Behavior-first tests:** Explicit collection only; deterministic exact preview/save; exclude OTPs, tokens, Authorization/PKCE material, raw Message IDs, bodies, Mailbox Identity; collection/save failure; no upload.

**Acceptance criteria:** Saved bytes match preview; synthetic canary scan proves all prohibited fields absent.

**Dependencies:** 2, 22, 24.

**Risk:** Critical—support tooling can become a privacy leak.

## 31. Apply the complete visual system and accessibility pass

**Objective:** Make the assembled UI native-feeling, distinctive, compact, and WCAG 2.2 AA.

**Expected files/modules:** CSS/tokens/primitives, accessibility tests/checklist.

**Behavior-first tests:** Axe; names/states; keyboard/Escape/focus; target/type measurements; contrast; 200% zoom; Reduce Motion/Transparency; Increase Contrast; VoiceOver.

**Acceptance criteria:** No serious/critical violations, core text below 12 px, generic gradients/card dashboard, or inaccessible production state.

**Dependencies:** 25–27, 29–30.

**Risk:** Medium—cross-cutting styles land after behavior stabilizes.

## 32. Add native lifecycle and reproducible performance E2E

**Objective:** Prove native behavior and the documented baseline.

**Expected files/modules:** packaged-app harness, fixture server, network shaping, benchmark scripts, macOS 13 CI/self-hosted job.

**Behavior-first tests:** Tray/window; callback; cross-app clipboard; sleep/wake; notification denial; Start at Login; Update handoff; M1/8 GB/macOS 13.7 release-build metrics with 5 warmups + 30 samples and nearest-rank p95.

**Acceptance criteria:** Cold/warm definitions and raw metadata/samples are recorded; `macos-latest` is not treated as macOS 13 evidence.

**Dependencies:** 12, 19, 21, 28, 31.

**Risk:** High—native flake and host availability.

## 33. Replace release, signing, notarization, and feed automation

**Objective:** Produce the actual signed Tauri artifact and signed Update feed.

**Expected files/modules:** release workflow, entitlements, updater keys/config, verifier, release/recovery guide.

**Behavior-first tests:** Workflow schema; version mismatch; missing secrets; Tauri paths; codesign/spctl/stapler; checksum; signed metadata; clean install; prior-beta update/download/install/relaunch; invalid signature rejection.

**Acceptance criteria:** No Electron/dist references; protected job signs, notarizes, staples, verifies, publishes checksums/feed, and tests the exact artifact.

**Dependencies:** 12, 28, 32.

**Risk:** Critical—Apple/GitHub credentials and irreversible release.

## 34. Publish product, privacy, architecture, and showcase docs

**Objective:** Align public claims and maintainer guidance with v2.

**Expected files/modules:** `README.md`, privacy/threat/architecture/support/recovery docs, compatibility matrix, screenshots.

**Behavior-first tests:** Markdown/link check; clean-checkout commands; claim-to-owner review; canary scan of assets; macOS 13 and OAuth deployment review.

**Acceptance criteria:** Docs use canonical terms, explain History Off/key loss/deletion limits/updates/Diagnostics, and show synthetic portfolio-quality states.

**Dependencies:** 31, 33.

**Risk:** Medium—claims and assets can drift or leak data.

## 35. Final traceability, release candidate, and promotion

**Objective:** Prove the definition of done against one immutable artifact.

**Expected files/modules:** release evidence, traceability links, issues/milestone, release notes.

**Behavior-first tests:** All section 10 gates; every section 9.4 crash boundary; clean macOS 13/current journey; v1 migration/key-loss recovery; 7-day beta thresholds; VoiceOver/recovery drills.

**Acceptance criteria:** Every section 13 row links to evidence and a closed issue; tested checksum equals published signed/notarized artifact; no exception remains.

**Dependencies:** 1–34.

**Risk:** Critical—exceptions block stable promotion.

## Commit and ownership guidance

- Keep Authorization tasks 9–11, interpretation tasks 16–18, and intake/effect tasks 19–21 in separate reviews.
- The state-store primitive, migration, History projection, Seen Message ledger, and acceptance/outbox are tasks 3–6 and 20; they share one snapshot schema but separate invariants.
- After task 24, tasks 25–27, 29, and 30 may proceed only with disjoint component ownership; task 31 integrates styling afterward.
- Every pull request lists requirement IDs, crash/migration impact, named tests, screenshots for UI work, and rollback notes.
