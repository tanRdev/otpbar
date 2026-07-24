# OTPBar v2 implementation plan

This backlog implements the [modernization specification](modernization-spec.md). Tasks are dependency-ordered and sized for one reviewable conventional commit each. Production behavior is developed red-green-refactor: add the named failing behavior test, implement the smallest coherent module change, then run the affected and global gates. File names are expected targets, not a mandate to preserve current layout.

## 1. Establish enforceable local and CI quality gates

**Objective:** Make failures visible before security modules move.

**Expected files/modules:** `package.json`, frontend test/lint configuration, `src/test/`, Rust test support, `.github/workflows/build.yml`, `verify-build.sh`.

**Behavior-first tests:** Add one frontend reducer smoke test and one Rust fake-clock smoke test that fail before their runners exist; validate the workflow schema and demonstrate that an intentional lint failure fails CI.

**Acceptance criteria:** Frontend format/lint/typecheck/unit/build and Rust fmt/strict all-target clippy/test commands exist; `npm run verify` runs non-release local gates; no `|| true`; deterministic fake clock, filesystem, HTTP, Keychain, clipboard, and event collector fixtures are available.

**Dependencies:** Specification approval.

**Risk:** Medium—tooling churn can obscure product diffs; isolate it from behavior changes.

## 2. Define error, metadata, clock, storage, and redaction foundations

**Objective:** Give deep modules shared contracts without a global state bag.

**Expected files/modules:** `src-tauri/src/domain/error.rs`, `ports.rs`, `redaction.rs`, `storage.rs`, `src-tauri/src/lib.rs`.

**Behavior-first tests:** Machine errors serialize with stable code/retryability/safe message; atomic write survives injected write/rename failures; redaction snapshots contain no OTP, token, Authorization code, verifier, body, or raw Message ID.

**Acceptance criteria:** Side-effect ports are injectable; atomic storage returns typed failures and quarantines corrupt data; structured logs use redacted IDs; no production feature behavior changes yet.

**Dependencies:** 1.

**Risk:** Medium—over-generalization. Add only ports required by tasks 3–11.

## 3. Implement the Clipboard Lease core

**Objective:** Eliminate destructive clipboard races behind one authoritative service.

**Expected files/modules:** `src-tauri/src/clipboard_lease.rs`, clipboard/clock ports, lease unit tests.

**Behavior-first tests:** Older expiry cannot clear replacement; external clipboard change causes ownership loss without mutation; matching active lease clears once; write/read/clear denial is typed; cancel and shutdown are idempotent; 15/30/60-second validation.

**Acceptance criteria:** One active lease maximum; lease identity and exact content ownership are checked at expiry; fake-clock tests contain no sleeps; service emits all section 4.2 lease states.

**Dependencies:** 2.

**Risk:** High—OS clipboard behavior differs; keep the core pure and the adapter thin.

## 4. Route all copy paths through Clipboard Lease

**Objective:** Remove independent manual/automatic timers and expose lease status.

**Expected files/modules:** `src-tauri/src/main.rs` or command adapter, `src-tauri/src/types.rs`, Tauri clipboard adapter, integration tests.

**Behavior-first tests:** Manual then automatic copy replaces the same lease; two card copies leave only the latest active; command failure is returned; app exit never clears unrelated content.

**Acceptance criteria:** No clipboard timer or direct clear remains outside the module; both copy sources share one command path; RB-01 backend integration evidence passes.

**Dependencies:** 3.

**Risk:** High—touches current command/state wiring; do not combine with UI work.

## 5. Build public-client Authorization and safe loopback callback

**Objective:** Replace the OAuth happy path with a cancellable security state machine.

**Expected files/modules:** `src-tauri/src/authorization/`, refactored `gmail.rs`, `oauth_server.rs`, Keychain adapter, Authorization fixtures.

**Behavior-first tests:** Fresh verifier/challenge and state; mismatch stops exchange; bind occurs before browser open on an IP literal/ephemeral port; URL decoding and request limits; escaped fixed HTML; bind failure; cancellation; concurrent attempt replacement; timeout; denial; token refresh; Keychain failure; disconnect/re-authorize.

**Acceptance criteria:** Authorization owns every transition in section 4.2; no secret is required as confidential proof; no lock spans browser/network/storage waits; callback closes after one terminal result; credential/log scan passes.

**Dependencies:** 2.

**Risk:** Critical—security and platform integration. Review independently and test with a fake provider before Gmail.

## 6. Restrict Tauri CSP and capabilities

**Objective:** Minimize webview injection impact and IPC authority.

**Expected files/modules:** `src-tauri/tauri.conf.json`, `src-tauri/capabilities/`, command registration, CSP/capability tests.

**Behavior-first tests:** Production config rejects remote script/style and unsafe eval; main window can invoke only declared commands; unapproved window/plugin operations fail.

**Acceptance criteria:** Non-null narrow CSP; least-privilege capability inventory with rationale; production UI and OAuth callback still function; RB-05 evidence passes.

**Dependencies:** 1; coordinate final command list with 4 and 5.

**Risk:** High—Tauri config can fail only in packaged builds, so test a production bundle.

## 7. Create the Settings owner and consent migration

**Objective:** Centralize validated settings and ensure legacy Auto-copy is not consent.

**Expected files/modules:** `src-tauri/src/settings.rs`, migration from `preferences.rs`, settings schema/fixtures.

**Behavior-first tests:** Fresh defaults are consent unknown, Auto-copy off, 7-day History, 30-second lease; legacy enabled preference becomes consent unknown/off; valid patches increment revision; invalid duration/retention rejected; write failure returns old authoritative snapshot; consent revocation removes overrides.

**Acceptance criteria:** One owner supplies defaults/validation/persistence; only Off/1/7/30 and 15/30/60 accepted; commands never report false success; settings writes are atomic/versioned.

**Dependencies:** 2.

**Risk:** High—silent legacy behavior could mutate clipboard; migration must bias safe.

## 8. Implement encrypted Recent Code History and plaintext migration

**Objective:** Enforce the approved local History privacy policy.

**Expected files/modules:** `src-tauri/src/history/`, Keychain key adapter, migration/quarantine fixtures; retire current `history.rs`.

**Behavior-first tests:** Authenticated-encryption round trip and tamper failure; random nonce; 7-day/50-entry pruning; Off/1/7/30 transitions; atomic failure; corrupt quarantine; successful plaintext migrate/read-back/delete; failed migration preserves plaintext; restart idempotency; no plaintext fallback on Keychain failure.

**Acceptance criteria:** OTP fields are absent from files/logs in plaintext; successful upgrade deletes `code_history.json`; History loads before intake; all mutations return snapshots/errors; schema and key metadata are versioned.

**Dependencies:** 2, 7.

**Risk:** Critical—data loss or disclosure. Require fault-injection review and backup fixtures.

## 9. Implement the Seen Message Ledger

**Objective:** Make Message consideration idempotent independently of History.

**Expected files/modules:** `src-tauri/src/seen_messages.rs`, Keychain digest key adapter, ledger migration/store tests.

**Behavior-first tests:** Same Mailbox/Message is seen after restart; different Mailboxes do not collide; rejected Messages are recorded; History clear/Off does not affect ledger; 30-day and 10,000-entry pruning; tamper/corruption and storage failures are explicit.

**Acceptance criteria:** Ledger stores keyed identities and decision metadata only; no OTP/sender/subject/body/raw Message ID; lookup and commit are deterministic and independently retained.

**Dependencies:** 2.

**Risk:** High—incorrect identity creates duplicate effects or suppresses valid Messages.

## 10. Deepen Gmail Mailbox and Email Interpretation

**Objective:** Separate transport from deterministic MIME normalization and OTP classification.

**Expected files/modules:** `src-tauri/src/mailbox/`, `src-tauri/src/interpretation/`, Gmail/MIME fixtures and adversarial corpus.

**Behavior-first tests:** Pagination and bounded four-request concurrency; every non-2xx mapping; partial detail fetch; nested multipart/alternative; plain-over-HTML preference; charset/base64 errors; quoted reply exclusion; 4–8 digit contextual positives; dates, phone, currency, order/tracking, and old quoted code negatives; Provider inference.

**Acceptance criteria:** Gmail alone implements the narrow Mailbox contract; interpreter has no I/O; a check reports completeness; generic numeric matching requires contextual evidence; fixture corpus records rejection reasons.

**Dependencies:** 2, 5.

**Risk:** High—false positives and silent partial success. Tune against committed fixtures, not live inboxes.

## 11. Implement the cancellable OTP Intake owner

**Objective:** Coordinate monitoring, durable acceptance, effects, and health in one lifecycle.

**Expected files/modules:** `src-tauri/src/intake.rs`, scheduler/backoff, notification adapter, integration fixtures; remove polling logic from `main.rs`.

**Behavior-first tests:** Start only after migration/Authorization; stop within 1 second on disconnect/shutdown; restart cleanly; 8-second jittered schedule; Retry-After and 15-second-to-15-minute backoff; reset after complete success; partial fetch retry; repeated unread Message across restart produces one notification/Auto-copy; storage failure produces no committed effect; notification denial degrades locally.

**Acceptance criteria:** Exactly one intake owner/task; no network wait under shared lock; Seen/History commit precedes idempotent effects; complete Monitoring Health metadata is emitted; C-01–C-05 and RB-03 backend evidence passes.

**Dependencies:** 4, 5, 7, 8, 9, 10.

**Risk:** Critical—central correctness path. Keep notification integration separate from detection policy.

## 12. Build the Privacy Projection

**Objective:** Report authoritative, non-secret data without duplicating constants or masking uncertainty.

**Expected files/modules:** `src-tauri/src/privacy.rs`, owner metadata interfaces, projection tests.

**Behavior-first tests:** Keychain/storage unavailable remains unknown; retention/capacity matches History owner; scope/account matches Authorization; clearing History leaves Authorization/ledger; projection never includes OTP/token/raw Message ID.

**Acceptance criteria:** Projection performs no independent storage reads and owns no policy constants; partial values carry source status and recovery action; Reveal in Finder targets only validated local paths.

**Dependencies:** 5, 7, 8, 9.

**Risk:** Medium—privacy copy can overpromise; review wording against actual metadata.

## 13. Define the typed Desktop Session contract

**Objective:** Replace invoke mirroring with a versioned, coherent cross-boundary contract.

**Expected files/modules:** shared schema under `contracts/`, Rust DTO adapters, generated/validated `src/types/`, `src/lib/tauri.ts`, contract tests.

**Behavior-first tests:** Every section 4.2 state round-trips; stable machine errors; monotonic revisions; event gap requests a snapshot; stale/duplicate event is ignored; unknown future enum fails safely; secrets are absent.

**Acceptance criteria:** One source schema covers snapshots, events, and command envelopes; compatibility test runs in CI; commands return authoritative data; Rust domain types do not leak directly into UI.

**Dependencies:** 5, 7, 8, 11, 12.

**Risk:** High—wide compile-time impact. Land contract before reducer/components and freeze names during UI work.

## 14. Implement the frontend Desktop Session reducer and shell

**Objective:** Keep the app usable through partial startup and event races.

**Expected files/modules:** `src/session/`, `src/App.tsx`, error boundary, Tauri client/listener hooks, frontend fixtures.

**Behavior-first tests:** Boot to usable/degraded snapshots; command and event share reducer; duplicate/revision-gap behavior; listeners register once/clean up; clear History empties main list before resolve; failed settings save reconciles/rolls back; Authorization failure leaves Quit/settings/privacy available.

**Acceptance criteria:** No component maintains a competing Recent Code, Authorization, or lease truth; module errors render locally; ISSUE-001 and ISSUE-005 are closed by deterministic tests.

**Dependencies:** 13.

**Risk:** High—state migration can create transient duplicate truth; delete old state only after parity tests.

## 15. Build onboarding, Authorization, and health experience

**Objective:** Deliver first-launch consent and trustworthy primary status.

**Expected files/modules:** onboarding/auth/health components, shell header/menu, adaptive window controller, UI fixtures.

**Behavior-first tests:** Unsupported OS/configuration; restore/disconnected/awaiting/cancelled/denied/failed/connected; separate consent; healthy empty, checking, stale, offline, rate-limited, partial, permission denied; check-now/backoff actions; adaptive bounds.

**Acceptance criteria:** Mailbox identity and Monitoring Health are visible on the primary view; declining Auto-copy preserves manual copy/monitoring; all relevant production states have safe actions; menu separates Settings/Privacy/Disconnect/Quit.

**Dependencies:** 14.

**Risk:** Medium—dense content can overwhelm menubar space; validate at 320 × 420 and target 360 × 500.

## 16. Build Recent Codes and Clipboard Lease experience

**Objective:** Make code access and ownership status reliable and compact.

**Expected files/modules:** `CodeList`, `CodeCard`, lease status/toast/live-region components.

**Behavior-first tests:** Newest-first/empty/retention-Off; manual copy success/failure; automatic copy eligibility; replacement; expiry; ownership loss; permission denial; only authoritative lease shows countdown/status; notification contains no OTP.

**Acceptance criteria:** No per-card reconstructed timer; one primary copy action per code; feedback timing meets UX-05; codes remain accessible without Auto-copy; list handles 50 entries within performance budget.

**Dependencies:** 14.

**Risk:** Medium—OTP exposure via accessibility/notifications; review announced and displayed content explicitly.

## 17. Build Settings, Privacy, and destructive flows

**Objective:** Expose every approved control and make data consequences explicit.

**Expected files/modules:** Settings and Privacy screens, confirmation dialogs, path actions.

**Behavior-first tests:** Global/provider policy and consent rules; lease duration; retention changes/Off; saving/saved/validation/persistence states; unknown privacy metadata; copy/select/reveal paths; disconnect preserves History; delete preserves Authorization; combined delete; partial deletion.

**Acceptance criteria:** Effective Auto-copy policy is explained; errors do not imply saved state; destructive confirmation names retained/removed data; ISSUE-006 and S-02/S-03 are closed.

**Dependencies:** 14; avoid simultaneous edits with 15–16 by assigning disjoint component files.

**Risk:** High—destructive semantics and privacy claims; require product-copy review.

## 18. Apply the complete visual system and accessibility pass

**Objective:** Make the assembled UI distinctive, native-feeling, portfolio-quality, and WCAG 2.2 AA.

**Expected files/modules:** `src/index.css`, tokens/primitives/icons, component styles, accessibility tests and manual checklist.

**Behavior-first tests:** Axe zero serious/critical; named/checked Auto-copy; keyboard order/Escape/focus restoration; minimum target and type measurements; worst-case light/dark contrast; 200% zoom; Reduce Motion/Transparency and Increase Contrast snapshots.

**Acceptance criteria:** No core text below 12 px; required targets and contrast pass; all states are keyboard/VoiceOver usable on macOS 13/current; no generic gradient/card-dashboard treatment; stable opaque fallback works on hostile wallpapers.

**Dependencies:** 15, 16, 17.

**Risk:** Medium—cross-cutting CSS conflicts. Land after component structure stabilizes and freeze behavior.

## 19. Add native lifecycle, security, and performance E2E

**Objective:** Verify behaviors the web harness and unit ports cannot prove.

**Expected files/modules:** native test harness, fake OAuth provider, packaged-app scripts, performance fixtures, CI workflow.

**Behavior-first tests:** Tray open/close and bounded placement; callback lifecycle; clipboard changed by another app; sleep/wake/no duplicate poller; offline recovery; notification denial; signed-like production CSP; launch/check/storage p95 budgets.

**Acceptance criteria:** Runs on macOS in CI with documented local command; no fixed sleeps where observable readiness exists; macOS 13 and current compatibility jobs cover release-critical flows; performance baselines are stored and gated.

**Dependencies:** 6, 11, 18.

**Risk:** High—native E2E flakiness. Quarantine requires a linked issue and cannot remove blocker coverage.

## 20. Replace release, signing, notarization, and update automation

**Objective:** Produce and verify the actual Tauri artifact.

**Expected files/modules:** `.github/workflows/release.yml`, build workflow, `verify-build.sh`, entitlements, updater config, `docs/releasing.md`, `docs/recovery.md`.

**Behavior-first tests:** Workflow schema; tag/version mismatch; missing signing/notary secret; Tauri DMG path; codesign/spctl/stapler verification; checksum; clean install/launch; update from prior beta; invalid update signature rejection.

**Acceptance criteria:** No Electron/dist references; protected job signs with Developer ID, hardened runtime, notarizes, staples, verifies, and publishes checksum/update metadata; local verifier matches non-secret gates; secrets and rotation/recovery are documented without values.

**Dependencies:** 6, 19.

**Risk:** Critical—external Apple/GitHub credentials and irreversible release. Test draft prerelease before stable promotion.

## 21. Publish product, privacy, architecture, and showcase documentation

**Objective:** Align public claims and maintainer guidance with shipped v2.

**Expected files/modules:** `README.md`, `docs/privacy.md`, `docs/threat-model.md`, `docs/architecture.md`, `docs/support.md`, compatibility matrix, `screenshots/` and demo assets.

**Behavior-first tests:** Markdown/link checker; screenshot dimensions/current-state review; secret/OTP metadata scan; README commands execute from clean checkout; privacy claims map to owner metadata and tests.

**Acceptance criteria:** README states macOS 13+, consent-first Auto-copy, encrypted finite History, Gmail-only scope, public-client setup, actual build path, and support path; architecture uses canonical language; portfolio-quality screenshots show healthy, code, settings, and degraded states without real personal data.

**Dependencies:** 18, 20.

**Risk:** Medium—docs can drift or leak sample secrets. Generate assets from deterministic synthetic fixtures.

## 22. Final traceability, release candidate, and promotion

**Objective:** Prove the definition of done against one immutable artifact.

**Expected files/modules:** release checklist/evidence, traceability links in this spec, GitHub issues/milestone, release notes.

**Behavior-first tests:** Run every gate from section 10; clean macOS 13/current journey from install through uninstall; migration from a fixture copy of v1; 7-day beta rollback thresholds; manual VoiceOver and recovery drills.

**Acceptance criteria:** Every section 13 row links to passing evidence and a closed issue; no ignored failures, plaintext History, secrets, or unresolved release blockers; signed/notarized artifact checksum matches tested artifact; beta thresholds pass before stable promotion.

**Dependencies:** 1–21.

**Risk:** Critical—schedule pressure encourages exceptions. Any exception reopens the finding and blocks stable release.

## Commit and ownership guidance

- Keep tasks 3–6 in separate reviews because Clipboard, Authorization, and Tauri security have different failure modes.
- Tasks 8 and 9 use separate files and keys; do not merge their persistence models.
- After task 13 lands, tasks 15–17 may proceed in parallel only with disjoint component ownership; task 18 integrates styling afterward.
- Every pull request lists requirement IDs, test names, migration impact, screenshots for UI changes, and rollback notes.
- Use conventional commit subjects such as `feat(auth): secure native authorization flow` or `test(intake): cover repeated unread messages`.
