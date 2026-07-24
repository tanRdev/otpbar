# OTPBar modernization spec — proposed structure

## Document contract

- **Type:** explanation-led product and engineering specification
- **Audience:** senior engineer or small implementation team taking ownership
  of the repository
- **Reader goal:** understand the current risks, choose a target product
  contract, and implement the modernization in safe, reviewable phases
- **Included:** macOS menubar UX, Gmail authorization and ingestion, OTP
  detection, clipboard behavior, local data/privacy, frontend/backend
  architecture, testing, CI/release, observability, migration, and acceptance
  criteria
- **Excluded:** mobile/Windows support, additional mailbox providers, cloud
  sync, and a framework rewrite unless the product decisions explicitly add
  them

## Proposed table of contents

1. **Executive decision record**
   - Current disposition, release blockers, security blockers, and the
     recommended modernization strategy.
2. **Product definition and domain language**
   - Define Authorization, Mailbox, Message, Detected OTP, Provider, Seen
     Message, Recent Code, History, Auto-copy, and Clipboard Lease.
3. **Current-state audit**
   - Evidence-backed findings grouped by security, correctness, UX,
     accessibility, architecture, tests, operations, documentation, and
     release engineering.
4. **Target user journeys**
   - First launch, authorization, healthy monitoring, code arrival, manual
     copy, clipboard expiry, missing-code recovery, settings, privacy/history,
     sign-out, offline/rate-limited/error, and update/release.
5. **Target experience and visual system**
   - Information hierarchy, shell/navigation model, typography, density,
     surfaces, interaction states, accessibility requirements, and screen-level
     requirements for every state.
6. **Functional requirements**
   - Gmail query semantics, MIME handling, detection confidence, deduplication,
     retention, notification, auto-copy policy, clipboard ownership, settings,
     error recovery, and lifecycle behavior.
7. **Security and privacy requirements**
   - OAuth PKCE/state/loopback requirements, credential handling, Tauri CSP and
     capabilities, local OTP storage decision, redaction, deletion semantics,
     and threat-model acceptance criteria.
8. **Target architecture**
   - Deep modules and their interfaces: authorization, mailbox,
     email interpretation, OTP intake, seen-message ledger, recent-code
     history, clipboard lease, settings, privacy projection, and desktop
     session.
9. **Data model and migrations**
   - Versioned durable schemas, atomic writes, corruption handling, retention,
     upgrade/downgrade policy, and migration from the current files/Keychain
     items.
10. **Verification strategy**
    - Unit, contract, fixture, integration, frontend, accessibility, native E2E,
      security, performance, and release tests with explicit quality gates.
11. **Delivery plan**
    - Sequenced milestones that first stop unsafe behavior, then establish deep
      modules, then redesign UI, then harden distribution.
12. **Acceptance criteria and definition of done**
    - Measurable release criteria, non-goals, rollout checks, and follow-up
      decisions.
13. **Finding-to-requirement traceability**
    - Map every audit finding to a requirement, test, milestone, and final
      disposition so no problem is lost during implementation.

## Decisions required before the full draft

1. Should OTP history remain on disk, become encrypted with a finite default
   retention, or be removed entirely?
2. Should OTPBar remain Gmail-only for this modernization, while keeping the
   internal Mailbox module narrow enough for a future second adapter?
3. Should automatic copy stay enabled by default, or require explicit opt-in
   during onboarding?
4. Should the product remain a fixed-size 320 × 420 popover, or may the new
   information hierarchy modestly increase its width/height?
