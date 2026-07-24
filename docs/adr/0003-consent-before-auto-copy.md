# Require consent before Auto-copy

## Status

Accepted

**Date:** 2026-07-24

## Context

Automatic clipboard mutation is convenient but security-sensitive, observable outside OTPBar, and surprising without informed consent.

## Decision

Auto-copy remains off until the user explicitly grants consent during onboarding or Settings. After consent, the user may configure a global policy and Provider-specific overrides; declining consent does not block monitoring or manual copy.

## Consequences

Legacy enabled preferences do not count as consent. Revoking consent disables Auto-copy and clears Provider overrides. Automatic effects are current-process, best-effort at-most-once attempts: durable intent metadata never contains the code, and no automatic effect replays after restart. Manual copy remains user-initiated and outside that effect mechanism.
