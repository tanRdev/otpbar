# Require consent before Auto-copy

## Status

Accepted

## Context

Automatic clipboard mutation is convenient but security-sensitive, observable outside OTPBar, and surprising without informed consent.

## Decision

Auto-copy remains off until the user explicitly grants consent during onboarding or Settings. After consent, the user may configure a global policy and Provider-specific overrides; declining consent does not block monitoring or manual copy.

## Consequences

Legacy enabled preferences do not count as consent. Revoking consent disables Auto-copy and clears Provider overrides. Automatic effects are best-effort at-most-once attempts, so a crash may lose an Auto-copy but must never repeat it after restart; manual copy remains user-initiated and outside that effect mechanism.
