# Keep v2 Gmail-only behind a narrow Mailbox boundary

## Status

Accepted

## Context

Additional mailbox vendors would multiply Authorization, transport, fixture, support, and release risk while v2 must first correct Gmail security and lifecycle defects.

## Decision

OTPBar v2 supports Gmail only. Gmail is isolated behind a narrow Mailbox contract so intake and Message Interpretation do not depend on Gmail transport details, but v2 adds neither speculative provider infrastructure nor another adapter.

## Consequences

Gmail-specific Authorization, query, and status behavior remains in one adapter. A future Mailbox requires its own product validation, ADR, fixtures, privacy review, and release scope; the seam reduces coupling but does not promise plug-in compatibility.
