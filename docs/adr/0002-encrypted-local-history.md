# Retain a small encrypted local History

## Status

Accepted

**Date:** 2026-07-24

## Context

Missing-code recovery is useful, but one-time passcodes and Message metadata are sensitive. Plaintext indefinite retention contradicts the product's privacy claim, while removing all durable idempotency would allow repeated effects after restart.

## Decision

OTPBar keeps one local, versioned, encrypted atomic state snapshot containing durable History, the Seen Message ledger, and payload-free effect-intent metadata. History defaults to 7 days, is capped at 50, and offers Off, 1 day, 7 days, or 30 days; the Seen Message ledger remains durable when History is Off. A random application-readable 256-bit symmetric key lives in macOS Keychain. Verified migration commits and reads back the encrypted snapshot before deleting legacy plaintext. No state is cloud-synced.

## Consequences

Keychain access is required and key loss makes encrypted state unrecoverable. OTPBar offers confirmed deletion of an unreadable new store, but cannot recover it; downgrade is unsupported without confirmed local-data deletion. APFS/SSD copy-on-write and snapshots mean deletion, including legacy plaintext deletion after verified migration, cannot guarantee secure erasure. History Off still permits a bounded 15-minute in-memory Recent Code projection and retains encrypted Seen Message identities to prevent repeats.
