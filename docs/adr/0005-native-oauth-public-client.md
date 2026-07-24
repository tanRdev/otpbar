# Treat native OAuth as a public-client flow

## Status

Accepted

**Date:** 2026-07-24

## Context

A distributed macOS application cannot keep a client secret confidential. The fixed callback and missing PKCE/state protections expose Authorization to interception and request-forgery risk.

## Decision

OTPBar uses the OAuth 2.0 Authorization Code flow for a public native client with fresh PKCE and high-entropy state. Each attempt binds an ephemeral loopback callback to `127.0.0.1` or `[::1]` before opening the browser; a distributed client secret is neither confidential nor security proof.

## Consequences

Google deployment must register and verify the native-client configuration and support loopback redirects. The callback is single-use, time-bounded, cancellable, strict about path/method/host/state, and serves only escaped fixed HTML. Packaging supplies a client ID but no security-sensitive secret; callback, credential, and Google adapters require separate integration tests.
