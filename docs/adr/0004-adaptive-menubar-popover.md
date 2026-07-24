# Allow a bounded adaptive menubar popover

## Status

Accepted

## Context

The fixed 320 × 420 canvas cannot reliably fit Monitoring Health, accessible controls, recoverable errors, and larger text, while a conventional unbounded window would stop feeling like a menubar utility.

## Decision

The v2 popover may grow from 320 × 420 toward a 360 × 500 target when content or accessibility settings require it. It remains anchored to the menubar and bounded to the active screen's usable area.

## Consequences

Layouts must work at both the compact and target sizes, scroll internal content rather than the shell, and be tested with zoom and macOS accessibility display modes. The adaptive bound is a product constraint for every new screen, not permission to become a dashboard.
