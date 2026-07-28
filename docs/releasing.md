# Releasing OTPBar

OTPBar releases are built from immutable `v*` tags by GitHub Actions. The
workflow refuses to publish unsigned or unnotarized macOS artifacts.

## Required repository secrets

- `APPLE_CERTIFICATE` — base64-encoded Developer ID Application `.p12`
- `APPLE_CERTIFICATE_PASSWORD`
- `APPLE_SIGNING_IDENTITY`
- `APPLE_ID`
- `APPLE_PASSWORD` — app-specific password
- `APPLE_TEAM_ID`

## Release checklist

1. Confirm `main` is clean, pushed, and green in `build-and-test`.
2. Update the same version in:
   - `package.json` and the root package entry in `package-lock.json`
   - `src-tauri/Cargo.toml` and the `otpbar` entry in `src-tauri/Cargo.lock`
   - `src-tauri/tauri.conf.json`
3. Run:

   ```bash
   npm ci
   npm run verify:code
   CI=true npm run tauri build -- --bundles app
   ```

4. Commit and push the version change.
5. Create and push an annotated tag:

   ```bash
   git tag -a vX.Y.Z -m "OTPBar vX.Y.Z"
   git push origin vX.Y.Z
   ```

The release workflow re-runs all gates, builds the DMG, verifies code signing,
notarization, stapling, and Gatekeeper assessment, creates SHA-256 checksums,
and only then publishes the GitHub release.

## Update policy

OTPBar does not currently include an in-app updater. Install newer releases
manually from GitHub after verifying the published checksum. Adding an updater
requires a separately signed update feed and is tracked in the implementation
plan.
