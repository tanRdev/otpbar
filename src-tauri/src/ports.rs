use crate::domain::error::ErrorEnvelope;

/// Result of an atomic clipboard compare-and-clear operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardClearOutcome {
    /// The expected text was still current and was cleared.
    Cleared,
    /// Clipboard contents changed, so no mutation occurred.
    Changed,
}

/// Cryptographically secure random-byte source.
pub trait RandomSource {
    /// Fills the destination with cryptographically secure random bytes.
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), ErrorEnvelope>;
}

/// Application-readable secret persistence, implemented by macOS Keychain.
pub trait SecretStore {
    /// Reads an application-readable secret by its adapter-owned key.
    fn read_secret(&self, key: &str) -> Result<Option<Vec<u8>>, ErrorEnvelope>;

    /// Writes an application-readable secret by its adapter-owned key.
    fn write_secret(&mut self, key: &str, value: &[u8]) -> Result<(), ErrorEnvelope>;

    /// Deletes a secret. A missing value is treated as already deleted.
    fn delete_secret(&mut self, key: &str) -> Result<(), ErrorEnvelope>;
}

/// Text clipboard access required by Clipboard Lease ownership checks.
pub trait Clipboard {
    /// Reads the current text value, or `None` for non-text/empty content.
    fn read_text(&self) -> Result<Option<String>, ErrorEnvelope>;

    /// Replaces the current clipboard content with text.
    fn write_text(&mut self, value: &str) -> Result<(), ErrorEnvelope>;

    /// Atomically clears only when the current text exactly matches `expected`.
    ///
    /// Implementations must not compose a separate public read and clear; the
    /// comparison and mutation are one adapter-owned ownership operation.
    fn clear_if_text(&mut self, expected: &str) -> Result<ClipboardClearOutcome, ErrorEnvelope>;
}
