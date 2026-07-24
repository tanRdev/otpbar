use crate::domain::error::ErrorEnvelope;

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

    /// Clears clipboard content.
    fn clear(&mut self) -> Result<(), ErrorEnvelope>;
}
