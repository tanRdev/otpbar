//! Production clipboard boundary for the Clipboard Lease.
//!
//! `tauri-plugin-clipboard-manager` exposes independent `read_text` and
//! `clear` operations. macOS does not offer the plugin a compare-and-clear
//! transaction, so composing those operations would leave a race in which an
//! external application could replace the clipboard between the comparison
//! and the clear. The lease contract prohibits that mutation. Until the
//! platform adapter can prove an atomic ownership check, expiry is therefore
//! deliberately blocked and leaves clipboard content untouched.

use otpbar::{
    domain::error::{ErrorCode, ErrorEnvelope, UserMessage},
    ports::{Clipboard, ClipboardClearOutcome},
};
use tauri_plugin_clipboard_manager::ClipboardExt;

/// The exact platform limitation behind the fail-closed expiry behavior.
pub const ATOMIC_CLEAR_LIMITATION: &str = "BLOCKED: tauri-plugin-clipboard-manager exposes separate read_text and clear operations only; it cannot prove an OS-atomic compare-and-clear against cross-application clipboard changes.";

/// Adapter for Tauri's native clipboard plugin.
pub struct TauriClipboardAdapter<R: tauri::Runtime> {
    app: tauri::AppHandle<R>,
}

impl<R: tauri::Runtime> TauriClipboardAdapter<R> {
    /// Creates an adapter backed by the clipboard plugin managed by `app`.
    pub fn new(app: tauri::AppHandle<R>) -> Self {
        Self { app }
    }
}

impl<R: tauri::Runtime> Clipboard for TauriClipboardAdapter<R> {
    fn read_text(&self) -> Result<Option<String>, ErrorEnvelope> {
        self.app
            .clipboard()
            .read_text()
            .map(Some)
            .map_err(clipboard_error)
    }

    fn write_text(&mut self, value: &str) -> Result<(), ErrorEnvelope> {
        self.app
            .clipboard()
            .write_text(value)
            .map_err(clipboard_error)
    }

    fn clear_if_text(&mut self, _expected: &str) -> Result<ClipboardClearOutcome, ErrorEnvelope> {
        // Never replace this with `read_text` followed by `clear`: that is not
        // atomic with respect to another clipboard owner.
        Err(atomic_clear_blocked())
    }
}

fn clipboard_error(error: tauri_plugin_clipboard_manager::Error) -> ErrorEnvelope {
    let detail = error.to_string();
    let permission_denied = detail.to_ascii_lowercase().contains("permission");
    if permission_denied {
        ErrorEnvelope::new(
            ErrorCode::ClipboardPermissionDenied,
            UserMessage::ClipboardPermissionRequired,
            false,
        )
    } else {
        ErrorEnvelope::new(
            ErrorCode::ClipboardUnavailable,
            UserMessage::ClipboardTemporarilyUnavailable,
            true,
        )
        .with_internal_detail(detail)
    }
}

/// Returns the safe typed error used when expiry cannot make an atomic claim.
pub fn atomic_clear_blocked() -> ErrorEnvelope {
    ErrorEnvelope::new(
        ErrorCode::ClipboardAtomicClearUnavailable,
        UserMessage::ClipboardAtomicClearUnavailable,
        false,
    )
    .with_internal_detail(ATOMIC_CLEAR_LIMITATION)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_clear_limit_is_fail_closed_and_safe_to_serialize() {
        let error = atomic_clear_blocked();

        assert_eq!(error.code(), ErrorCode::ClipboardAtomicClearUnavailable);
        let serialized = serde_json::to_string(&error).expect("error serializes");
        assert!(serialized.contains("clipboard_atomic_clear_unavailable"));
        assert!(!serialized.contains("BLOCKED"));
        assert!(!serialized.contains("compare-and-clear"));
    }
}
