//! Production macOS pasteboard boundary for the Clipboard Lease.
//!
//! Unlike `tauri-plugin-clipboard-manager`, `NSPasteboard` lets the adapter
//! own an atomic compare-and-clear: the ownership proof (current text plus
//! `changeCount`) and the mutation happen inside one adapter operation, so
//! expiry can clear safely instead of failing closed.

use objc2_app_kit::{NSPasteboard, NSPasteboardTypeString};
use objc2_foundation::NSString;
use otpbar::{
    domain::error::{ErrorCode, ErrorEnvelope, UserMessage},
    ports::{Clipboard, ClipboardClearOutcome},
};

/// Clipboard adapter backed directly by the macOS general pasteboard.
pub struct PasteboardClipboard;

impl PasteboardClipboard {
    /// Creates an adapter over the system general pasteboard.
    pub fn new() -> Self {
        Self
    }
}

impl Default for PasteboardClipboard {
    fn default() -> Self {
        Self::new()
    }
}

impl Clipboard for PasteboardClipboard {
    fn read_text(&self) -> Result<Option<String>, ErrorEnvelope> {
        let pasteboard = general_pasteboard();
        // SAFETY: `generalPasteboard` and `stringForType:` are main-thread-agnostic
        // AppKit calls; the pasteboard object is valid for the process lifetime.
        let text = unsafe { pasteboard.stringForType(NSPasteboardTypeString) };
        Ok(text.map(|value| value.to_string()))
    }

    fn write_text(&mut self, value: &str) -> Result<(), ErrorEnvelope> {
        let pasteboard = general_pasteboard();
        let string = NSString::from_str(value);
        // SAFETY: clearing and replacing the general pasteboard contents are
        // ordinary AppKit calls on a valid pasteboard object.
        unsafe {
            pasteboard.clearContents();
            if pasteboard.setString_forType(&string, NSPasteboardTypeString) {
                Ok(())
            } else {
                Err(pasteboard_unavailable("pasteboard write was rejected"))
            }
        }
    }

    fn clear_if_text(&mut self, expected: &str) -> Result<ClipboardClearOutcome, ErrorEnvelope> {
        let pasteboard = general_pasteboard();
        // SAFETY: the compare-and-clear below is one adapter-owned ownership
        // operation over a valid pasteboard object. `changeCount` proves no
        // other owner interleaved between the comparison and the clear.
        unsafe {
            let before = pasteboard.changeCount();
            let current = pasteboard.stringForType(NSPasteboardTypeString);
            if current.map(|value| value.to_string()).as_deref() != Some(expected) {
                return Ok(ClipboardClearOutcome::Changed);
            }
            let after = pasteboard.clearContents();
            if after == before + 1 {
                Ok(ClipboardClearOutcome::Cleared)
            } else {
                Ok(ClipboardClearOutcome::Changed)
            }
        }
    }
}

fn general_pasteboard() -> objc2::rc::Retained<NSPasteboard> {
    NSPasteboard::generalPasteboard()
}

fn pasteboard_unavailable(detail: &str) -> ErrorEnvelope {
    ErrorEnvelope::new(
        ErrorCode::ClipboardUnavailable,
        UserMessage::ClipboardTemporarilyUnavailable,
        true,
    )
    .with_internal_detail(detail)
}
