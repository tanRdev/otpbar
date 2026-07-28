use std::fmt;

use serde::Serialize;

/// Stable machine-readable categories exposed across application boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Local durable state cannot currently be accessed.
    StorageUnavailable,
    /// The operating system denied clipboard access.
    ClipboardPermissionDenied,
    /// Clipboard I/O failed for a reason other than permission.
    ClipboardUnavailable,
}

/// Pre-reviewed user-safe messages; arbitrary internal strings cannot cross IPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserMessage {
    /// Local data cannot currently be accessed.
    LocalDataUnavailable,
    /// Clipboard access must be enabled before copying can succeed.
    ClipboardPermissionRequired,
    /// Clipboard access failed and may be retried.
    ClipboardTemporarilyUnavailable,
}

impl UserMessage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::LocalDataUnavailable => "Local data is temporarily unavailable.",
            Self::ClipboardPermissionRequired => "Clipboard access is required to copy this code.",
            Self::ClipboardTemporarilyUnavailable => "The clipboard is temporarily unavailable.",
        }
    }
}

/// Stable command fields that may be identified in a public error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorField {
    /// The History retention setting.
    HistoryRetention,
}

/// A failure safe to return to the webview or include in diagnostics.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ErrorEnvelope {
    code: ErrorCode,
    message: String,
    retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<ErrorField>,
    #[serde(skip)]
    internal_detail: Option<String>,
}

impl ErrorEnvelope {
    /// Creates an error from stable, pre-reviewed public components.
    pub fn new(code: ErrorCode, message: UserMessage, retryable: bool) -> Self {
        Self {
            code,
            message: message.as_str().to_owned(),
            retryable,
            field: None,
            internal_detail: None,
        }
    }

    /// Identifies a public field associated with the failure.
    pub fn with_field(mut self, field: ErrorField) -> Self {
        self.field = Some(field);
        self
    }

    /// Retains causal detail that serialization and formatting always redact.
    pub fn with_internal_detail(mut self, detail: impl Into<String>) -> Self {
        self.internal_detail = Some(detail.into());
        self
    }

    /// Returns the stable category without exposing causal detail.
    pub const fn code(&self) -> ErrorCode {
        self.code
    }
}

impl fmt::Debug for ErrorEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ErrorEnvelope")
            .field("code", &self.code)
            .field("message", &self.message)
            .field("retryable", &self.retryable)
            .field("field", &self.field)
            .field(
                "internal_detail",
                &self.internal_detail.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

impl fmt::Display for ErrorEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ErrorEnvelope {}

/// Discriminated result shape used by command and event boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CommandEnvelope<T> {
    /// The command completed and returned data.
    Success { data: T },
    /// The command failed with a safe public error.
    Error { error: ErrorEnvelope },
}

impl<T> CommandEnvelope<T> {
    /// Wraps successful command data.
    pub fn success(data: T) -> Self {
        Self::Success { data }
    }

    /// Wraps a safe command failure.
    pub fn failure(error: ErrorEnvelope) -> Self {
        Self::Error { error }
    }
}
