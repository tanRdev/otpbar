use std::fmt;

use serde::Serialize;

/// Stable machine codes permitted at the diagnostics boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCode {
    /// An operation failed without exposing its sensitive inputs.
    OperationFailed,
}

/// Sensitive value categories that diagnostics must omit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveKind {
    /// A Detected OTP value.
    OneTimePasscode,
    /// An access, refresh, or other stored credential.
    Credential,
    /// A native Authorization callback code.
    AuthorizationCode,
    /// The anti-forgery state for a native Authorization attempt.
    AuthorizationState,
    /// A PKCE verifier or challenge.
    PkceMaterial,
    /// A provider's raw Message identifier.
    RawMessageId,
    /// Raw or normalized Message content.
    MessageBody,
    /// The user-recognizable identity of the authorized Mailbox.
    MailboxIdentity,
}

/// A value that may cross the redaction boundary but must never cross its output.
pub struct SensitiveValue {
    kind: SensitiveKind,
    value: String,
}

impl SensitiveValue {
    /// Classifies a sensitive value before it reaches diagnostics.
    pub fn new(kind: SensitiveKind, value: impl Into<String>) -> Self {
        Self {
            kind,
            value: value.into(),
        }
    }

    fn into_kind(self) -> SensitiveKind {
        let Self { kind, value } = self;
        drop(value);
        kind
    }
}

impl fmt::Debug for SensitiveValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitiveValue")
            .field("kind", &self.kind)
            .field("value", &"[redacted]")
            .finish()
    }
}

/// Unredacted diagnostic input. This type is intentionally not serializable.
pub struct DiagnosticInput {
    code: DiagnosticCode,
    sensitive: Vec<SensitiveValue>,
}

impl DiagnosticInput {
    /// Starts a diagnostic input with a stable machine code.
    pub fn new(code: DiagnosticCode) -> Self {
        Self {
            code,
            sensitive: Vec::new(),
        }
    }

    /// Adds a classified value that the output must omit.
    pub fn with_sensitive(mut self, value: SensitiveValue) -> Self {
        self.sensitive.push(value);
        self
    }
}

/// Serializable diagnostic output containing no sensitive values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RedactedDiagnostic {
    code: DiagnosticCode,
    omitted: Vec<SensitiveKind>,
}

/// Removes sensitive values and reports only which categories were omitted.
pub fn redact(input: DiagnosticInput) -> RedactedDiagnostic {
    let mut omitted = Vec::with_capacity(input.sensitive.len());
    for value in input.sensitive {
        let kind = value.into_kind();
        if !omitted.contains(&kind) {
            omitted.push(kind);
        }
    }

    RedactedDiagnostic {
        code: input.code,
        omitted,
    }
}
