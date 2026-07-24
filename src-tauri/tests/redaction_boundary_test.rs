use otpbar::redaction::{redact, DiagnosticCode, DiagnosticInput, SensitiveKind, SensitiveValue};

#[test]
fn diagnostics_omit_every_prohibited_sensitive_value() {
    let canaries = [
        (SensitiveKind::OneTimePasscode, "otp-canary-481516"),
        (SensitiveKind::Credential, "credential-canary"),
        (
            SensitiveKind::AuthorizationCode,
            "authorization-code-canary",
        ),
        (SensitiveKind::PkceMaterial, "pkce-verifier-canary"),
        (SensitiveKind::RawMessageId, "message-id-canary"),
        (SensitiveKind::MessageBody, "message-body-canary"),
        (SensitiveKind::MailboxIdentity, "mailbox-identity-canary"),
    ];
    let input = canaries.iter().fold(
        DiagnosticInput::new(DiagnosticCode::OperationFailed),
        |input, (kind, value)| input.with_sensitive(SensitiveValue::new(*kind, *value)),
    );

    let serialized =
        serde_json::to_string(&redact(input)).expect("redacted event should serialize");

    for (_, canary) in canaries {
        assert!(
            !serialized.contains(canary),
            "diagnostics leaked prohibited value {canary}",
        );
    }
    assert_eq!(
        serialized,
        r#"{"code":"operation_failed","omitted":["one_time_passcode","credential","authorization_code","pkce_material","raw_message_id","message_body","mailbox_identity"]}"#
    );
}

#[test]
fn sensitive_values_are_redacted_in_debug_output() {
    let value = SensitiveValue::new(SensitiveKind::Credential, "debug-credential-canary");

    let rendered = format!("{value:?}");

    assert!(!rendered.contains("debug-credential-canary"));
    assert!(rendered.contains("[redacted]"));
}
