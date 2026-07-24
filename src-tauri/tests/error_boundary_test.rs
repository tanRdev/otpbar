use otpbar::domain::error::{CommandEnvelope, ErrorCode, ErrorEnvelope, ErrorField, UserMessage};
use serde_json::json;

#[test]
fn command_errors_serialize_as_a_stable_user_safe_envelope() {
    let error = ErrorEnvelope::new(
        ErrorCode::StorageUnavailable,
        UserMessage::LocalDataUnavailable,
        true,
    )
    .with_field(ErrorField::HistoryRetention)
    .with_internal_detail("write failed for OTP 481516 using Bearer credential-canary");

    let serialized = serde_json::to_value(CommandEnvelope::<()>::failure(error))
        .expect("error envelope should serialize");

    assert_eq!(
        serialized,
        json!({
            "status": "error",
            "error": {
                "code": "storage_unavailable",
                "message": "Local data is temporarily unavailable.",
                "retryable": true,
                "field": "history_retention"
            }
        })
    );
    let rendered = serialized.to_string();
    assert!(!rendered.contains("481516"));
    assert!(!rendered.contains("credential-canary"));
}

#[test]
fn command_error_debug_and_display_never_render_internal_detail() {
    let error = ErrorEnvelope::new(
        ErrorCode::StorageUnavailable,
        UserMessage::LocalDataUnavailable,
        true,
    )
    .with_internal_detail("debug-secret-canary");

    let rendered = format!("{error:?} {error}");

    assert!(!rendered.contains("debug-secret-canary"));
    assert!(rendered.contains("[redacted]"));
    assert!(rendered.contains("Local data is temporarily unavailable."));
}
