use otpbar::interpretation::mime::{
    normalize_message, MimeHeader, MimePart, MimeRejection, MAX_ENCODED_BODY_BYTES, MAX_MIME_DEPTH,
    MAX_MIME_HEADERS, MAX_MIME_PARTS, MAX_NORMALIZED_TEXT_BYTES,
};

fn fixture(name: &str) -> MimePart {
    let source = match name {
        "attachment_exclusion" => include_str!("fixtures/mime/attachment_exclusion.json"),
        "html_only" => include_str!("fixtures/mime/html_only.json"),
        "invalid_base64" => include_str!("fixtures/mime/invalid_base64.json"),
        "invalid_utf8" => include_str!("fixtures/mime/invalid_utf8.json"),
        "nested_multipart" => include_str!("fixtures/mime/nested_multipart.json"),
        "quoted_plain_reply" => include_str!("fixtures/mime/quoted_plain_reply.json"),
        "quoted_html_reply" => include_str!("fixtures/mime/quoted_html_reply.json"),
        "unsupported_charset" => include_str!("fixtures/mime/unsupported_charset.json"),
        "windows_1252" => include_str!("fixtures/mime/windows_1252.json"),
        _ => panic!("unknown MIME fixture"),
    };
    serde_json::from_str(source).expect("fixture must be valid")
}

#[test]
fn quoted_html_reply_container_is_removed_before_text_extraction() {
    let normalized =
        normalize_message(&fixture("quoted_html_reply")).expect("current content exists");

    assert_eq!(normalized.text(), "Your current code is 222333");
}

#[test]
fn adversarial_mime_trees_and_bodies_are_rejected_at_hard_limits() {
    let leaf = MimePart {
        mime_type: "text/plain".to_owned(),
        headers: Vec::new(),
        body_data: Some("QQ".to_owned()),
        filename: String::new(),
        parts: Vec::new(),
    };

    let too_wide = MimePart {
        mime_type: "multipart/mixed".to_owned(),
        headers: Vec::new(),
        body_data: None,
        filename: String::new(),
        parts: vec![leaf.clone(); MAX_MIME_PARTS],
    };
    assert_eq!(
        normalize_message(&too_wide),
        Err(MimeRejection::TooManyParts)
    );

    let mut too_deep = leaf.clone();
    for _ in 0..MAX_MIME_DEPTH {
        too_deep = MimePart {
            mime_type: "multipart/mixed".to_owned(),
            headers: Vec::new(),
            body_data: None,
            filename: String::new(),
            parts: vec![too_deep],
        };
    }
    assert_eq!(
        normalize_message(&too_deep),
        Err(MimeRejection::NestingTooDeep)
    );

    let oversized = MimePart {
        body_data: Some("A".repeat(MAX_ENCODED_BODY_BYTES + 1)),
        ..leaf
    };
    assert_eq!(
        normalize_message(&oversized),
        Err(MimeRejection::MessageTooLarge)
    );

    let too_many_headers = MimePart {
        headers: vec![
            MimeHeader {
                name: "X-Test".to_owned(),
                value: String::new(),
            };
            MAX_MIME_HEADERS + 1
        ],
        ..MimePart {
            mime_type: "text/plain".to_owned(),
            headers: Vec::new(),
            body_data: Some("QQ".to_owned()),
            filename: String::new(),
            parts: Vec::new(),
        }
    };
    assert_eq!(
        normalize_message(&too_many_headers),
        Err(MimeRejection::TooManyHeaders)
    );

    use base64::Engine as _;
    let large_text = "A".repeat(MAX_NORMALIZED_TEXT_BYTES + 1);
    let too_much_normalized_text = MimePart {
        mime_type: "text/plain".to_owned(),
        headers: Vec::new(),
        body_data: Some(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(large_text.as_bytes()),
        ),
        filename: String::new(),
        parts: Vec::new(),
    };
    assert_eq!(
        normalize_message(&too_much_normalized_text),
        Err(MimeRejection::MessageTooLarge)
    );
}

#[test]
fn debug_output_redacts_all_untrusted_message_content() {
    let raw = MimePart {
        mime_type: "secret-media-type-135790".to_owned(),
        headers: vec![MimeHeader {
            name: "secret-header-246801".to_owned(),
            value: "secret-value-975310".to_owned(),
        }],
        body_data: Some("secret-body-864209".to_owned()),
        filename: "secret-file-753198.txt".to_owned(),
        parts: Vec::new(),
    };
    let raw_debug = format!("{raw:?}");
    for secret in ["135790", "246801", "975310", "864209", "753198", "secret"] {
        assert!(!raw_debug.contains(secret));
    }
    assert!(raw_debug.contains("[redacted]"));

    let normalized =
        normalize_message(&fixture("nested_multipart")).expect("Message should normalize");
    let normalized_debug = format!("{normalized:?}");
    assert!(!normalized_debug.contains("123456"));
    assert!(normalized_debug.contains("[redacted]"));
}

#[test]
fn quoted_plaintext_reply_is_removed_before_classification() {
    let normalized =
        normalize_message(&fixture("quoted_plain_reply")).expect("current content exists");

    assert_eq!(normalized.text(), "Your current code is 111222");
}

#[test]
fn attachments_are_excluded_even_when_they_look_like_text_content() {
    let normalized =
        normalize_message(&fixture("attachment_exclusion")).expect("inline text exists");

    assert_eq!(normalized.text(), "Real code 123456");
}

#[test]
fn malformed_base64_is_rejected_explicitly() {
    assert_eq!(
        normalize_message(&fixture("invalid_base64")),
        Err(MimeRejection::InvalidBase64)
    );
}

#[test]
fn unsupported_and_malformed_declared_charsets_are_distinct_rejections() {
    assert_eq!(
        normalize_message(&fixture("unsupported_charset")),
        Err(MimeRejection::UnsupportedCharset)
    );
    assert_eq!(
        normalize_message(&fixture("invalid_utf8")),
        Err(MimeRejection::InvalidEncoding)
    );
}

#[test]
fn declared_supported_charset_is_decoded_without_replacement() {
    let normalized = normalize_message(&fixture("windows_1252")).expect("charset is supported");

    assert_eq!(normalized.text(), "Votre code est 123456 — café");
}

#[test]
fn html_only_content_is_sanitized_into_readable_text() {
    let normalized = normalize_message(&fixture("html_only")).expect("Message should normalize");

    assert_eq!(
        normalized.text(),
        "Your code is 246810 today.\nDo not share it."
    );
}

#[test]
fn nested_multipart_prefers_decoded_plain_text() {
    let normalized =
        normalize_message(&fixture("nested_multipart")).expect("Message should normalize");

    assert_eq!(normalized.text(), "Your code is 123456");
}
