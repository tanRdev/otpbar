use base64::Engine as _;
use otpbar::interpretation::{
    classifier::{
        classify, CandidateExclusion, ClassificationInput, ClassificationRejection,
        MAX_CLASSIFICATION_CANDIDATES, MAX_ORIGIN_BYTES, MAX_SUBJECT_BYTES,
    },
    mime::{normalize_message, MimePart},
};
use serde::Deserialize;

#[derive(Deserialize)]
struct PositiveFixture {
    subject: String,
    origin: String,
    body: String,
    expected_code: String,
}

#[derive(Deserialize)]
struct NegativeFixture {
    body: String,
    reason: String,
}

#[derive(Deserialize)]
struct AmbiguousFixture {
    subject: String,
    origin: String,
    body: String,
    repeated_body: String,
}

#[derive(Deserialize)]
struct ProviderFixture {
    subject: String,
    origin: String,
    body: String,
    expected_provider: Option<String>,
}

fn normalized(body: &str) -> otpbar::interpretation::mime::NormalizedMessage {
    normalize_message(&MimePart {
        mime_type: "text/plain".to_owned(),
        headers: Vec::new(),
        body_data: Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(body)),
        filename: String::new(),
        parts: Vec::new(),
    })
    .expect("fixture body should normalize")
}

#[test]
fn contextual_four_to_eight_digit_candidates_are_detected() {
    let fixtures: Vec<PositiveFixture> =
        serde_json::from_str(include_str!("fixtures/classifier/contextual_positive.json"))
            .expect("fixture should parse");

    for fixture in fixtures {
        let message = normalized(&fixture.body);
        let detected = classify(ClassificationInput::new(
            &message,
            &fixture.subject,
            &fixture.origin,
        ))
        .expect("contextual candidate should be detected");

        assert_eq!(detected.code(), fixture.expected_code);
    }
}

#[test]
fn strongest_otp_context_wins_over_earlier_business_numbers() {
    let fixture: PositiveFixture =
        serde_json::from_str(include_str!("fixtures/classifier/multi_candidate.json"))
            .expect("fixture should parse");
    let message = normalized(&fixture.body);

    let detected = classify(ClassificationInput::new(
        &message,
        &fixture.subject,
        &fixture.origin,
    ))
    .expect("one candidate has strong OTP context");

    assert_eq!(detected.code(), fixture.expected_code);
}

#[test]
fn adversarial_business_numbers_have_specific_explainable_rejections() {
    let fixtures: Vec<NegativeFixture> = serde_json::from_str(include_str!(
        "fixtures/classifier/adversarial_negative.json"
    ))
    .expect("fixture should parse");

    for fixture in fixtures {
        let message = normalized(&fixture.body);
        let expected = match fixture.reason.as_str() {
            "date" => ClassificationRejection::Excluded(CandidateExclusion::Date),
            "phone" => ClassificationRejection::Excluded(CandidateExclusion::Phone),
            "currency" => ClassificationRejection::Excluded(CandidateExclusion::Currency),
            "business_reference" => {
                ClassificationRejection::Excluded(CandidateExclusion::BusinessReference)
            }
            "no_context" => ClassificationRejection::NoContextualCandidate,
            _ => panic!("unknown exclusion fixture"),
        };

        assert_eq!(
            classify(ClassificationInput::new(&message, "", "")),
            Err(expected)
        );
    }
}

#[test]
fn equally_strong_distinct_candidates_reject_but_repeated_code_is_deduplicated() {
    let fixture: AmbiguousFixture =
        serde_json::from_str(include_str!("fixtures/classifier/ambiguous.json"))
            .expect("fixture should parse");
    let ambiguous = normalized(&fixture.body);
    assert_eq!(
        classify(ClassificationInput::new(
            &ambiguous,
            &fixture.subject,
            &fixture.origin,
        )),
        Err(ClassificationRejection::AmbiguousCandidates)
    );

    let repeated = normalized(&fixture.repeated_body);
    let detected = classify(ClassificationInput::new(
        &repeated,
        &fixture.subject,
        &fixture.origin,
    ))
    .expect("the same code repeated is not ambiguous");
    assert_eq!(detected.code(), "246810");
}

#[test]
fn provider_inference_accepts_only_known_domains_or_whole_message_tokens() {
    let fixtures: Vec<ProviderFixture> =
        serde_json::from_str(include_str!("fixtures/classifier/provider_inference.json"))
            .expect("fixture should parse");

    for fixture in fixtures {
        let message = normalized(&fixture.body);
        let detected = classify(ClassificationInput::new(
            &message,
            &fixture.subject,
            &fixture.origin,
        ))
        .expect("fixture has a contextual candidate");

        assert_eq!(
            detected.provider().display_name(),
            fixture.expected_provider.as_deref()
        );
    }
}

#[test]
fn generic_numeric_fallback_requires_nearby_otp_language() {
    let no_number = normalized("Your verification request is ready.");
    assert_eq!(
        classify(ClassificationInput::new(&no_number, "", "")),
        Err(ClassificationRejection::NoNumericCandidate)
    );

    let isolated = normalized("Reference 123456 is ready.");
    assert_eq!(
        classify(ClassificationInput::new(&isolated, "", "")),
        Err(ClassificationRejection::Excluded(
            CandidateExclusion::BusinessReference
        ))
    );

    let distant = normalized(&format!(
        "Verification code information. {} Value 654321.",
        "ordinary text ".repeat(10)
    ));
    assert_eq!(
        classify(ClassificationInput::new(&distant, "", "")),
        Err(ClassificationRejection::NoContextualCandidate)
    );
}

#[test]
fn quoted_older_code_is_removed_by_normalization_before_ranking() {
    let message = normalized(
        "Your current verification code is 112233.\n\n\
         On Mon, Jul 27, 2026 at 9:00 AM Example wrote:\n\
         > Your verification code was 998877.",
    );

    let detected = classify(ClassificationInput::new(&message, "", ""))
        .expect("current normalized content has one candidate");

    assert_eq!(detected.code(), "112233");
}

#[test]
fn metadata_and_candidate_count_are_rejected_at_hard_limits() {
    let message = normalized("Your verification code is 123456.");
    assert_eq!(
        classify(ClassificationInput::new(
            &message,
            &"S".repeat(MAX_SUBJECT_BYTES + 1),
            "",
        )),
        Err(ClassificationRejection::InputTooLarge)
    );
    assert_eq!(
        classify(ClassificationInput::new(
            &message,
            "",
            &"O".repeat(MAX_ORIGIN_BYTES + 1),
        )),
        Err(ClassificationRejection::InputTooLarge)
    );

    let many_candidates = (0..=MAX_CLASSIFICATION_CANDIDATES)
        .map(|index| format!("code {:04}", index + 1000))
        .collect::<Vec<_>>()
        .join(" ");
    let message = normalized(&many_candidates);
    assert_eq!(
        classify(ClassificationInput::new(&message, "", "")),
        Err(ClassificationRejection::TooManyCandidates)
    );
}

#[test]
fn classifier_debug_output_redacts_message_metadata_and_detected_code() {
    let message = normalized("Secret body verification code is 739105.");
    let input = ClassificationInput::new(
        &message,
        "Secret subject 628094",
        "Secret Origin <secret-517083@example.test>",
    );
    let input_debug = format!("{input:?}");
    for secret in ["Secret", "739105", "628094", "517083", "example.test"] {
        assert!(!input_debug.contains(secret));
    }
    assert!(input_debug.contains("[redacted]"));

    let detected = classify(input).expect("one contextual candidate exists");
    let detected_debug = format!("{detected:?}");
    assert!(!detected_debug.contains("739105"));
    assert!(detected_debug.contains("[redacted]"));
}
