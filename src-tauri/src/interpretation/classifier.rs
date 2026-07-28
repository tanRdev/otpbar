//! Deterministic Detected OTP classification and Provider inference.

use std::fmt;

use lazy_static::lazy_static;
use regex::Regex;

use super::mime::NormalizedMessage;

/// Maximum subject size accepted by the classification boundary.
pub const MAX_SUBJECT_BYTES: usize = 4 * 1024;
/// Maximum Message Origin size accepted by the classification boundary.
pub const MAX_ORIGIN_BYTES: usize = 2 * 1024;
/// Maximum number of syntactically plausible candidates evaluated per Message.
pub const MAX_CLASSIFICATION_CANDIDATES: usize = 64;

lazy_static! {
    static ref DIGIT_RUN: Regex =
        Regex::new(r"[0-9]+").expect("classifier digit-run regex must be valid");
    static ref DIRECT_CONTEXT_PATTERNS: Vec<Regex> = vec![
        Regex::new(
            r"(?i)(?:\b(?:verification|security|one[- ]time|login|access)\b\s+)?\b(?:code|otp|pin|passcode)\b\s*(?:is|:|=)?\s*([0-9]{4,8})"
        )
        .expect("prefix context regex must be valid"),
        Regex::new(
            r"(?i)([0-9]{4,8})\s*(?:\bis\b\s*)?(?:\byour\b\s*)?(?:\b(?:verification|security|one[- ]time)\b\s*)?\b(?:code|otp|pin|passcode)\b"
        )
        .expect("suffix context regex must be valid"),
        Regex::new(r"(?i)enter\s+([0-9]{4,8})\s+to\s+(?:verify|confirm)")
            .expect("instruction context regex must be valid"),
    ];
    static ref DATE_PATTERN: Regex = Regex::new(
        r"\b(?:[0-9]{1,2}[/-][0-9]{1,2}[/-][0-9]{2,4}|[0-9]{4}[/-][0-9]{1,2}[/-][0-9]{1,2})\b"
    )
    .expect("date exclusion regex must be valid");
    static ref PHONE_PATTERN: Regex = Regex::new(
        r"(?:\+?1[\s.-]*)?\(?[0-9]{3}\)?[\s.-]+[0-9]{3}[\s.-]+[0-9]{4}|(?:\+[0-9]{1,3})[\s.-]+(?:[0-9]{2,4}[\s.-]+){1,3}[0-9]{3,4}"
    )
    .expect("phone exclusion regex must be valid");
    static ref CURRENCY_PATTERN: Regex = Regex::new(
        r"(?i)(?:[$€£]\s*[0-9][0-9,]{3,}|\b(?:usd|eur|gbp|cad|aud)\s+[0-9][0-9,]{3,}|[0-9][0-9,]{3,}\s+(?:usd|eur|gbp|cad|aud)\b)"
    )
    .expect("currency exclusion regex must be valid");
}

/// Message fields used by the pure classification boundary.
pub struct ClassificationInput<'a> {
    message: &'a NormalizedMessage,
    subject: &'a str,
    origin: &'a str,
}

impl<'a> ClassificationInput<'a> {
    /// Creates classification input from normalized content and Message metadata.
    pub const fn new(message: &'a NormalizedMessage, subject: &'a str, origin: &'a str) -> Self {
        Self {
            message,
            subject,
            origin,
        }
    }
}

impl fmt::Debug for ClassificationInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClassificationInput")
            .field("message", &"[redacted]")
            .field("subject", &"[redacted]")
            .field("origin", &"[redacted]")
            .finish()
    }
}

/// Conservative Provider inference associated with a Detected OTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderInference {
    /// A Provider matched a conservative domain or whole-token Message rule.
    Known(&'static str),
    /// No Provider could be inferred with sufficient confidence.
    Unknown,
}

impl ProviderInference {
    /// Returns the known Provider display name, or `None` when inference is uncertain.
    pub const fn display_name(self) -> Option<&'static str> {
        match self {
            Self::Known(display_name) => Some(display_name),
            Self::Unknown => None,
        }
    }
}

/// A Detected OTP accepted with sufficient contextual confidence.
#[derive(Clone, PartialEq, Eq)]
pub struct DetectedOtp {
    code: String,
    provider: ProviderInference,
}

impl DetectedOtp {
    /// Returns the detected one-time passcode.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the conservative Provider inference.
    pub const fn provider(&self) -> ProviderInference {
        self.provider
    }
}

impl fmt::Debug for DetectedOtp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DetectedOtp")
            .field("code", &"[redacted]")
            .field("provider", &self.provider)
            .finish()
    }
}

/// Explainable reason that normalized Message content was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateExclusion {
    /// The candidate is part of a calendar date.
    Date,
    /// The candidate is part of a phone number.
    Phone,
    /// The candidate is a currency amount.
    Currency,
    /// The candidate is an order, tracking, invoice, or similar business reference.
    BusinessReference,
}

/// Explainable reason that normalized Message content was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassificationRejection {
    /// The Message contains no 4–8 digit candidate.
    NoNumericCandidate,
    /// Numeric content exists but lacks nearby OTP language.
    NoContextualCandidate,
    /// All otherwise plausible candidates belong to an excluded numeric category.
    Excluded(CandidateExclusion),
    /// Multiple distinct candidates have equally strong OTP context.
    AmbiguousCandidates,
    /// Subject or Message Origin exceeds its hard classification bound.
    InputTooLarge,
    /// The normalized Message contains too many candidate digit runs.
    TooManyCandidates,
}

/// Ranks candidates in normalized Message content and returns one Detected OTP.
pub fn classify(input: ClassificationInput<'_>) -> Result<DetectedOtp, ClassificationRejection> {
    if input.subject.len() > MAX_SUBJECT_BYTES || input.origin.len() > MAX_ORIGIN_BYTES {
        return Err(ClassificationRejection::InputTooLarge);
    }

    let contextual_text = format!("{}\n{}", input.subject, input.message.text());
    let lower = contextual_text.to_ascii_lowercase();
    let mut candidates = Vec::new();
    for candidate in DIGIT_RUN
        .find_iter(&contextual_text)
        .filter(|candidate| (4..=8).contains(&candidate.as_str().len()))
    {
        if candidates.len() == MAX_CLASSIFICATION_CANDIDATES {
            return Err(ClassificationRejection::TooManyCandidates);
        }
        candidates.push(candidate);
    }
    if candidates.is_empty() {
        return Err(ClassificationRejection::NoNumericCandidate);
    }

    let direct_spans: Vec<_> = DIRECT_CONTEXT_PATTERNS
        .iter()
        .flat_map(|pattern| pattern.captures_iter(&contextual_text))
        .filter_map(|captures| captures.get(1))
        .map(|candidate| (candidate.start(), candidate.end()))
        .collect();
    let excluded_spans = exclusion_spans(&contextual_text);

    let mut ranked = Vec::new();
    let mut first_exclusion = None;
    for candidate in candidates {
        match assess_candidate(
            &lower,
            candidate.start(),
            candidate.end(),
            &direct_spans,
            &excluded_spans,
        ) {
            CandidateAssessment::Ranked(score) => ranked.push((candidate, score)),
            CandidateAssessment::Excluded(reason) => {
                first_exclusion.get_or_insert(reason);
            }
            CandidateAssessment::Uncontextual => {}
        }
    }
    let Some(best_score) = ranked.iter().map(|(_, score)| *score).max() else {
        return Err(first_exclusion.map_or(
            ClassificationRejection::NoContextualCandidate,
            ClassificationRejection::Excluded,
        ));
    };
    let mut top_codes = Vec::new();
    for (candidate, score) in &ranked {
        if *score == best_score && !top_codes.contains(&candidate.as_str()) {
            top_codes.push(candidate.as_str());
        }
    }
    if top_codes.len() > 1 {
        return Err(ClassificationRejection::AmbiguousCandidates);
    }
    let best_code = top_codes
        .first()
        .expect("a maximum score requires at least one candidate");

    Ok(DetectedOtp {
        code: (*best_code).to_owned(),
        provider: infer_provider(input.origin, &lower),
    })
}

struct ProviderRule {
    display_name: &'static str,
    domains: &'static [&'static str],
    tokens: &'static [&'static str],
}

const PROVIDER_RULES: &[ProviderRule] = &[
    ProviderRule {
        display_name: "Google",
        domains: &["google.com"],
        tokens: &["google"],
    },
    ProviderRule {
        display_name: "Apple",
        domains: &["apple.com"],
        tokens: &["apple"],
    },
    ProviderRule {
        display_name: "Microsoft",
        domains: &["microsoft.com", "outlook.com"],
        tokens: &["microsoft", "outlook"],
    },
    ProviderRule {
        display_name: "Amazon",
        domains: &["amazon.com"],
        tokens: &["amazon"],
    },
    ProviderRule {
        display_name: "GitHub",
        domains: &["github.com"],
        tokens: &["github"],
    },
    ProviderRule {
        display_name: "PayPal",
        domains: &["paypal.com"],
        tokens: &["paypal"],
    },
    ProviderRule {
        display_name: "Stripe",
        domains: &["stripe.com"],
        tokens: &["stripe"],
    },
    ProviderRule {
        display_name: "LinkedIn",
        domains: &["linkedin.com"],
        tokens: &["linkedin"],
    },
    ProviderRule {
        display_name: "Meta",
        domains: &["facebook.com", "instagram.com", "meta.com"],
        tokens: &["facebook", "instagram", "meta"],
    },
    ProviderRule {
        display_name: "Coinbase",
        domains: &["coinbase.com"],
        tokens: &["coinbase"],
    },
    ProviderRule {
        display_name: "Slack",
        domains: &["slack.com"],
        tokens: &["slack"],
    },
    ProviderRule {
        display_name: "Discord",
        domains: &["discord.com"],
        tokens: &["discord"],
    },
    ProviderRule {
        display_name: "Dropbox",
        domains: &["dropbox.com"],
        tokens: &["dropbox"],
    },
    ProviderRule {
        display_name: "Auth0",
        domains: &["auth0.com"],
        tokens: &["auth0"],
    },
    ProviderRule {
        display_name: "Okta",
        domains: &["okta.com"],
        tokens: &["okta"],
    },
];

fn infer_provider(origin: &str, lower_message: &str) -> ProviderInference {
    let domain = if origin.trim().is_empty() {
        None
    } else {
        match parse_single_origin_domain(origin) {
            Some(domain) => Some(domain),
            None => return ProviderInference::Unknown,
        }
    };

    for rule in PROVIDER_RULES {
        if domain.as_deref().is_some_and(|origin_domain| {
            rule.domains.iter().any(|known_domain| {
                origin_domain == *known_domain
                    || origin_domain.ends_with(&format!(".{known_domain}"))
            })
        }) {
            return ProviderInference::Known(rule.display_name);
        }
    }

    for rule in PROVIDER_RULES {
        if rule
            .tokens
            .iter()
            .any(|token| contains_ascii_token(lower_message, token))
        {
            return ProviderInference::Known(rule.display_name);
        }
    }

    ProviderInference::Unknown
}

fn parse_single_origin_domain(origin: &str) -> Option<String> {
    let trimmed = origin.trim();
    if trimmed.matches('@').count() != 1 {
        return None;
    }

    let address = match (trimmed.find('<'), trimmed.find('>')) {
        (Some(open), Some(close))
            if open < close
                && close == trimmed.len().saturating_sub(1)
                && !trimmed[open + 1..close].contains(['<', '>'])
                && !trimmed[..open].contains(['<', '>']) =>
        {
            trimmed[open + 1..close].trim()
        }
        (None, None)
            if !trimmed
                .chars()
                .any(|character| character.is_ascii_whitespace() || ",()".contains(character)) =>
        {
            trimmed
        }
        _ => return None,
    };

    let (local, domain) = address.split_once('@')?;
    if local.is_empty()
        || local.len() > 64
        || !local.chars().all(|character| {
            character.is_ascii_alphanumeric() || ".!#$%&'*+-/=?^_`{|}~".contains(character)
        })
        || !valid_domain(domain)
    {
        return None;
    }

    Some(domain.to_ascii_lowercase())
}

fn valid_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
}

fn contains_ascii_token(text: &str, token: &str) -> bool {
    text.match_indices(token).any(|(start, matched)| {
        let end = start + matched.len();
        let before_is_word = text[..start]
            .chars()
            .next_back()
            .is_some_and(|character| character.is_ascii_alphanumeric());
        let after_is_word = text[end..]
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphanumeric());
        !before_is_word && !after_is_word
    })
}

enum CandidateAssessment {
    Ranked(u16),
    Excluded(CandidateExclusion),
    Uncontextual,
}

struct ExcludedSpan {
    start: usize,
    end: usize,
    reason: CandidateExclusion,
}

fn exclusion_spans(text: &str) -> Vec<ExcludedSpan> {
    [
        (&*DATE_PATTERN, CandidateExclusion::Date),
        (&*PHONE_PATTERN, CandidateExclusion::Phone),
        (&*CURRENCY_PATTERN, CandidateExclusion::Currency),
    ]
    .into_iter()
    .flat_map(|(pattern, reason)| {
        pattern.find_iter(text).map(move |matched| ExcludedSpan {
            start: matched.start(),
            end: matched.end(),
            reason,
        })
    })
    .collect()
}

fn assess_candidate(
    lower: &str,
    start: usize,
    end: usize,
    direct_spans: &[(usize, usize)],
    excluded_spans: &[ExcludedSpan],
) -> CandidateAssessment {
    if let Some(excluded) = excluded_spans
        .iter()
        .find(|excluded| start >= excluded.start && end <= excluded.end)
    {
        return CandidateAssessment::Excluded(excluded.reason);
    }

    let nearby = ascii_window(lower, start, end, 32);
    if contains_any_ascii_token(
        nearby,
        &[
            "order",
            "tracking",
            "invoice",
            "receipt",
            "total",
            "amount",
            "price",
            "phone",
            "shipping",
            "shipment",
            "delivery",
            "reference",
            "booking",
            "reservation",
        ],
    ) {
        return CandidateAssessment::Excluded(CandidateExclusion::BusinessReference);
    }

    if direct_spans
        .iter()
        .any(|&(direct_start, direct_end)| direct_start == start && direct_end == end)
    {
        return CandidateAssessment::Ranked(100);
    }

    let broad_context = ascii_window(lower, start, end, 48);
    if contains_any_ascii_token(
        broad_context,
        &[
            "verification",
            "verify",
            "one-time",
            "security",
            "passcode",
            "code",
            "otp",
            "pin",
            "confirm",
            "access",
        ],
    ) {
        CandidateAssessment::Ranked(50)
    } else {
        CandidateAssessment::Uncontextual
    }
}

fn contains_any_ascii_token(text: &str, tokens: &[&str]) -> bool {
    tokens.iter().any(|token| contains_ascii_token(text, token))
}

fn ascii_window(text: &str, start: usize, end: usize, radius: usize) -> &str {
    let mut window_start = start.saturating_sub(radius);
    while !text.is_char_boundary(window_start) {
        window_start = window_start.saturating_add(1);
    }
    let mut window_end = end.saturating_add(radius).min(text.len());
    while !text.is_char_boundary(window_end) {
        window_end = window_end.saturating_sub(1);
    }
    &text[window_start..window_end]
}
