//! Deterministic, side-effect-free MIME Message normalization.

use std::fmt;

use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use encoding_rs::Encoding;
use kuchikiki::traits::*;
use kuchikiki::{NodeData, NodeRef};
use serde::Deserialize;

/// Maximum number of MIME parts, including the root.
pub const MAX_MIME_PARTS: usize = 128;
/// Maximum zero-based nesting depth accepted for a MIME part.
pub const MAX_MIME_DEPTH: usize = 16;
/// Maximum aggregate base64url body size accepted across all MIME parts.
pub const MAX_ENCODED_BODY_BYTES: usize = 256 * 1024;
/// Maximum aggregate MIME metadata size.
pub const MAX_METADATA_BYTES: usize = 64 * 1024;
/// Maximum aggregate header count.
pub const MAX_MIME_HEADERS: usize = 256;
/// Maximum normalized Message text size.
pub const MAX_NORMALIZED_TEXT_BYTES: usize = 64 * 1024;

/// One MIME header supplied by the Mailbox transport.
#[derive(Clone, Deserialize, PartialEq, Eq)]
pub struct MimeHeader {
    /// Header name.
    pub name: String,
    /// Header value.
    pub value: String,
}

impl fmt::Debug for MimeHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MimeHeader")
            .field("name", &"[redacted]")
            .field("value", &"[redacted]")
            .finish()
    }
}

/// A transport-decoded MIME tree whose leaf bodies remain base64url encoded.
#[derive(Clone, Deserialize, PartialEq, Eq)]
pub struct MimePart {
    /// Media type reported by the transport.
    pub mime_type: String,
    /// MIME headers associated with this part.
    #[serde(default)]
    pub headers: Vec<MimeHeader>,
    /// Base64url-encoded leaf body.
    #[serde(default)]
    pub body_data: Option<String>,
    /// Transport-reported filename, empty for ordinary inline content.
    #[serde(default)]
    pub filename: String,
    /// Nested MIME parts.
    #[serde(default)]
    pub parts: Vec<MimePart>,
}

impl fmt::Debug for MimePart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MimePart")
            .field("mime_type", &"[redacted]")
            .field(
                "headers",
                &(!self.headers.is_empty()).then_some("[redacted]"),
            )
            .field("body_data", &self.body_data.as_ref().map(|_| "[redacted]"))
            .field(
                "filename",
                &(!self.filename.is_empty()).then_some("[redacted]"),
            )
            .field("part_count", &self.parts.len())
            .finish()
    }
}

/// Normalized Message content suitable for deterministic classification.
#[derive(Clone, PartialEq, Eq)]
pub struct NormalizedMessage {
    text: String,
}

impl fmt::Debug for NormalizedMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NormalizedMessage")
            .field("text", &"[redacted]")
            .finish()
    }
}

impl NormalizedMessage {
    /// Returns the normalized, unquoted Message text.
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// Explicit reason that a MIME Message could not be normalized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MimeRejection {
    /// The MIME tree contains more parts than the interpretation boundary accepts.
    TooManyParts,
    /// The MIME tree is nested more deeply than the interpretation boundary accepts.
    NestingTooDeep,
    /// The MIME tree contains too many headers.
    TooManyHeaders,
    /// Encoded bodies, metadata, or normalized content exceed a hard size bound.
    MessageTooLarge,
    /// The preferred text body is not valid base64url.
    InvalidBase64,
    /// The preferred text body is not valid text in its declared encoding.
    InvalidEncoding,
    /// The preferred text body declares an unsupported charset.
    UnsupportedCharset,
    /// No supported inline textual body exists.
    NoUsableText,
}

/// Converts a MIME tree into deterministic Message content without performing I/O.
pub fn normalize_message(root: &MimePart) -> Result<NormalizedMessage, MimeRejection> {
    let mut limits = LimitState::default();
    validate_part(root, 0, &mut limits)?;

    let mut plain = Vec::new();
    let mut html = Vec::new();
    collect_text_parts(root, &mut plain, &mut html);

    let (selected, is_html) = plain
        .first()
        .map(|candidate| (candidate, false))
        .or_else(|| html.first().map(|candidate| (candidate, true)))
        .ok_or(MimeRejection::NoUsableText)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(selected.body)
        .or_else(|_| URL_SAFE.decode(selected.body))
        .map_err(|_| MimeRejection::InvalidBase64)?;
    let encoding = Encoding::for_label(selected.charset.as_bytes())
        .ok_or(MimeRejection::UnsupportedCharset)?;
    let (decoded, had_errors) = encoding.decode_with_bom_removal(&bytes);
    if had_errors {
        return Err(MimeRejection::InvalidEncoding);
    }
    let decoded_text = if is_html {
        html_to_text(decoded.as_ref())
    } else {
        decoded.into_owned()
    };
    let text = remove_quoted_reply(&decoded_text);
    if text.is_empty() {
        return Err(MimeRejection::NoUsableText);
    }
    if text.len() > MAX_NORMALIZED_TEXT_BYTES {
        return Err(MimeRejection::MessageTooLarge);
    }

    Ok(NormalizedMessage { text })
}

#[derive(Default)]
struct LimitState {
    parts: usize,
    headers: usize,
    encoded_body_bytes: usize,
    metadata_bytes: usize,
}

fn validate_part(
    part: &MimePart,
    depth: usize,
    limits: &mut LimitState,
) -> Result<(), MimeRejection> {
    if depth >= MAX_MIME_DEPTH {
        return Err(MimeRejection::NestingTooDeep);
    }

    limits.parts = limits.parts.saturating_add(1);
    if limits.parts > MAX_MIME_PARTS {
        return Err(MimeRejection::TooManyParts);
    }

    limits.headers = limits.headers.saturating_add(part.headers.len());
    if limits.headers > MAX_MIME_HEADERS {
        return Err(MimeRejection::TooManyHeaders);
    }

    let local_metadata_bytes = part
        .mime_type
        .len()
        .saturating_add(part.filename.len())
        .saturating_add(part.headers.iter().fold(0_usize, |total, header| {
            total
                .saturating_add(header.name.len())
                .saturating_add(header.value.len())
        }));
    limits.metadata_bytes = limits.metadata_bytes.saturating_add(local_metadata_bytes);
    if limits.metadata_bytes > MAX_METADATA_BYTES {
        return Err(MimeRejection::MessageTooLarge);
    }

    limits.encoded_body_bytes = limits.encoded_body_bytes.saturating_add(
        part.body_data
            .as_ref()
            .map_or(0, |body_data| body_data.len()),
    );
    if limits.encoded_body_bytes > MAX_ENCODED_BODY_BYTES {
        return Err(MimeRejection::MessageTooLarge);
    }

    for child in &part.parts {
        validate_part(child, depth.saturating_add(1), limits)?;
    }
    Ok(())
}

fn remove_quoted_reply(text: &str) -> String {
    let mut current = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let reply_boundary = (trimmed.starts_with("On ") && trimmed.ends_with(" wrote:"))
            || trimmed.eq_ignore_ascii_case("-----Original Message-----")
            || trimmed.starts_with('>');
        if reply_boundary {
            break;
        }
        current.push(line.trim_end());
    }

    current.join("\n").trim().to_owned()
}

fn html_to_text(html: &str) -> String {
    let document = kuchikiki::parse_html().one(html).document_node;
    if let Ok(matches) = document
        .select("head, script, style, noscript, template, blockquote, .gmail_quote, #divRplyFwdMsg")
    {
        let discarded: Vec<NodeRef> = matches.map(|node| node.as_node().clone()).collect();
        for node in discarded {
            node.detach();
        }
    }

    let mut rendered = String::new();
    render_html_node(&document, &mut rendered);
    normalize_rendered_text(&rendered)
}

fn render_html_node(node: &NodeRef, output: &mut String) {
    match node.data() {
        NodeData::Text(text) => output.push_str(&text.borrow()),
        NodeData::Element(element) => {
            let name = element.name.local.as_ref();
            let is_break = name == "br";
            let is_block = matches!(
                name,
                "address"
                    | "article"
                    | "aside"
                    | "blockquote"
                    | "div"
                    | "footer"
                    | "h1"
                    | "h2"
                    | "h3"
                    | "h4"
                    | "h5"
                    | "h6"
                    | "header"
                    | "li"
                    | "main"
                    | "p"
                    | "pre"
                    | "section"
                    | "table"
                    | "tr"
            );
            if is_block || is_break {
                push_line_break(output);
            }
            for child in node.children() {
                render_html_node(&child, output);
            }
            if is_block {
                push_line_break(output);
            }
        }
        _ => {
            for child in node.children() {
                render_html_node(&child, output);
            }
        }
    }
}

fn push_line_break(output: &mut String) {
    if !output.is_empty() && !output.ends_with('\n') {
        output.push('\n');
    }
}

fn normalize_rendered_text(rendered: &str) -> String {
    rendered
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

struct TextCandidate<'a> {
    body: &'a str,
    charset: String,
}

fn collect_text_parts<'a>(
    part: &'a MimePart,
    plain: &mut Vec<TextCandidate<'a>>,
    html: &mut Vec<TextCandidate<'a>>,
) {
    if is_attachment(part) {
        return;
    }

    let media_type = part.mime_type.split(';').next().unwrap_or_default().trim();

    if let Some(body) = part.body_data.as_deref().filter(|body| !body.is_empty()) {
        let candidate = || TextCandidate {
            body,
            charset: declared_charset(part).unwrap_or_else(|| "utf-8".to_owned()),
        };
        if media_type.eq_ignore_ascii_case("text/plain") {
            plain.push(candidate());
        } else if media_type.eq_ignore_ascii_case("text/html") {
            html.push(candidate());
        }
    }

    for child in &part.parts {
        collect_text_parts(child, plain, html);
    }
}

fn is_attachment(part: &MimePart) -> bool {
    !part.filename.trim().is_empty()
        || part.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("content-disposition")
                && header
                    .value
                    .split(';')
                    .next()
                    .is_some_and(|value| value.trim().eq_ignore_ascii_case("attachment"))
        })
}

fn declared_charset(part: &MimePart) -> Option<String> {
    let content_type = part
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-type"))
        .map(|header| header.value.as_str())
        .unwrap_or(&part.mime_type);

    content_type.split(';').skip(1).find_map(|parameter| {
        let (name, value) = parameter.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("charset")
            .then(|| value.trim().trim_matches(['"', '\'']).to_owned())
    })
}
