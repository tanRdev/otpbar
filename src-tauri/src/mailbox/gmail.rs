//! Read-only Gmail query and Message transport.

use std::{
    fmt,
    time::{Duration, SystemTime},
};

use reqwest::{Client, Response, Url};
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    authorization::{credentials::CredentialBundle, runtime::AuthorizedCredential},
    clock::Timestamp,
};

const GMAIL_API_ROOT: &str = "https://gmail.googleapis.com/gmail/v1/users/me/";
const UNREAD_QUERY: &str = "is:unread";
const MAX_MESSAGES_PER_FETCH: usize = 25;
const MAX_LIST_PAGES: usize = 4;
const MAX_CONCURRENT_DETAILS: usize = 4;
const MAX_LIST_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_DETAIL_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_ERROR_RESPONSE_BYTES: usize = 32 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Stable transport failures with no raw status body or Message identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GmailError {
    AuthorizationRequired,
    PermissionDenied,
    RateLimited { retry_after: Option<Duration> },
    Offline,
    ServerUnavailable,
    MalformedResponse,
    UnexpectedStatus,
}

impl fmt::Display for GmailError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AuthorizationRequired => "Gmail Authorization must be renewed.",
            Self::PermissionDenied => "Gmail read-only permission is required.",
            Self::RateLimited { .. } => "Gmail temporarily rate limited this check.",
            Self::Offline => "Gmail is temporarily offline.",
            Self::ServerUnavailable => "Gmail is temporarily unavailable.",
            Self::MalformedResponse => "Gmail returned an invalid response.",
            Self::UnexpectedStatus => "Gmail rejected the mailbox request.",
        })
    }
}

impl std::error::Error for GmailError {}

/// Whether every listed Message detail was retrieved within the bounded check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchCompleteness {
    Complete,
    Partial {
        failed_details: usize,
        pagination_truncated: bool,
    },
}

/// One typed failed detail request without exposing its raw Message identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetailFailure {
    ordinal: usize,
    error: GmailError,
}

impl DetailFailure {
    /// Returns the zero-based list position whose detail could not be fetched.
    pub const fn ordinal(&self) -> usize {
        self.ordinal
    }

    /// Returns the stable transport failure.
    pub const fn error(&self) -> GmailError {
        self.error
    }
}

/// Raw Gmail Message JSON for the pure MIME normalization boundary.
pub struct GmailMessage {
    id: Zeroizing<String>,
    json: Zeroizing<Vec<u8>>,
}

impl GmailMessage {
    /// Returns the raw Gmail Message identifier only for idempotency plumbing.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the validated raw transport JSON for MIME decoding.
    pub fn json(&self) -> &[u8] {
        &self.json
    }
}

impl fmt::Debug for GmailMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GmailMessage")
            .field("id", &"[redacted]")
            .field("json", &"[redacted]")
            .finish()
    }
}

/// Bounded unread Message details and explicit completeness.
pub struct GmailFetch {
    messages: Vec<GmailMessage>,
    failures: Vec<DetailFailure>,
    pagination_truncated: bool,
}

impl GmailFetch {
    /// Returns successfully fetched details in the original list order.
    pub fn messages(&self) -> &[GmailMessage] {
        &self.messages
    }

    /// Returns typed detail failures without raw Message identifiers.
    pub fn failures(&self) -> &[DetailFailure] {
        &self.failures
    }

    /// Returns whether this check is safe to treat as complete.
    pub fn completeness(&self) -> FetchCompleteness {
        if self.failures.is_empty() && !self.pagination_truncated {
            FetchCompleteness::Complete
        } else {
            FetchCompleteness::Partial {
                failed_details: self.failures.len(),
                pagination_truncated: self.pagination_truncated,
            }
        }
    }
}

impl fmt::Debug for GmailFetch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GmailFetch")
            .field("message_count", &self.messages.len())
            .field("failures", &self.failures)
            .field("pagination_truncated", &self.pagination_truncated)
            .finish()
    }
}

/// Read-only Gmail transport with no shared mutable state or external locks.
pub struct GmailMailbox {
    api_root: Url,
    http: Client,
    retry_after_now: Option<Timestamp>,
}

impl GmailMailbox {
    /// Creates the production Gmail transport.
    pub fn new() -> Self {
        Self {
            api_root: Url::parse(GMAIL_API_ROOT).expect("fixed Gmail API URL is valid"),
            http: Client::new(),
            retry_after_now: None,
        }
    }

    #[cfg(test)]
    fn for_test(base: &str) -> Result<Self, GmailError> {
        let mut api_root = Url::parse(base).map_err(|_| GmailError::MalformedResponse)?;
        api_root.set_path("/gmail/v1/users/me/");
        Ok(Self {
            api_root,
            http: Client::new(),
            retry_after_now: None,
        })
    }

    #[cfg(test)]
    fn for_test_at(base: &str, now: Timestamp) -> Result<Self, GmailError> {
        let mut mailbox = Self::for_test(base)?;
        mailbox.retry_after_now = Some(now);
        Ok(mailbox)
    }

    fn retry_after_now(&self) -> Timestamp {
        self.retry_after_now
            .unwrap_or_else(|| Timestamp::from_system_time(SystemTime::now()))
    }

    /// Fetches at most 25 unread Message details across at most four list pages.
    pub async fn fetch_unread(
        &self,
        credentials: &CredentialBundle,
    ) -> Result<GmailFetch, GmailError> {
        self.fetch_unread_with_access(credentials.access_token())
            .await
    }

    /// Fetches unread Messages using a request-scoped credential lease.
    pub async fn fetch_unread_authorized(
        &self,
        credentials: &AuthorizedCredential,
    ) -> Result<GmailFetch, GmailError> {
        self.fetch_unread_with_access(credentials.access_token())
            .await
    }

    async fn fetch_unread_with_access(&self, access_token: &str) -> Result<GmailFetch, GmailError> {
        let mut identifiers = Vec::new();
        let mut next_page_token: Option<Zeroizing<String>> = None;
        let mut pagination_truncated = false;

        for page_index in 0..MAX_LIST_PAGES {
            let remaining = MAX_MESSAGES_PER_FETCH - identifiers.len();
            if remaining == 0 {
                break;
            }
            let mut url = self
                .api_root
                .join("messages")
                .map_err(|_| GmailError::MalformedResponse)?;
            {
                let mut query = url.query_pairs_mut();
                query
                    .append_pair("q", UNREAD_QUERY)
                    .append_pair("maxResults", &remaining.to_string());
                if let Some(token) = next_page_token.as_deref() {
                    query.append_pair("pageToken", token);
                }
            }
            let response = self
                .http
                .get(url)
                .timeout(REQUEST_TIMEOUT)
                .bearer_auth(access_token)
                .send()
                .await
                .map_err(|_| GmailError::Offline)?;
            let bytes =
                success_body(response, MAX_LIST_RESPONSE_BYTES, self.retry_after_now()).await?;
            let mut page: MessageListResponse =
                serde_json::from_slice(&bytes).map_err(|_| GmailError::MalformedResponse)?;
            for mut message in page.messages.drain(..) {
                if identifiers.len() == MAX_MESSAGES_PER_FETCH {
                    break;
                }
                if message.id.is_empty() {
                    return Err(GmailError::MalformedResponse);
                }
                identifiers.push(Zeroizing::new(std::mem::take(&mut message.id)));
            }
            next_page_token = page.next_page_token.take().map(Zeroizing::new);
            if next_page_token.is_none() {
                break;
            }
            if page_index + 1 == MAX_LIST_PAGES {
                pagination_truncated = true;
            }
        }
        pagination_truncated |= next_page_token.is_some();

        let identifier_count = identifiers.len();
        let mut outcomes = Vec::with_capacity(identifier_count);
        let mut tasks = tokio::task::JoinSet::new();
        let mut identifiers = identifiers.into_iter().enumerate();
        for _ in 0..MAX_CONCURRENT_DETAILS {
            let Some((ordinal, identifier)) = identifiers.next() else {
                break;
            };
            spawn_detail(
                &mut tasks,
                self.http.clone(),
                self.api_root.clone(),
                Zeroizing::new(access_token.to_owned()),
                ordinal,
                identifier,
                self.retry_after_now,
            );
        }
        while let Some(joined) = tasks.join_next().await {
            outcomes.push(joined.map_err(|_| GmailError::Offline)?);
            if let Some((ordinal, identifier)) = identifiers.next() {
                spawn_detail(
                    &mut tasks,
                    self.http.clone(),
                    self.api_root.clone(),
                    Zeroizing::new(access_token.to_owned()),
                    ordinal,
                    identifier,
                    self.retry_after_now,
                );
            }
        }
        outcomes.sort_by_key(|(ordinal, _)| *ordinal);

        let mut messages = Vec::with_capacity(identifier_count);
        let mut failures = Vec::new();
        for (ordinal, outcome) in outcomes {
            match outcome {
                Ok(message) => messages.push(message),
                Err(error) => failures.push(DetailFailure { ordinal, error }),
            }
        }
        Ok(GmailFetch {
            messages,
            failures,
            pagination_truncated,
        })
    }
}

fn spawn_detail(
    tasks: &mut tokio::task::JoinSet<(usize, Result<GmailMessage, GmailError>)>,
    http: Client,
    api_root: Url,
    access_token: Zeroizing<String>,
    ordinal: usize,
    identifier: Zeroizing<String>,
    retry_after_now: Option<Timestamp>,
) {
    tasks.spawn(async move {
        let now = retry_after_now.unwrap_or_else(|| Timestamp::from_system_time(SystemTime::now()));
        let outcome = fetch_detail(http, api_root, &access_token, &identifier, now).await;
        (ordinal, outcome)
    });
}

async fn fetch_detail(
    http: Client,
    api_root: Url,
    access_token: &str,
    identifier: &str,
    retry_after_now: Timestamp,
) -> Result<GmailMessage, GmailError> {
    let mut url = api_root
        .join("messages/")
        .map_err(|_| GmailError::MalformedResponse)?;
    url.path_segments_mut()
        .map_err(|_| GmailError::MalformedResponse)?
        .pop_if_empty()
        .push(identifier);
    url.query_pairs_mut().append_pair("format", "full");
    let response = http
        .get(url)
        .timeout(REQUEST_TIMEOUT)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|_| GmailError::Offline)?;
    let json = success_body(response, MAX_DETAIL_RESPONSE_BYTES, retry_after_now).await?;
    let envelope: DetailEnvelope<'_> =
        serde_json::from_slice(&json).map_err(|_| GmailError::MalformedResponse)?;
    if envelope.id != identifier {
        return Err(GmailError::MalformedResponse);
    }
    Ok(GmailMessage {
        id: Zeroizing::new(identifier.to_owned()),
        json,
    })
}

impl Default for GmailMailbox {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Deserialize, Zeroize)]
#[zeroize(drop)]
struct MessageReference {
    id: String,
}

#[derive(Deserialize, Zeroize)]
#[zeroize(drop)]
struct MessageListResponse {
    #[serde(default)]
    messages: Vec<MessageReference>,
    #[serde(default, rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct DetailEnvelope<'a> {
    #[serde(borrow)]
    id: &'a str,
    #[serde(rename = "payload")]
    _payload: serde::de::IgnoredAny,
}

async fn success_body(
    response: Response,
    maximum_bytes: usize,
    retry_after_now: Timestamp,
) -> Result<Zeroizing<Vec<u8>>, GmailError> {
    if !response.status().is_success() {
        return Err(map_error_response(response, retry_after_now).await);
    }
    read_bounded_body(response, maximum_bytes).await
}

async fn read_bounded_body(
    mut response: Response,
    maximum_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, GmailError> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum_bytes as u64)
    {
        return Err(GmailError::MalformedResponse);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(1024));
    while let Some(chunk) = response.chunk().await.map_err(|_| GmailError::Offline)? {
        if bytes.len().saturating_add(chunk.len()) > maximum_bytes {
            return Err(GmailError::MalformedResponse);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn map_error_response(response: Response, retry_after_now: Timestamp) -> GmailError {
    let status = response.status();
    let retry_after = parse_retry_after(response.headers(), retry_after_now);
    let base = map_status(status, retry_after, false);
    if status != reqwest::StatusCode::FORBIDDEN {
        return base;
    }
    let body = match read_bounded_body(response, MAX_ERROR_RESPONSE_BYTES).await {
        Ok(body) => body,
        Err(_) => return base,
    };
    if has_rate_limit_reason(&body) {
        GmailError::RateLimited { retry_after }
    } else {
        base
    }
}

fn map_status(
    status: reqwest::StatusCode,
    retry_after: Option<Duration>,
    rate_limit_reason: bool,
) -> GmailError {
    match status.as_u16() {
        401 => GmailError::AuthorizationRequired,
        403 if rate_limit_reason => GmailError::RateLimited { retry_after },
        403 => GmailError::PermissionDenied,
        429 => GmailError::RateLimited { retry_after },
        500..=599 => GmailError::ServerUnavailable,
        400 | 404 => GmailError::MalformedResponse,
        _ => GmailError::UnexpectedStatus,
    }
}

#[derive(Deserialize)]
struct ProviderErrorEnvelope<'a> {
    #[serde(borrow)]
    error: ProviderErrorDetail<'a>,
}

#[derive(Deserialize)]
struct ProviderErrorDetail<'a> {
    #[serde(default, borrow)]
    errors: Vec<ProviderErrorReason<'a>>,
    #[serde(default, borrow)]
    status: Option<&'a str>,
}

#[derive(Deserialize)]
struct ProviderErrorReason<'a> {
    #[serde(borrow)]
    reason: &'a str,
}

fn has_rate_limit_reason(body: &[u8]) -> bool {
    let Ok(envelope) = serde_json::from_slice::<ProviderErrorEnvelope<'_>>(body) else {
        return false;
    };
    envelope.error.status == Some("RESOURCE_EXHAUSTED")
        || envelope.error.errors.iter().any(|error| {
            matches!(
                error.reason,
                "rateLimitExceeded" | "userRateLimitExceeded" | "quotaExceeded"
            )
        })
}

fn parse_retry_after(headers: &reqwest::header::HeaderMap, now: Timestamp) -> Option<Duration> {
    let value = headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?;
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let deadline = chrono::DateTime::parse_from_rfc2822(value).ok()?;
    let remaining_millis = deadline
        .timestamp_millis()
        .saturating_sub(now.unix_millis());
    Some(Duration::from_millis(
        u64::try_from(remaining_millis.max(0)).ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
        time::Duration,
    };

    use crate::{authorization::credentials::CredentialBundle, clock::Timestamp};
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
    };

    use super::{FetchCompleteness, GmailMailbox};

    async fn paging_fixture() -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            for _ in 0..4 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0_u8; 2048];
                loop {
                    let count = stream.read(&mut buffer).await.unwrap();
                    request.extend_from_slice(&buffer[..count]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8(request).unwrap();
                let request_line = request.lines().next().unwrap().to_owned();
                captured.lock().unwrap().push(request_line.clone());
                let body = if request_line.contains("/messages/m1?") {
                    r#"{"id":"m1","threadId":"t1","payload":{"mimeType":"text/plain"}}"#
                } else if request_line.contains("/messages/m2?") {
                    r#"{"id":"m2","threadId":"t2","payload":{"mimeType":"text/plain"}}"#
                } else if request_line.contains("pageToken=next-page") {
                    r#"{"messages":[{"id":"m2"}]}"#
                } else {
                    r#"{"messages":[{"id":"m1"}],"nextPageToken":"next-page"}"#
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
            drop(captured);
            Arc::try_unwrap(requests).unwrap().into_inner().unwrap()
        });
        (base, task)
    }

    async fn concurrency_fixture() -> (String, tokio::task::JoinHandle<usize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(async move {
            let mut handlers = tokio::task::JoinSet::new();
            for _ in 0..9 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let active = Arc::clone(&active);
                let maximum = Arc::clone(&maximum);
                handlers.spawn(async move {
                    let mut request = Vec::new();
                    let mut buffer = [0_u8; 2048];
                    loop {
                        let count = stream.read(&mut buffer).await.unwrap();
                        request.extend_from_slice(&buffer[..count]);
                        if request.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let request = String::from_utf8(request).unwrap();
                    let request_line = request.lines().next().unwrap();
                    let is_detail = request_line.contains("format=full");
                    let body = if is_detail {
                        let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                        maximum.fetch_max(current, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        active.fetch_sub(1, Ordering::SeqCst);
                        let identifier = request_line
                            .split("/messages/")
                            .nth(1)
                            .unwrap()
                            .split('?')
                            .next()
                            .unwrap();
                        format!(
                            r#"{{"id":"{identifier}","payload":{{"mimeType":"text/plain"}}}}"#
                        )
                    } else {
                        let messages = (0..8)
                            .map(|index| format!(r#"{{"id":"m{index}"}}"#))
                            .collect::<Vec<_>>()
                            .join(",");
                        format!(r#"{{"messages":[{messages}]}}"#)
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                });
            }
            while handlers.join_next().await.is_some() {}
            maximum.load(Ordering::SeqCst)
        });
        (base, task)
    }

    async fn one_response_fixture(
        status: u16,
        extra_headers: &'static str,
        body: &'static str,
    ) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 2048];
            loop {
                let count = stream.read(&mut buffer).await.unwrap();
                request.extend_from_slice(&buffer[..count]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let reason = match status {
                200 => "OK",
                401 => "Unauthorized",
                403 => "Forbidden",
                429 => "Too Many Requests",
                503 => "Service Unavailable",
                _ => "Unexpected",
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra_headers}\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8(request).unwrap()
        });
        (base, task)
    }

    async fn partial_fixture() -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut handlers = tokio::task::JoinSet::new();
            for _ in 0..4 {
                let (mut stream, _) = listener.accept().await.unwrap();
                handlers.spawn(async move {
                    let mut request = Vec::new();
                    let mut buffer = [0_u8; 2048];
                    loop {
                        let count = stream.read(&mut buffer).await.unwrap();
                        request.extend_from_slice(&buffer[..count]);
                        if request.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let request = String::from_utf8(request).unwrap();
                    let request_line = request.lines().next().unwrap();
                    let (status, reason, body) = if request_line.contains("/messages/m0?") {
                        (
                            200,
                            "OK",
                            r#"{"id":"m0","payload":{"body":{"data":"secret-body"}}}"#,
                        )
                    } else if request_line.contains("/messages/m1?") {
                        (401, "Unauthorized", r#"{"error":"invalid credential"}"#)
                    } else if request_line.contains("/messages/m2?") {
                        (503, "Service Unavailable", r#"{"error":"server detail"}"#)
                    } else {
                        (
                            200,
                            "OK",
                            r#"{"messages":[{"id":"m0"},{"id":"m1"},{"id":"m2"}]}"#,
                        )
                    };
                    let response = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                });
            }
            while handlers.join_next().await.is_some() {}
        });
        (base, task)
    }

    async fn pagination_limit_fixture() -> (String, tokio::task::JoinHandle<usize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            for page in 0..4 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0_u8; 2048];
                loop {
                    let count = stream.read(&mut buffer).await.unwrap();
                    request.extend_from_slice(&buffer[..count]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let body = format!(r#"{{"nextPageToken":"next-{page}"}}"#);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
            4
        });
        (base, task)
    }

    async fn oversized_list_fixture() -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                super::MAX_LIST_RESPONSE_BYTES + 1
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        (base, task)
    }

    async fn cap_continuation_fixture() -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut handlers = tokio::task::JoinSet::new();
            for _ in 0..26 {
                let (mut stream, _) = listener.accept().await.unwrap();
                handlers.spawn(async move {
                    let mut request = Vec::new();
                    let mut buffer = [0_u8; 2048];
                    loop {
                        let count = stream.read(&mut buffer).await.unwrap();
                        request.extend_from_slice(&buffer[..count]);
                        if request.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let request = String::from_utf8(request).unwrap();
                    let request_line = request.lines().next().unwrap();
                    let body = if request_line.contains("format=full") {
                        let identifier = request_line
                            .split("/messages/")
                            .nth(1)
                            .unwrap()
                            .split('?')
                            .next()
                            .unwrap();
                        format!(r#"{{"id":"{identifier}","payload":{{}}}}"#)
                    } else {
                        let messages = (0..25)
                            .map(|index| format!(r#"{{"id":"m{index}"}}"#))
                            .collect::<Vec<_>>()
                            .join(",");
                        format!(
                            r#"{{"messages":[{messages}],"nextPageToken":"more-unread"}}"#
                        )
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                });
            }
            while handlers.join_next().await.is_some() {}
        });
        (base, task)
    }

    async fn broken_error_body_fixture(
        status: u16,
        retry_after: Option<u64>,
        oversized: bool,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request).await.unwrap();
            let retry = retry_after
                .map(|seconds| format!("Retry-After: {seconds}\r\n"))
                .unwrap_or_default();
            let (length, body) = if oversized {
                (super::MAX_ERROR_RESPONSE_BYTES + 1, "")
            } else {
                (100, "{")
            };
            let response = format!(
                "HTTP/1.1 {status} Broken\r\nContent-Type: application/json\r\n{retry}Content-Length: {length}\r\nConnection: close\r\n\r\n{body}"
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        (base, task)
    }

    fn credentials() -> CredentialBundle {
        CredentialBundle::new(
            "access-secret".to_owned(),
            "refresh-secret".to_owned(),
            Timestamp::from_unix_millis(3_600_000),
            "person@example.com".to_owned(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn unread_query_pages_are_bounded_and_details_preserve_list_order() {
        let (base, fixture) = paging_fixture().await;
        let mailbox = GmailMailbox::for_test(&base).unwrap();

        let result = mailbox.fetch_unread(&credentials()).await.unwrap();

        assert_eq!(result.completeness(), FetchCompleteness::Complete);
        assert_eq!(
            result
                .messages()
                .iter()
                .map(|message| message.id())
                .collect::<Vec<_>>(),
            ["m1", "m2"]
        );
        let requests = fixture.await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.contains("/messages?"))
                .count(),
            2
        );
        assert!(requests[0].contains("q=is%3Aunread"));
        assert!(requests[0].contains("maxResults=25"));
        assert!(requests[1].contains("pageToken=next-page"));
        assert!(requests
            .iter()
            .filter(|request| request.contains("format=full"))
            .all(|request| request.starts_with("GET ")));
    }

    #[tokio::test]
    async fn detail_fetch_uses_at_most_four_concurrent_requests() {
        let (base, fixture) = concurrency_fixture().await;
        let mailbox = GmailMailbox::for_test(&base).unwrap();

        let result = mailbox.fetch_unread(&credentials()).await.unwrap();

        assert_eq!(result.messages().len(), 8);
        assert_eq!(result.completeness(), FetchCompleteness::Complete);
        assert_eq!(fixture.await.unwrap(), 4);
        assert_eq!(
            result
                .messages()
                .iter()
                .map(|message| message.id())
                .collect::<Vec<_>>(),
            ["m0", "m1", "m2", "m3", "m4", "m5", "m6", "m7"]
        );
    }

    #[tokio::test]
    async fn list_status_offline_and_malformed_failures_have_stable_mappings() {
        for (status, headers, body, expected) in [
            (
                401,
                "",
                r#"{"error":"credential-secret"}"#,
                super::GmailError::AuthorizationRequired,
            ),
            (
                403,
                "",
                r#"{"error":"permission-secret"}"#,
                super::GmailError::PermissionDenied,
            ),
            (
                403,
                "Retry-After: 9\r\n",
                r#"{"error":{"errors":[{"reason":"userRateLimitExceeded"}]}}"#,
                super::GmailError::RateLimited {
                    retry_after: Some(Duration::from_secs(9)),
                },
            ),
            (
                429,
                "Retry-After: 17\r\n",
                r#"{"error":"rate-secret"}"#,
                super::GmailError::RateLimited {
                    retry_after: Some(Duration::from_secs(17)),
                },
            ),
            (
                503,
                "",
                r#"{"error":"server-secret"}"#,
                super::GmailError::ServerUnavailable,
            ),
            (200, "", "{malformed", super::GmailError::MalformedResponse),
        ] {
            let (base, fixture) = one_response_fixture(status, headers, body).await;
            let mailbox = GmailMailbox::for_test(&base).unwrap();
            let error = mailbox.fetch_unread(&credentials()).await.unwrap_err();
            assert_eq!(error, expected);
            let rendered = format!("{error:?}");
            assert!(!rendered.contains("secret"));
            let request = fixture.await.unwrap();
            assert!(request
                .to_ascii_lowercase()
                .contains("authorization: bearer access-secret"));
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        assert!(matches!(
            GmailMailbox::for_test(&base)
                .unwrap()
                .fetch_unread(&credentials())
                .await,
            Err(super::GmailError::Offline)
        ));
    }

    #[tokio::test]
    async fn failed_details_return_typed_partial_completeness_without_identifiers() {
        let (base, fixture) = partial_fixture().await;
        let mailbox = GmailMailbox::for_test(&base).unwrap();

        let result = mailbox.fetch_unread(&credentials()).await.unwrap();

        assert_eq!(
            result.completeness(),
            FetchCompleteness::Partial {
                failed_details: 2,
                pagination_truncated: false,
            }
        );
        assert_eq!(result.messages().len(), 1);
        assert_eq!(result.messages()[0].id(), "m0");
        assert_eq!(result.failures()[0].ordinal(), 1);
        assert_eq!(
            result.failures()[0].error(),
            super::GmailError::AuthorizationRequired
        );
        assert_eq!(result.failures()[1].ordinal(), 2);
        assert_eq!(
            result.failures()[1].error(),
            super::GmailError::ServerUnavailable
        );
        let rendered = format!("{result:?}");
        assert!(!rendered.contains("m0"));
        assert!(!rendered.contains("m1"));
        assert!(!rendered.contains("m2"));
        assert!(!rendered.contains("secret-body"));
        fixture.await.unwrap();
    }

    #[tokio::test]
    async fn page_count_and_response_body_limits_are_explicit() {
        let (base, fixture) = pagination_limit_fixture().await;
        let mailbox = GmailMailbox::for_test(&base).unwrap();
        let result = mailbox.fetch_unread(&credentials()).await.unwrap();
        assert_eq!(
            result.completeness(),
            FetchCompleteness::Partial {
                failed_details: 0,
                pagination_truncated: true,
            }
        );
        assert_eq!(fixture.await.unwrap(), 4);

        let (base, fixture) = oversized_list_fixture().await;
        assert!(matches!(
            GmailMailbox::for_test(&base)
                .unwrap()
                .fetch_unread(&credentials())
                .await,
            Err(super::GmailError::MalformedResponse)
        ));
        fixture.await.unwrap();
    }

    #[tokio::test]
    async fn continuation_after_message_cap_is_partial() {
        let (base, fixture) = cap_continuation_fixture().await;
        let result = GmailMailbox::for_test(&base)
            .unwrap()
            .fetch_unread(&credentials())
            .await
            .unwrap();

        assert_eq!(result.messages().len(), 25);
        assert_eq!(
            result.completeness(),
            FetchCompleteness::Partial {
                failed_details: 0,
                pagination_truncated: true,
            }
        );
        fixture.await.unwrap();
    }

    #[tokio::test]
    async fn authoritative_status_survives_oversized_and_truncated_error_bodies() {
        for (status, retry_after, oversized, expected) in [
            (401, None, true, super::GmailError::AuthorizationRequired),
            (
                429,
                Some(12),
                false,
                super::GmailError::RateLimited {
                    retry_after: Some(Duration::from_secs(12)),
                },
            ),
            (503, None, true, super::GmailError::ServerUnavailable),
            (403, None, false, super::GmailError::PermissionDenied),
        ] {
            let (base, fixture) = broken_error_body_fixture(status, retry_after, oversized).await;
            assert_eq!(
                GmailMailbox::for_test(&base)
                    .unwrap()
                    .fetch_unread(&credentials())
                    .await
                    .unwrap_err(),
                expected
            );
            fixture.await.unwrap();
        }
    }

    #[tokio::test]
    async fn retry_after_http_date_uses_injected_check_time() {
        let deadline =
            chrono::DateTime::parse_from_rfc2822("Wed, 21 Oct 2015 07:28:00 GMT").unwrap();
        let now = Timestamp::from_unix_millis(deadline.timestamp_millis() - 30_000);
        let (base, fixture) = one_response_fixture(
            429,
            "Retry-After: Wed, 21 Oct 2015 07:28:00 GMT\r\n",
            r#"{"error":"rate-secret"}"#,
        )
        .await;

        assert_eq!(
            GmailMailbox::for_test_at(&base, now)
                .unwrap()
                .fetch_unread(&credentials())
                .await
                .unwrap_err(),
            super::GmailError::RateLimited {
                retry_after: Some(Duration::from_secs(30)),
            }
        );
        fixture.await.unwrap();
    }
}
