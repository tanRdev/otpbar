//! Strict, single-use native OAuth loopback callback receiver.
//!
//! The browser redirect is exposed only after an IP-literal loopback listener
//! has bound an ephemeral port. Hostile or malformed local requests receive a
//! fixed response and cannot become Authorization callbacks.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot, Notify},
    task::JoinSet,
    time::Instant,
};
use zeroize::Zeroizing;

use super::core::AttemptId;

const CALLBACK_PATH: &str = "/oauth/callback";
const MAX_HEADER_BYTES: usize = 8 * 1024;
const MAX_CONCURRENT_CONNECTIONS: usize = 16;
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(2);

const SUCCESS_HTML: &str =
    "<!doctype html><html><body>Authorization received. You may close this window.</body></html>";
const DENIED_HTML: &str =
    "<!doctype html><html><body>Authorization was declined. You may close this window.</body></html>";
const FAILED_HTML: &str =
    "<!doctype html><html><body>Authorization could not be completed. Return to OTPBar.</body></html>";
const INVALID_HTML: &str =
    "<!doctype html><html><body>This callback request is invalid.</body></html>";
const ALREADY_RECEIVED_HTML: &str =
    "<!doctype html><html><body>An Authorization callback was already received.</body></html>";

/// Safe classification of a terminal provider callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopbackCallbackKind {
    /// The provider returned an Authorization code ready for state validation.
    AuthorizationCode,
    /// The user or provider explicitly denied Authorization.
    Denied,
    /// The provider returned another error, whose raw value was discarded.
    ProviderError,
}

/// One terminal callback, with secrets unavailable to formatting/serialization.
pub struct LoopbackCallback {
    attempt_id: AttemptId,
    kind: LoopbackCallbackKind,
    authorization_code: Option<Zeroizing<String>>,
    state: Zeroizing<String>,
}

impl LoopbackCallback {
    /// Returns the core attempt that owns this listener.
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the provider-string-free terminal classification.
    pub const fn kind(&self) -> LoopbackCallbackKind {
        self.kind
    }

    /// Returns the short-lived code only for token exchange.
    pub fn authorization_code(&self) -> Option<&str> {
        self.authorization_code
            .as_deref()
            .map(std::string::String::as_str)
    }

    /// Returns the state only for the core's constant-time validation.
    pub fn state(&self) -> &str {
        &self.state
    }
}

impl fmt::Debug for LoopbackCallback {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoopbackCallback")
            .field("attempt_id", &self.attempt_id)
            .field("kind", &self.kind)
            .field(
                "authorization_code",
                &self.authorization_code.as_ref().map(|_| "[redacted]"),
            )
            .field("state", &"[redacted]")
            .finish()
    }
}

/// Stable, provider-string-free loopback lifecycle failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopbackError {
    /// The required IP-literal loopback socket could not be bound.
    BindFailed,
    /// The bound listener stopped accepting connections unexpectedly.
    ListenerFailed,
    /// The owning Authorization attempt cancelled or was replaced.
    Cancelled,
    /// No terminal callback arrived before the supplied deadline.
    TimedOut,
}

impl fmt::Display for LoopbackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::BindFailed => "The local Authorization callback could not start.",
            Self::ListenerFailed => "The local Authorization callback stopped unexpectedly.",
            Self::Cancelled => "Authorization was cancelled.",
            Self::TimedOut => "Authorization timed out.",
        })
    }
}

impl std::error::Error for LoopbackError {}

#[derive(Default)]
struct CancellationState {
    cancelled: AtomicBool,
    notify: Notify,
}

/// Cloneable cancellation signal for one listener lifecycle.
#[derive(Clone, Default)]
pub struct LoopbackCancellation {
    state: Arc<CancellationState>,
}

impl LoopbackCancellation {
    /// Creates a signal scoped to one loopback listener lifecycle.
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancels the listener idempotently and wakes its receiver.
    pub fn cancel(&self) {
        if !self.state.cancelled.swap(true, Ordering::AcqRel) {
            self.state.notify.notify_waiters();
        }
    }

    async fn cancelled(&self) {
        loop {
            let notified = self.state.notify.notified();
            if self.state.cancelled.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

/// One already-bound ephemeral loopback callback listener.
pub struct LoopbackCallbackListener {
    attempt_id: AttemptId,
    listener: TcpListener,
    address: SocketAddr,
}

impl LoopbackCallbackListener {
    /// Binds `127.0.0.1:0` before returning any successful redirect URI.
    pub async fn bind(attempt_id: AttemptId) -> Result<Self, LoopbackError> {
        Self::bind_at(
            attempt_id,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .await
    }

    async fn bind_at(
        attempt_id: AttemptId,
        requested_address: SocketAddr,
    ) -> Result<Self, LoopbackError> {
        if !requested_address.ip().is_loopback() {
            return Err(LoopbackError::BindFailed);
        }
        let listener = TcpListener::bind(requested_address)
            .await
            .map_err(|_| LoopbackError::BindFailed)?;
        let address = listener
            .local_addr()
            .map_err(|_| LoopbackError::BindFailed)?;
        Ok(Self {
            attempt_id,
            listener,
            address,
        })
    }

    /// Returns the registered browser redirect only after the listener is bound.
    pub fn redirect_uri(&self) -> String {
        format!("http://{}{}", self.address, CALLBACK_PATH)
    }

    /// Returns the already-bound address for native adapter orchestration.
    pub const fn local_addr(&self) -> SocketAddr {
        self.address
    }

    /// Receives at most one terminal callback and then deterministically closes.
    ///
    /// Requests are processed concurrently so a slow local peer cannot block a
    /// valid browser callback. No shared-state lock is held across socket I/O.
    pub async fn receive_until(
        self,
        deadline: Instant,
        cancellation: LoopbackCancellation,
    ) -> Result<LoopbackCallback, LoopbackError> {
        let expected_host = self.address.to_string();
        let (candidate_sender, mut candidate_receiver) = mpsc::channel(MAX_CONCURRENT_CONNECTIONS);
        let mut connections = JoinSet::new();

        loop {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => {
                    connections.abort_all();
                    return Err(LoopbackError::Cancelled);
                }
                () = tokio::time::sleep_until(deadline) => {
                    connections.abort_all();
                    return Err(LoopbackError::TimedOut);
                }
                accepted = self.listener.accept(),
                    if connections.len() < MAX_CONCURRENT_CONNECTIONS =>
                {
                    let (stream, peer) = accepted.map_err(|_| LoopbackError::ListenerFailed)?;
                    if !peer.ip().is_loopback() {
                        continue;
                    }
                    let sender = candidate_sender.clone();
                    let host = expected_host.clone();
                    let attempt_id = self.attempt_id;
                    connections.spawn(async move {
                        handle_connection(stream, &host, attempt_id, sender).await;
                    });
                }
                Some(candidate) = candidate_receiver.recv() => {
                    let callback = candidate.callback;
                    let _ = candidate.decision.send(true);

                    // Stop accepting and settle every connection accepted before
                    // arbitration. Other terminal candidates receive one fixed
                    // loser response; bounded partial requests finish or time out.
                    while !connections.is_empty() {
                        tokio::select! {
                            biased;
                            Some(loser) = candidate_receiver.recv() => {
                                let _ = loser.decision.send(false);
                            }
                            _ = connections.join_next() => {}
                        }
                    }
                    return Ok(callback);
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    }
}

enum ParsedCallback {
    AuthorizationCode {
        code: Zeroizing<String>,
        state: Zeroizing<String>,
    },
    Denied {
        state: Zeroizing<String>,
    },
    ProviderError {
        state: Zeroizing<String>,
    },
}

struct TerminalCandidate {
    callback: LoopbackCallback,
    decision: oneshot::Sender<bool>,
}

async fn handle_connection(
    mut stream: TcpStream,
    expected_host: &str,
    attempt_id: AttemptId,
    candidate_sender: mpsc::Sender<TerminalCandidate>,
) {
    let request = match read_bounded_request(&mut stream).await {
        Ok(request) => request,
        Err(RequestFailure::Oversized) => {
            write_fixed_response(&mut stream, 431, INVALID_HTML).await;
            return;
        }
        Err(RequestFailure::Invalid | RequestFailure::TimedOut) => {
            write_fixed_response(&mut stream, 400, INVALID_HTML).await;
            return;
        }
    };

    let parsed = match parse_request(&request, expected_host) {
        Some(parsed) => parsed,
        None => {
            write_fixed_response(&mut stream, 400, INVALID_HTML).await;
            return;
        }
    };

    let (callback, winner_html) = match parsed {
        ParsedCallback::AuthorizationCode { code, state } => (
            LoopbackCallback {
                attempt_id,
                kind: LoopbackCallbackKind::AuthorizationCode,
                authorization_code: Some(code),
                state,
            },
            SUCCESS_HTML,
        ),
        ParsedCallback::Denied { state } => (
            LoopbackCallback {
                attempt_id,
                kind: LoopbackCallbackKind::Denied,
                authorization_code: None,
                state,
            },
            DENIED_HTML,
        ),
        ParsedCallback::ProviderError { state } => (
            LoopbackCallback {
                attempt_id,
                kind: LoopbackCallbackKind::ProviderError,
                authorization_code: None,
                state,
            },
            FAILED_HTML,
        ),
    };

    let (decision, receiver) = oneshot::channel();
    if candidate_sender
        .send(TerminalCandidate { callback, decision })
        .await
        .is_err()
    {
        return;
    }
    match receiver.await {
        Ok(true) => write_fixed_response(&mut stream, 200, winner_html).await,
        Ok(false) => write_fixed_response(&mut stream, 409, ALREADY_RECEIVED_HTML).await,
        Err(_) => {}
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestFailure {
    Invalid,
    Oversized,
    TimedOut,
}

async fn read_bounded_request(
    stream: &mut TcpStream,
) -> Result<Zeroizing<Vec<u8>>, RequestFailure> {
    tokio::time::timeout(REQUEST_READ_TIMEOUT, async {
        let mut request = Zeroizing::new(Vec::with_capacity(1024));
        let mut buffer = Zeroizing::new([0_u8; 1024]);
        loop {
            let count = stream
                .read(&mut buffer[..])
                .await
                .map_err(|_| RequestFailure::Invalid)?;
            if count == 0 {
                return Err(RequestFailure::Invalid);
            }
            if request.len().saturating_add(count) > MAX_HEADER_BYTES {
                return Err(RequestFailure::Oversized);
            }
            request.extend_from_slice(&buffer[..count]);
            if let Some(end) = find_header_end(&request) {
                if end != request.len() {
                    return Err(RequestFailure::Invalid);
                }
                return Ok(request);
            }
        }
    })
    .await
    .map_err(|_| RequestFailure::TimedOut)?
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn parse_request(request: &[u8], expected_host: &str) -> Option<ParsedCallback> {
    let request = std::str::from_utf8(request).ok()?;
    let mut lines = request.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some() || method != "GET" || version != "HTTP/1.1" {
        return None;
    }

    let mut host = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if line.starts_with([' ', '\t']) {
            return None;
        }
        let (name, value) = line.split_once(':')?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
        {
            return None;
        }
        let value = value.trim_matches([' ', '\t']);
        if value.bytes().any(|byte| byte.is_ascii_control()) {
            return None;
        }
        if name.eq_ignore_ascii_case("host") {
            if host.replace(value).is_some() {
                return None;
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            || (name.eq_ignore_ascii_case("content-length") && value != "0")
        {
            return None;
        }
    }
    if host != Some(expected_host) {
        return None;
    }

    let (path, query) = target.split_once('?')?;
    if path != CALLBACK_PATH || query.is_empty() || target.contains('#') {
        return None;
    }
    parse_query(query)
}

fn parse_query(query: &str) -> Option<ParsedCallback> {
    let mut code = None;
    let mut state = None;
    let mut error = None;

    for pair in query.split('&') {
        let (raw_name, raw_value) = pair.split_once('=')?;
        let name = percent_decode_once(raw_name)?;
        match name.as_str() {
            "code" => set_once(&mut code, Zeroizing::new(percent_decode_once(raw_value)?))?,
            "state" => set_once(&mut state, Zeroizing::new(percent_decode_once(raw_value)?))?,
            "error" => set_once(&mut error, percent_decode_once(raw_value)?)?,
            _ => {}
        }
    }

    let state = state.filter(|value| !value.is_empty())?;
    match (code, error) {
        (Some(code), None) if !code.is_empty() => {
            Some(ParsedCallback::AuthorizationCode { code, state })
        }
        (None, Some(error)) if error == "access_denied" => Some(ParsedCallback::Denied { state }),
        (None, Some(error)) if !error.is_empty() => Some(ParsedCallback::ProviderError { state }),
        _ => None,
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Option<()> {
    if slot.replace(value).is_some() {
        return None;
    }
    Some(())
}

fn percent_decode_once(value: &str) -> Option<String> {
    let mut decoded = Zeroizing::new(Vec::with_capacity(value.len()));
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let high = *bytes.get(index + 1)?;
                let low = *bytes.get(index + 2)?;
                decoded.push(
                    hex_value(high)?
                        .checked_mul(16)?
                        .checked_add(hex_value(low)?)?,
                );
                index += 3;
            }
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    let text = std::str::from_utf8(&decoded).ok()?;
    if text.chars().any(char::is_control) {
        return None;
    }
    Some(
        String::from_utf8(std::mem::take(decoded.as_mut()))
            .expect("UTF-8 was validated before ownership transfer"),
    )
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

async fn write_fixed_response(stream: &mut TcpStream, status: u16, html: &'static str) {
    let reason = match status {
        200 => "OK",
        409 => "Conflict",
        431 => "Request Header Fields Too Large",
        _ => "Bad Request",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Content-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Connection: close\r\n\r\n{html}",
        html.len()
    );
    let _ = tokio::time::timeout(REQUEST_READ_TIMEOUT, async {
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authorization::core::AuthorizationCore, domain::error::ErrorEnvelope, ports::RandomSource,
    };
    use std::time::Duration;

    struct FixedRandom;

    impl RandomSource for FixedRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), ErrorEnvelope> {
            destination.fill(7);
            Ok(())
        }
    }

    fn attempt_id() -> AttemptId {
        let mut core = AuthorizationCore::new(Duration::from_secs(30));
        core.prepare(&mut FixedRandom)
            .expect("fixed random prepares an attempt")
            .attempt_id()
    }

    async fn try_request(address: SocketAddr, request: &str) -> std::io::Result<String> {
        let stream = TcpStream::connect(address).await?;
        request_on_stream(stream, request).await
    }

    async fn request_on_stream(mut stream: TcpStream, request: &str) -> std::io::Result<String> {
        stream.write_all(request.as_bytes()).await?;
        let mut response = String::new();
        stream.read_to_string(&mut response).await?;
        Ok(response)
    }

    async fn request(address: SocketAddr, request: &str) -> String {
        try_request(address, request)
            .await
            .expect("complete callback request")
    }

    fn valid_request(host: SocketAddr, query: &str) -> String {
        format!("GET {CALLBACK_PATH}?{query} HTTP/1.1\r\nHost: {host}\r\n\r\n")
    }

    #[tokio::test]
    async fn redirect_is_an_ip_literal_ephemeral_port_bound_before_success() {
        let listener = LoopbackCallbackListener::bind(attempt_id())
            .await
            .expect("loopback bind");

        assert_eq!(listener.address.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_ne!(listener.address.port(), 0);
        assert_eq!(
            listener.redirect_uri(),
            format!(
                "http://127.0.0.1:{}/oauth/callback",
                listener.address.port()
            )
        );
        assert!(listener.listener.local_addr().is_ok());
    }

    #[tokio::test]
    async fn success_decodes_each_query_value_once_and_closes_listener() {
        let id = attempt_id();
        let listener = LoopbackCallbackListener::bind(id).await.unwrap();
        let address = listener.local_addr();
        let cancellation = LoopbackCancellation::new();
        let receiver = tokio::spawn(
            listener.receive_until(Instant::now() + Duration::from_secs(5), cancellation),
        );

        let provider_secret = "provider-secret-%2F";
        let response = request(
            address,
            &valid_request(address, "code=provider-secret-%252F&state=state%2Dvalue"),
        )
        .await;
        let callback = receiver.await.unwrap().unwrap();

        assert_eq!(callback.attempt_id(), id);
        assert_eq!(callback.kind(), LoopbackCallbackKind::AuthorizationCode);
        assert_eq!(callback.authorization_code(), Some(provider_secret));
        assert_eq!(callback.state(), "state-value");
        assert!(!response.contains(provider_secret));
        assert!(!response.contains("state-value"));
        assert!(format!("{callback:?}").contains("[redacted]"));
        assert!(TcpStream::connect(address).await.is_err());
    }

    #[tokio::test]
    async fn wrong_method_path_host_body_and_duplicate_security_fields_are_nonterminal() {
        let listener = LoopbackCallbackListener::bind(attempt_id()).await.unwrap();
        let address = listener.local_addr();
        let cancellation = LoopbackCancellation::new();
        let receiver = tokio::spawn(
            listener.receive_until(Instant::now() + Duration::from_secs(5), cancellation),
        );

        let invalid = [
            format!("POST {CALLBACK_PATH}?code=x&state=s HTTP/1.1\r\nHost: {address}\r\n\r\n"),
            format!("GET /wrong?code=x&state=s HTTP/1.1\r\nHost: {address}\r\n\r\n"),
            format!("GET {CALLBACK_PATH}?code=x&state=s HTTP/1.1\r\nHost: localhost\r\n\r\n"),
            format!(
                "GET {CALLBACK_PATH}?code=x&state=s HTTP/1.1\r\nHost: {address}\r\nContent-Length: 1\r\n\r\n"
            ),
            valid_request(address, "code=x&code=y&state=s"),
        ];
        for request_text in invalid {
            assert!(request(address, &request_text)
                .await
                .starts_with("HTTP/1.1 400"));
        }

        let response = request(address, &valid_request(address, "code=good&state=state")).await;
        assert!(response.starts_with("HTTP/1.1 200"));
        assert_eq!(
            receiver.await.unwrap().unwrap().authorization_code(),
            Some("good")
        );
    }

    #[tokio::test]
    async fn provider_denial_and_error_are_typed_and_never_reflected() {
        for (error, expected_kind) in [
            ("access_denied", LoopbackCallbackKind::Denied),
            (
                "\"><script>alert(1)</script>",
                LoopbackCallbackKind::ProviderError,
            ),
        ] {
            let listener = LoopbackCallbackListener::bind(attempt_id()).await.unwrap();
            let address = listener.local_addr();
            let receiver = tokio::spawn(listener.receive_until(
                Instant::now() + Duration::from_secs(5),
                LoopbackCancellation::new(),
            ));
            let encoded_error = error
                .bytes()
                .map(|byte| format!("%{byte:02X}"))
                .collect::<String>();
            let response = request(
                address,
                &valid_request(
                    address,
                    &format!("error={encoded_error}&state=secret-state"),
                ),
            )
            .await;
            let callback = receiver.await.unwrap().unwrap();

            assert_eq!(callback.kind(), expected_kind);
            assert_eq!(callback.authorization_code(), None);
            assert!(!response.contains(error));
            assert!(!response.contains("secret-state"));
        }
    }

    #[tokio::test]
    async fn oversized_and_slow_requests_cannot_terminate_the_receiver() {
        let listener = LoopbackCallbackListener::bind(attempt_id()).await.unwrap();
        let address = listener.local_addr();
        let cancellation = LoopbackCancellation::new();
        let receiver = tokio::spawn(
            listener.receive_until(Instant::now() + Duration::from_secs(5), cancellation),
        );

        let oversized = format!(
            "GET {CALLBACK_PATH}?code={}&state=s HTTP/1.1\r\nHost: {address}\r\n\r\n",
            "a".repeat(MAX_HEADER_BYTES)
        );
        assert!(request(address, &oversized)
            .await
            .starts_with("HTTP/1.1 431"));

        let mut slow = TcpStream::connect(address).await.unwrap();
        slow.write_all(b"GET /").await.unwrap();
        let response = request(address, &valid_request(address, "code=good&state=state")).await;
        assert!(response.starts_with("HTTP/1.1 200"));
        assert_eq!(
            receiver.await.unwrap().unwrap().authorization_code(),
            Some("good")
        );
    }

    #[tokio::test]
    async fn cancellation_timeout_bind_failure_and_replacement_close_deterministically() {
        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let occupied_address = occupied.local_addr().unwrap();
        assert!(matches!(
            LoopbackCallbackListener::bind_at(attempt_id(), occupied_address).await,
            Err(LoopbackError::BindFailed)
        ));

        let cancelled_listener = LoopbackCallbackListener::bind(attempt_id()).await.unwrap();
        let cancelled_address = cancelled_listener.local_addr();
        let cancellation = LoopbackCancellation::new();
        let receiver = tokio::spawn(cancelled_listener.receive_until(
            Instant::now() + Duration::from_secs(5),
            cancellation.clone(),
        ));
        cancellation.cancel();
        assert!(matches!(
            receiver.await.unwrap(),
            Err(LoopbackError::Cancelled)
        ));
        assert!(TcpStream::connect(cancelled_address).await.is_err());

        let timed_listener = LoopbackCallbackListener::bind(attempt_id()).await.unwrap();
        let timed_address = timed_listener.local_addr();
        assert!(matches!(
            timed_listener
                .receive_until(Instant::now(), LoopbackCancellation::new())
                .await,
            Err(LoopbackError::TimedOut)
        ));
        assert!(TcpStream::connect(timed_address).await.is_err());

        let replacement = LoopbackCallbackListener::bind(attempt_id()).await.unwrap();
        let replacement_address = replacement.local_addr();
        let receiver = tokio::spawn(replacement.receive_until(
            Instant::now() + Duration::from_secs(5),
            LoopbackCancellation::new(),
        ));
        let _ = request(
            replacement_address,
            &valid_request(replacement_address, "code=new&state=state"),
        )
        .await;
        assert_eq!(
            receiver.await.unwrap().unwrap().authorization_code(),
            Some("new")
        );
    }

    #[tokio::test]
    async fn concurrent_terminal_requests_deliver_exactly_one_callback() {
        for _ in 0..32 {
            let listener = LoopbackCallbackListener::bind(attempt_id()).await.unwrap();
            let address = listener.local_addr();
            let receiver = tokio::spawn(listener.receive_until(
                Instant::now() + Duration::from_secs(5),
                LoopbackCancellation::new(),
            ));
            let first_stream = TcpStream::connect(address).await.unwrap();
            let second_stream = TcpStream::connect(address).await.unwrap();
            let first = valid_request(address, "code=first&state=state");
            let second = valid_request(address, "code=second&state=state");

            let (first_response, second_response) = tokio::join!(
                request_on_stream(first_stream, &first),
                request_on_stream(second_stream, &second)
            );
            let callback = receiver.await.unwrap().unwrap();
            let responses = [first_response.unwrap(), second_response.unwrap()];

            assert!(matches!(
                callback.authorization_code(),
                Some("first" | "second")
            ));
            assert_eq!(
                responses
                    .iter()
                    .filter(|response| response.starts_with("HTTP/1.1 200"))
                    .count(),
                1
            );
            assert_eq!(
                responses
                    .iter()
                    .filter(|response| response.starts_with("HTTP/1.1 409"))
                    .count(),
                1
            );
            assert!(TcpStream::connect(address).await.is_err());
        }
    }
}
