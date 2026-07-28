//! Google public-client Authorization transport.

use std::{fmt, time::Duration};

use reqwest::{Client, Url};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use super::{
    core::{AuthorizationRequest, ExchangeMaterial},
    credentials::CredentialBundle,
};

const GOOGLE_AUTHORIZATION_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_PROFILE_ENDPOINT: &str = "https://gmail.googleapis.com/gmail/v1/users/me/profile";
pub const GMAIL_READONLY_SCOPE: &str = "https://www.googleapis.com/auth/gmail.readonly";
const MAX_AUTHORIZATION_RESPONSE_BYTES: usize = 64 * 1024;
const AUTHORIZATION_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Stable, provider-payload-free Google Authorization failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoogleAuthorizationError {
    ConfigurationMissing,
    Offline,
    AuthorizationRejected,
    PermissionDenied,
    RateLimited,
    ProviderUnavailable,
    RefreshRequired,
    MalformedResponse,
}

impl fmt::Display for GoogleAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ConfigurationMissing => "Google Authorization is not configured.",
            Self::Offline => "Google Authorization is temporarily offline.",
            Self::AuthorizationRejected => "Google rejected the Authorization credential.",
            Self::PermissionDenied => "Google did not grant the required read-only permission.",
            Self::RateLimited => "Google temporarily rate limited Authorization.",
            Self::ProviderUnavailable => "Google Authorization is temporarily unavailable.",
            Self::RefreshRequired => "Google Authorization must be renewed.",
            Self::MalformedResponse => "Google returned an invalid Authorization response.",
        })
    }
}

impl std::error::Error for GoogleAuthorizationError {}

impl GoogleAuthorizationError {
    /// Maps transport failures into the pure Authorization state machine.
    pub const fn authorization_failure(self) -> super::core::AuthorizationFailure {
        match self {
            Self::ConfigurationMissing => super::core::AuthorizationFailure::ConfigurationMissing,
            Self::RefreshRequired => super::core::AuthorizationFailure::RefreshRequired,
            Self::Offline
            | Self::AuthorizationRejected
            | Self::PermissionDenied
            | Self::RateLimited
            | Self::ProviderUnavailable
            | Self::MalformedResponse => super::core::AuthorizationFailure::ExchangeFailed,
        }
    }
}

/// Public native-client configuration. It deliberately has no client secret.
pub struct GoogleConfiguration {
    client_id: String,
    authorization_endpoint: Url,
    token_endpoint: Url,
    profile_endpoint: Url,
}

impl GoogleConfiguration {
    /// Loads the client ID embedded by the build and fixed Google endpoints.
    pub fn from_build() -> Result<Self, GoogleAuthorizationError> {
        Self::new(
            option_env!("GOOGLE_CLIENT_ID").unwrap_or_default(),
            GOOGLE_AUTHORIZATION_ENDPOINT,
            GOOGLE_TOKEN_ENDPOINT,
            GOOGLE_PROFILE_ENDPOINT,
        )
    }

    fn new(
        client_id: &str,
        authorization_endpoint: &str,
        token_endpoint: &str,
        profile_endpoint: &str,
    ) -> Result<Self, GoogleAuthorizationError> {
        if client_id.trim().is_empty() {
            return Err(GoogleAuthorizationError::ConfigurationMissing);
        }
        Ok(Self {
            client_id: client_id.to_owned(),
            authorization_endpoint: parse_endpoint(authorization_endpoint)?,
            token_endpoint: parse_endpoint(token_endpoint)?,
            profile_endpoint: parse_endpoint(profile_endpoint)?,
        })
    }

    #[cfg(test)]
    fn for_test(
        client_id: &str,
        authorization_endpoint: &str,
        token_endpoint: &str,
        profile_endpoint: &str,
    ) -> Result<Self, GoogleAuthorizationError> {
        Self::new(
            client_id,
            authorization_endpoint,
            token_endpoint,
            profile_endpoint,
        )
    }
}

fn parse_endpoint(endpoint: &str) -> Result<Url, GoogleAuthorizationError> {
    Url::parse(endpoint).map_err(|_| GoogleAuthorizationError::ConfigurationMissing)
}

/// Stateless Google OAuth transport; methods never require an external lock.
pub struct GoogleAuthorization {
    configuration: GoogleConfiguration,
    http: Client,
}

impl GoogleAuthorization {
    /// Creates an adapter with a reusable HTTP client.
    pub fn new(configuration: GoogleConfiguration) -> Self {
        Self {
            configuration,
            http: Client::new(),
        }
    }

    /// Builds a read-only public-client Authorization URL.
    pub fn authorization_url(
        &self,
        request: &AuthorizationRequest,
        redirect_uri: &str,
    ) -> Result<String, GoogleAuthorizationError> {
        let mut url = self.configuration.authorization_endpoint.clone();
        url.query_pairs_mut()
            .append_pair("client_id", &self.configuration.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", GMAIL_READONLY_SCOPE)
            .append_pair("access_type", "offline")
            .append_pair("prompt", "consent")
            .append_pair("code_challenge", request.pkce_challenge())
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", request.state());
        Ok(url.into())
    }

    /// Exchanges one validated callback code with its matching PKCE verifier.
    pub async fn exchange_code(
        &self,
        authorization_code: &str,
        material: &ExchangeMaterial<'_>,
        redirect_uri: &str,
        now: crate::clock::Timestamp,
    ) -> Result<CredentialBundle, GoogleAuthorizationError> {
        let response = self
            .http
            .post(self.configuration.token_endpoint.clone())
            .timeout(AUTHORIZATION_REQUEST_TIMEOUT)
            .form(&[
                ("code", authorization_code),
                ("client_id", self.configuration.client_id.as_str()),
                ("redirect_uri", redirect_uri),
                ("grant_type", "authorization_code"),
                ("code_verifier", material.pkce_verifier()),
            ])
            .send()
            .await
            .map_err(|_| GoogleAuthorizationError::Offline)?;
        let mut token: TokenResponse = decode_response(response, TokenOperation::Exchange).await?;
        if token.token_type != "Bearer" {
            return Err(GoogleAuthorizationError::MalformedResponse);
        }
        let refresh_token = token
            .refresh_token
            .take()
            .ok_or(GoogleAuthorizationError::MalformedResponse)?;
        let expires_at = expires_at(now, token.expires_in)?;
        let mailbox_identity = self.fetch_mailbox_identity(&token.access_token).await?;
        CredentialBundle::new(
            std::mem::take(&mut token.access_token),
            refresh_token,
            expires_at,
            mailbox_identity,
        )
        .map_err(|_| GoogleAuthorizationError::MalformedResponse)
    }

    /// Refreshes an access credential while preserving refresh and identity data.
    pub async fn refresh_access(
        &self,
        existing: &CredentialBundle,
        now: crate::clock::Timestamp,
    ) -> Result<CredentialBundle, GoogleAuthorizationError> {
        let response = self
            .http
            .post(self.configuration.token_endpoint.clone())
            .timeout(AUTHORIZATION_REQUEST_TIMEOUT)
            .form(&[
                ("refresh_token", existing.refresh_token()),
                ("client_id", self.configuration.client_id.as_str()),
                ("grant_type", "refresh_token"),
            ])
            .send()
            .await
            .map_err(|_| GoogleAuthorizationError::Offline)?;
        let mut token: TokenResponse = decode_response(response, TokenOperation::Refresh).await?;
        if token.token_type != "Bearer" {
            return Err(GoogleAuthorizationError::MalformedResponse);
        }
        let expires_at = expires_at(now, token.expires_in)?;
        CredentialBundle::new(
            std::mem::take(&mut token.access_token),
            existing.refresh_token().to_owned(),
            expires_at,
            existing.mailbox_identity().to_owned(),
        )
        .map_err(|_| GoogleAuthorizationError::MalformedResponse)
    }

    async fn fetch_mailbox_identity(
        &self,
        access_token: &str,
    ) -> Result<String, GoogleAuthorizationError> {
        let response = self
            .http
            .get(self.configuration.profile_endpoint.clone())
            .timeout(AUTHORIZATION_REQUEST_TIMEOUT)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|_| GoogleAuthorizationError::Offline)?;
        let mut profile: ProfileResponse =
            decode_response(response, TokenOperation::Exchange).await?;
        if profile.email_address.trim().is_empty() {
            return Err(GoogleAuthorizationError::MalformedResponse);
        }
        Ok(std::mem::take(&mut profile.email_address))
    }
}

#[derive(Deserialize, Zeroize)]
#[zeroize(drop)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: u64,
    token_type: String,
}

#[derive(Deserialize, Zeroize)]
#[zeroize(drop)]
struct ProfileResponse {
    #[serde(rename = "emailAddress")]
    email_address: String,
}

#[derive(Clone, Copy)]
enum TokenOperation {
    Exchange,
    Refresh,
}

async fn decode_response<T: DeserializeOwned>(
    response: reqwest::Response,
    operation: TokenOperation,
) -> Result<T, GoogleAuthorizationError> {
    if !response.status().is_success() {
        return Err(map_status(response.status(), operation));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_AUTHORIZATION_RESPONSE_BYTES as u64)
    {
        return Err(GoogleAuthorizationError::MalformedResponse);
    }
    let mut response = response;
    let mut bytes = Zeroizing::new(Vec::with_capacity(1024));
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| GoogleAuthorizationError::Offline)?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_AUTHORIZATION_RESPONSE_BYTES {
            return Err(GoogleAuthorizationError::MalformedResponse);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| GoogleAuthorizationError::MalformedResponse)
}

fn map_status(status: reqwest::StatusCode, operation: TokenOperation) -> GoogleAuthorizationError {
    match status.as_u16() {
        400 | 401 => match operation {
            TokenOperation::Exchange => GoogleAuthorizationError::AuthorizationRejected,
            TokenOperation::Refresh => GoogleAuthorizationError::RefreshRequired,
        },
        403 => GoogleAuthorizationError::PermissionDenied,
        429 => GoogleAuthorizationError::RateLimited,
        500..=599 => GoogleAuthorizationError::ProviderUnavailable,
        _ => GoogleAuthorizationError::AuthorizationRejected,
    }
}

fn expires_at(
    now: crate::clock::Timestamp,
    expires_in_seconds: u64,
) -> Result<crate::clock::Timestamp, GoogleAuthorizationError> {
    if expires_in_seconds == 0 {
        return Err(GoogleAuthorizationError::MalformedResponse);
    }
    now.checked_add(Duration::from_secs(expires_in_seconds))
        .ok_or(GoogleAuthorizationError::MalformedResponse)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, time::Duration};

    use crate::{
        authorization::{
            core::{AuthorizationCore, AuthorizationStatus, CallbackOutcome},
            credentials::CredentialRepository,
            loopback::{LoopbackCallbackListener, LoopbackCancellation},
        },
        clock::Timestamp,
        domain::error::ErrorEnvelope,
        ports::{RandomSource, SecretStore},
    };
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
    };

    use super::{GoogleAuthorization, GoogleConfiguration, GMAIL_READONLY_SCOPE};

    struct FixedRandom;

    impl RandomSource for FixedRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), ErrorEnvelope> {
            destination.fill(11);
            Ok(())
        }
    }

    #[derive(Default)]
    struct MemorySecretStore(BTreeMap<String, Vec<u8>>);

    impl SecretStore for MemorySecretStore {
        fn read_secret(&self, key: &str) -> Result<Option<Vec<u8>>, ErrorEnvelope> {
            Ok(self.0.get(key).cloned())
        }

        fn write_secret(&mut self, key: &str, value: &[u8]) -> Result<(), ErrorEnvelope> {
            self.0.insert(key.to_owned(), value.to_vec());
            Ok(())
        }

        fn delete_secret(&mut self, key: &str) -> Result<(), ErrorEnvelope> {
            self.0.remove(key);
            Ok(())
        }
    }

    async fn fake_provider(
        responses: Vec<(u16, &'static str)>,
    ) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1024];
                loop {
                    let count = stream.read(&mut buffer).await.unwrap();
                    request.extend_from_slice(&buffer[..count]);
                    let header_end = request
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .map(|index| index + 4);
                    let Some(header_end) = header_end else {
                        continue;
                    };
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .and_then(|value| value.parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if request.len() >= header_end + content_length {
                        break;
                    }
                }
                requests.push(String::from_utf8(request).unwrap());
                let reason = match status {
                    200 => "OK",
                    400 => "Bad Request",
                    401 => "Unauthorized",
                    403 => "Forbidden",
                    429 => "Too Many Requests",
                    _ => "Service Unavailable",
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
            requests
        });
        (base, task)
    }

    #[test]
    fn authorization_url_is_public_client_pkce_and_read_only() {
        let mut core = AuthorizationCore::new(Duration::from_secs(30));
        let request = core.prepare(&mut FixedRandom).unwrap();
        let adapter = GoogleAuthorization::new(
            GoogleConfiguration::for_test(
                "desktop-client.apps.googleusercontent.com",
                "https://provider.test/authorize",
                "https://provider.test/token",
                "https://provider.test/profile",
            )
            .unwrap(),
        );

        let url = adapter
            .authorization_url(&request, "http://127.0.0.1:49152/oauth/callback")
            .unwrap();
        let url = reqwest::Url::parse(&url).unwrap();
        let query = url
            .query_pairs()
            .collect::<std::collections::BTreeMap<_, _>>();

        assert_eq!(
            url.as_str().split('?').next(),
            Some("https://provider.test/authorize")
        );
        assert_eq!(
            query.get("client_id").map(|value| value.as_ref()),
            Some("desktop-client.apps.googleusercontent.com")
        );
        assert_eq!(
            query.get("redirect_uri").map(|value| value.as_ref()),
            Some("http://127.0.0.1:49152/oauth/callback")
        );
        assert_eq!(
            query.get("scope").map(|value| value.as_ref()),
            Some(GMAIL_READONLY_SCOPE)
        );
        assert_eq!(
            query.get("response_type").map(|value| value.as_ref()),
            Some("code")
        );
        assert_eq!(
            query
                .get("code_challenge_method")
                .map(|value| value.as_ref()),
            Some("S256")
        );
        assert_eq!(
            query.get("code_challenge").map(|value| value.as_ref()),
            Some(request.pkce_challenge())
        );
        assert_eq!(
            query.get("state").map(|value| value.as_ref()),
            Some(request.state())
        );
        assert_eq!(
            query.get("access_type").map(|value| value.as_ref()),
            Some("offline")
        );
        assert_eq!(
            query.get("prompt").map(|value| value.as_ref()),
            Some("consent")
        );
        assert!(!query.contains_key("client_secret"));
    }

    #[tokio::test]
    async fn exchange_uses_pkce_fetches_mailbox_identity_and_has_no_client_secret() {
        let (base, provider) = fake_provider(vec![
            (
                200,
                r#"{"access_token":"access-secret","refresh_token":"refresh-secret","expires_in":3600,"token_type":"Bearer"}"#,
            ),
            (200, r#"{"emailAddress":"person@example.com"}"#),
        ])
        .await;
        let adapter = GoogleAuthorization::new(
            GoogleConfiguration::for_test(
                "desktop-client",
                &format!("{base}/authorize"),
                &format!("{base}/token"),
                &format!("{base}/profile"),
            )
            .unwrap(),
        );
        let mut core = AuthorizationCore::new(Duration::from_secs(30));
        let request = core.prepare(&mut FixedRandom).unwrap();
        assert!(core.await_callback(request.attempt_id(), Timestamp::from_unix_millis(1_000)));
        assert_eq!(
            core.receive_callback(
                request.attempt_id(),
                request.state(),
                Timestamp::from_unix_millis(2_000),
            ),
            crate::authorization::core::CallbackOutcome::ExchangeReady
        );
        let material = core.exchange_material(request.attempt_id()).unwrap();

        let credentials = adapter
            .exchange_code(
                "authorization-secret",
                &material,
                "http://127.0.0.1:49152/oauth/callback",
                Timestamp::from_unix_millis(2_000),
            )
            .await
            .unwrap();

        assert_eq!(credentials.access_token(), "access-secret");
        assert_eq!(credentials.refresh_token(), "refresh-secret");
        assert_eq!(
            credentials.expires_at(),
            Timestamp::from_unix_millis(3_602_000)
        );
        assert_eq!(credentials.mailbox_identity(), "person@example.com");
        let requests = provider.await.unwrap();
        assert!(requests[0].contains("code=authorization-secret"));
        assert!(requests[0].contains("code_verifier="));
        assert!(requests[0].contains("client_id=desktop-client"));
        assert!(!requests[0].contains("client_secret"));
        assert!(requests[1]
            .to_ascii_lowercase()
            .contains("authorization: bearer access-secret"));
        assert!(!format!("{credentials:?}").contains("access-secret"));
        assert!(!format!("{credentials:?}").contains("person@example.com"));
    }

    #[tokio::test]
    async fn refresh_preserves_identity_and_maps_expired_refresh_credentials() {
        let original = crate::authorization::credentials::CredentialBundle::new(
            "old-access".to_owned(),
            "refresh-secret".to_owned(),
            Timestamp::from_unix_millis(2_000),
            "person@example.com".to_owned(),
        )
        .unwrap();
        let (base, provider) = fake_provider(vec![(
            200,
            r#"{"access_token":"fresh-access","expires_in":1800,"token_type":"Bearer"}"#,
        )])
        .await;
        let adapter = GoogleAuthorization::new(
            GoogleConfiguration::for_test(
                "desktop-client",
                &format!("{base}/authorize"),
                &format!("{base}/token"),
                &format!("{base}/profile"),
            )
            .unwrap(),
        );

        let refreshed = adapter
            .refresh_access(&original, Timestamp::from_unix_millis(5_000))
            .await
            .unwrap();
        assert_eq!(refreshed.access_token(), "fresh-access");
        assert_eq!(refreshed.refresh_token(), "refresh-secret");
        assert_eq!(refreshed.mailbox_identity(), "person@example.com");
        assert_eq!(
            refreshed.expires_at(),
            Timestamp::from_unix_millis(1_805_000)
        );
        let requests = provider.await.unwrap();
        assert!(requests[0].contains("refresh_token=refresh-secret"));
        assert!(!requests[0].contains("client_secret"));

        let (base, provider) = fake_provider(vec![(400, r#"{"error":"invalid_grant"}"#)]).await;
        let adapter = GoogleAuthorization::new(
            GoogleConfiguration::for_test(
                "desktop-client",
                &format!("{base}/authorize"),
                &format!("{base}/token"),
                &format!("{base}/profile"),
            )
            .unwrap(),
        );
        assert!(matches!(
            adapter
                .refresh_access(&original, Timestamp::from_unix_millis(5_000))
                .await,
            Err(super::GoogleAuthorizationError::RefreshRequired)
        ));
        provider.await.unwrap();
    }

    #[tokio::test]
    async fn exchange_failures_have_stable_typed_mappings() {
        for (status, body, expected) in [
            (
                401,
                r#"{"error":"invalid_grant"}"#,
                super::GoogleAuthorizationError::AuthorizationRejected,
            ),
            (
                403,
                r#"{"error":"insufficient_scope"}"#,
                super::GoogleAuthorizationError::PermissionDenied,
            ),
            (
                429,
                r#"{"error":"slow_down"}"#,
                super::GoogleAuthorizationError::RateLimited,
            ),
            (
                503,
                r#"{"error":"unavailable"}"#,
                super::GoogleAuthorizationError::ProviderUnavailable,
            ),
            (
                200,
                r#"{"access_token":"truncated"}"#,
                super::GoogleAuthorizationError::MalformedResponse,
            ),
        ] {
            let (base, provider) = fake_provider(vec![(status, body)]).await;
            let adapter = GoogleAuthorization::new(
                GoogleConfiguration::for_test(
                    "desktop-client",
                    &format!("{base}/authorize"),
                    &format!("{base}/token"),
                    &format!("{base}/profile"),
                )
                .unwrap(),
            );
            let mut core = AuthorizationCore::new(Duration::from_secs(30));
            let request = core.prepare(&mut FixedRandom).unwrap();
            assert!(core.await_callback(request.attempt_id(), Timestamp::from_unix_millis(1_000)));
            assert_eq!(
                core.receive_callback(
                    request.attempt_id(),
                    request.state(),
                    Timestamp::from_unix_millis(2_000),
                ),
                CallbackOutcome::ExchangeReady
            );
            let material = core.exchange_material(request.attempt_id()).unwrap();

            assert!(matches!(
                adapter
                    .exchange_code(
                        "authorization-secret",
                        &material,
                        "http://127.0.0.1:49152/oauth/callback",
                        Timestamp::from_unix_millis(2_000),
                    )
                    .await,
                Err(error) if error == expected
            ));
            provider.await.unwrap();
        }
    }

    #[tokio::test]
    async fn fake_provider_journey_connects_disconnects_and_starts_cleanly_again() {
        let (base, provider) = fake_provider(vec![
            (
                200,
                r#"{"access_token":"access-secret","refresh_token":"refresh-secret","expires_in":3600,"token_type":"Bearer"}"#,
            ),
            (200, r#"{"emailAddress":"person@example.com"}"#),
        ])
        .await;
        let adapter = GoogleAuthorization::new(
            GoogleConfiguration::for_test(
                "desktop-client",
                &format!("{base}/authorize"),
                &format!("{base}/token"),
                &format!("{base}/profile"),
            )
            .unwrap(),
        );
        let mut repository = CredentialRepository::new(MemorySecretStore::default());
        let mut core = AuthorizationCore::new(Duration::from_secs(30));
        assert!(repository.restore().unwrap().is_none());
        assert!(core.restore_disconnected());

        let request = core.prepare(&mut FixedRandom).unwrap();
        let listener = LoopbackCallbackListener::bind(request.attempt_id())
            .await
            .unwrap();
        let address = listener.local_addr();
        let redirect_uri = listener.redirect_uri();
        let authorization_url = adapter.authorization_url(&request, &redirect_uri).unwrap();
        assert!(authorization_url.contains("code_challenge="));
        assert!(core.await_callback(request.attempt_id(), Timestamp::from_unix_millis(1_000)));
        let receiver = tokio::spawn(listener.receive_until(
            tokio::time::Instant::now() + Duration::from_secs(5),
            LoopbackCancellation::new(),
        ));
        let mut browser = tokio::net::TcpStream::connect(address).await.unwrap();
        let callback_request = format!(
            "GET /oauth/callback?code=authorization-secret&state={} HTTP/1.1\r\nHost: {address}\r\n\r\n",
            request.state()
        );
        browser
            .write_all(callback_request.as_bytes())
            .await
            .unwrap();
        let mut browser_response = String::new();
        browser.read_to_string(&mut browser_response).await.unwrap();
        assert!(browser_response.starts_with("HTTP/1.1 200"));
        let callback = receiver.await.unwrap().unwrap();
        assert_eq!(
            core.receive_callback(
                callback.attempt_id(),
                callback.state(),
                Timestamp::from_unix_millis(2_000),
            ),
            CallbackOutcome::ExchangeReady
        );
        let material = core.exchange_material(callback.attempt_id()).unwrap();
        let credentials = adapter
            .exchange_code(
                callback.authorization_code().unwrap(),
                &material,
                &redirect_uri,
                Timestamp::from_unix_millis(2_000),
            )
            .await
            .unwrap();
        repository.persist(&credentials).unwrap();
        assert!(core.exchange_succeeded(callback.attempt_id()));
        assert_eq!(core.status(), AuthorizationStatus::Connected);
        assert_eq!(
            repository.restore().unwrap().unwrap().mailbox_identity(),
            "person@example.com"
        );

        core.disconnect();
        repository.disconnect().unwrap();
        assert_eq!(core.status(), AuthorizationStatus::Disconnected);
        assert!(repository.restore().unwrap().is_none());
        let replacement = core.prepare(&mut FixedRandom).unwrap();
        let replacement_listener = LoopbackCallbackListener::bind(replacement.attempt_id())
            .await
            .unwrap();
        assert_ne!(replacement.attempt_id(), request.attempt_id());
        assert!(adapter
            .authorization_url(&replacement, &replacement_listener.redirect_uri())
            .unwrap()
            .contains("prompt=consent"));
        provider.await.unwrap();
    }
}
