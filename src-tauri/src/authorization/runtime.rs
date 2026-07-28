//! Cancellable production Authorization lifecycle owner.

use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime},
};

use serde::Serialize;
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
    time::Instant,
};
use zeroize::Zeroizing;

use crate::{
    authorization::{
        core::{
            AuthorizationCore, AuthorizationFailure, AuthorizationRequest, AuthorizationStatus,
            CallbackOutcome, ExchangeMaterial,
        },
        credentials::{CredentialBundle, CredentialRepository},
        google::{GoogleAuthorization, GoogleAuthorizationError},
        loopback::{LoopbackCallbackKind, LoopbackCallbackListener},
    },
    clock::Timestamp,
    ports::{RandomSource, SecretStore},
};

/// Stable provider, browser, and callback failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationTransportError {
    ConfigurationMissing,
    Unavailable,
    RefreshRequired,
}

impl fmt::Display for AuthorizationTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ConfigurationMissing => "Google Authorization is not configured.",
            Self::Unavailable => "Google Authorization is temporarily unavailable.",
            Self::RefreshRequired => "Google Authorization must be renewed.",
        })
    }
}

impl std::error::Error for AuthorizationTransportError {}

/// Public-client provider boundary.
pub trait AuthorizationTransport: Send + Sync + 'static {
    /// Reports a build-time configuration state before any browser work.
    fn startup_status(&self) -> Option<AuthorizationStatus> {
        None
    }

    fn authorization_url(
        &self,
        request: &AuthorizationRequest,
        redirect_uri: &str,
    ) -> Result<String, AuthorizationTransportError>;

    fn exchange<'a>(
        &'a self,
        authorization_code: &'a str,
        material: ExchangeMaterial<'a>,
        redirect_uri: &'a str,
        now: Timestamp,
    ) -> Pin<
        Box<dyn Future<Output = Result<CredentialBundle, AuthorizationTransportError>> + Send + 'a>,
    >;

    /// Refreshes an expired access credential without exposing its refresh token.
    fn refresh<'a>(
        &'a self,
        _existing: &'a CredentialBundle,
        _now: Timestamp,
    ) -> Pin<
        Box<dyn Future<Output = Result<CredentialBundle, AuthorizationTransportError>> + Send + 'a>,
    > {
        Box::pin(async { Err(AuthorizationTransportError::RefreshRequired) })
    }
}

/// User-browser launch boundary.
pub trait AuthorizationBrowser: Send + Sync + 'static {
    fn open(&self, url: &str) -> Result<(), AuthorizationTransportError>;
}

/// Transport used when the build omitted the public Google client ID.
pub struct ConfigurationMissingTransport;

impl AuthorizationTransport for ConfigurationMissingTransport {
    fn startup_status(&self) -> Option<AuthorizationStatus> {
        Some(AuthorizationStatus::ConfigurationMissing)
    }

    fn authorization_url(
        &self,
        _request: &AuthorizationRequest,
        _redirect_uri: &str,
    ) -> Result<String, AuthorizationTransportError> {
        Err(AuthorizationTransportError::ConfigurationMissing)
    }

    fn exchange<'a>(
        &'a self,
        _authorization_code: &'a str,
        _material: ExchangeMaterial<'a>,
        _redirect_uri: &'a str,
        _now: Timestamp,
    ) -> Pin<
        Box<dyn Future<Output = Result<CredentialBundle, AuthorizationTransportError>> + Send + 'a>,
    > {
        Box::pin(async { Err(AuthorizationTransportError::ConfigurationMissing) })
    }
}

impl AuthorizationTransport for GoogleAuthorization {
    fn authorization_url(
        &self,
        request: &AuthorizationRequest,
        redirect_uri: &str,
    ) -> Result<String, AuthorizationTransportError> {
        GoogleAuthorization::authorization_url(self, request, redirect_uri)
            .map_err(map_google_error)
    }

    fn exchange<'a>(
        &'a self,
        authorization_code: &'a str,
        material: ExchangeMaterial<'a>,
        redirect_uri: &'a str,
        now: Timestamp,
    ) -> Pin<
        Box<dyn Future<Output = Result<CredentialBundle, AuthorizationTransportError>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.exchange_code(authorization_code, &material, redirect_uri, now)
                .await
                .map_err(map_google_error)
        })
    }

    fn refresh<'a>(
        &'a self,
        existing: &'a CredentialBundle,
        now: Timestamp,
    ) -> Pin<
        Box<dyn Future<Output = Result<CredentialBundle, AuthorizationTransportError>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.refresh_access(existing, now)
                .await
                .map_err(map_google_error)
        })
    }
}

fn map_google_error(error: GoogleAuthorizationError) -> AuthorizationTransportError {
    match error {
        GoogleAuthorizationError::ConfigurationMissing => {
            AuthorizationTransportError::ConfigurationMissing
        }
        GoogleAuthorizationError::RefreshRequired => AuthorizationTransportError::RefreshRequired,
        GoogleAuthorizationError::Offline
        | GoogleAuthorizationError::AuthorizationRejected
        | GoogleAuthorizationError::PermissionDenied
        | GoogleAuthorizationError::RateLimited
        | GoogleAuthorizationError::ProviderUnavailable
        | GoogleAuthorizationError::MalformedResponse => AuthorizationTransportError::Unavailable,
    }
}

/// Short-lived credential view for one authenticated mailbox request.
///
/// It deliberately omits the refresh token and redacts all sensitive fields
/// from formatting. The Authorization owner remains the only refresh-token
/// owner.
pub struct AuthorizedCredential {
    access_token: Zeroizing<String>,
    expires_at: Timestamp,
    mailbox_identity: Zeroizing<String>,
}

impl AuthorizedCredential {
    /// Returns the bearer credential for an authenticated provider request.
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// Returns the verified mailbox identity associated with the credential.
    pub fn mailbox_identity(&self) -> &str {
        &self.mailbox_identity
    }

    /// Returns the access credential expiry.
    pub const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }
}

impl fmt::Debug for AuthorizedCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedCredential")
            .field("access_token", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .field("mailbox_identity", &"[redacted]")
            .finish()
    }
}

/// Cloneable command and status handle for the single Authorization owner.
#[derive(Clone)]
pub struct AuthorizationHandle {
    status: watch::Receiver<AuthorizationStatus>,
    commands: mpsc::Sender<AuthorizationCommand>,
}

impl AuthorizationHandle {
    /// Returns the latest safe public state without waiting.
    pub fn status(&self) -> AuthorizationStatus {
        *self.status.borrow()
    }

    /// Waits only for startup Keychain restoration to leave its unknown state.
    pub async fn wait_until_restored(&self) -> AuthorizationStatus {
        let mut status = self.status.clone();
        loop {
            let current = *status.borrow_and_update();
            if current != AuthorizationStatus::UnknownRestoring {
                return current;
            }
            if status.changed().await.is_err() {
                return *status.borrow();
            }
        }
    }

    /// Subscribes to safe status changes for Desktop Session publication.
    pub fn subscribe(&self) -> watch::Receiver<AuthorizationStatus> {
        self.status.clone()
    }

    /// Starts or replaces one Authorization attempt.
    pub async fn begin(&self) -> Result<AuthorizationStatus, AuthorizationTransportError> {
        self.send(|reply| AuthorizationCommand::Begin { reply })
            .await
    }

    /// Cancels browser/callback/token work and publishes cancellation promptly.
    pub async fn cancel(&self) -> Result<AuthorizationStatus, AuthorizationTransportError> {
        self.send(|reply| AuthorizationCommand::Cancel { reply })
            .await
    }

    /// Deletes credentials before atomically publishing disconnected.
    pub async fn disconnect(&self) -> Result<AuthorizationStatus, AuthorizationTransportError> {
        self.send(|reply| AuthorizationCommand::Disconnect { reply })
            .await
    }

    /// Obtains an unexpired request credential, refreshing and persisting first
    /// when required.
    pub async fn authorized_credential(
        &self,
    ) -> Result<AuthorizedCredential, AuthorizationTransportError> {
        let (reply, receiver) = oneshot::channel();
        self.commands
            .send(AuthorizationCommand::Credential { reply })
            .await
            .map_err(|_| AuthorizationTransportError::Unavailable)?;
        receiver
            .await
            .map_err(|_| AuthorizationTransportError::Unavailable)?
    }

    async fn send(
        &self,
        command: impl FnOnce(
            oneshot::Sender<Result<AuthorizationStatus, AuthorizationTransportError>>,
        ) -> AuthorizationCommand,
    ) -> Result<AuthorizationStatus, AuthorizationTransportError> {
        let (reply, receiver) = oneshot::channel();
        self.commands
            .send(command(reply))
            .await
            .map_err(|_| AuthorizationTransportError::Unavailable)?;
        receiver
            .await
            .map_err(|_| AuthorizationTransportError::Unavailable)?
    }
}

enum AuthorizationCommand {
    Begin {
        reply: oneshot::Sender<Result<AuthorizationStatus, AuthorizationTransportError>>,
    },
    Cancel {
        reply: oneshot::Sender<Result<AuthorizationStatus, AuthorizationTransportError>>,
    },
    Disconnect {
        reply: oneshot::Sender<Result<AuthorizationStatus, AuthorizationTransportError>>,
    },
    Credential {
        reply: oneshot::Sender<Result<AuthorizedCredential, AuthorizationTransportError>>,
    },
}

enum AttemptEvent {
    Status {
        generation: u64,
        status: AuthorizationStatus,
    },
    Finished {
        generation: u64,
        status: AuthorizationStatus,
        credentials: Option<CredentialBundle>,
    },
}

struct ActiveAttempt {
    generation: u64,
    task: JoinHandle<()>,
}

enum RefreshEvent {
    Finished {
        generation: u64,
        previous: CredentialBundle,
        result: Result<CredentialBundle, AuthorizationTransportError>,
    },
}

struct ActiveRefresh {
    generation: u64,
    task: JoinHandle<()>,
}

/// Starts the single Authorization owner and restores Keychain state first.
pub fn spawn_authorization<S, T, B, R>(
    mut repository: CredentialRepository<S>,
    transport: Arc<T>,
    browser: Arc<B>,
    random: R,
) -> AuthorizationHandle
where
    S: SecretStore + Send + 'static,
    T: AuthorizationTransport,
    B: AuthorizationBrowser,
    R: RandomSource + Send + 'static,
{
    let (status_sender, status) = watch::channel(AuthorizationStatus::UnknownRestoring);
    let (commands, mut command_receiver) = mpsc::channel(16);
    let (attempt_sender, mut attempt_receiver) = mpsc::unbounded_channel();
    let (refresh_sender, mut refresh_receiver) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut random = random;
        let mut generation = 0_u64;
        let mut active: Option<ActiveAttempt> = None;
        let mut refresh_generation = 0_u64;
        let mut active_refresh: Option<ActiveRefresh> = None;
        let mut pending_credentials = Vec::new();
        let mut credentials = None;

        if let Some(configuration_status) = transport.startup_status() {
            let _ = status_sender.send(configuration_status);
        } else {
            match repository.restore() {
                Ok(Some(restored)) if restored.expires_at() <= now() => {
                    refresh_generation = 1;
                    active_refresh = Some(spawn_refresh(
                        refresh_generation,
                        restored,
                        transport.clone(),
                        refresh_sender.clone(),
                    ));
                }
                Ok(Some(restored)) => {
                    credentials = Some(restored);
                    let _ = status_sender.send(AuthorizationStatus::Connected);
                }
                Ok(None) => {
                    let _ = status_sender.send(AuthorizationStatus::Disconnected);
                }
                Err(error) => {
                    let _ = status_sender
                        .send(error.authorization_failure().public_status_for_runtime());
                }
            }
        }

        loop {
            tokio::select! {
                Some(command) = command_receiver.recv() => {
                    match command {
                        AuthorizationCommand::Begin { reply } => {
                            abort_active(&mut active);
                            abort_refresh(&mut active_refresh, &mut pending_credentials);
                            generation = generation.wrapping_add(1).max(1);
                            let mut core = AuthorizationCore::default();
                            let _ = core.restore_disconnected();
                            let request = match core.prepare(&mut random) {
                                Ok(request) => request,
                                Err(_) => {
                                    let status = AuthorizationStatus::Failed;
                                    let _ = status_sender.send(status);
                                    let _ = reply.send(Err(AuthorizationTransportError::Unavailable));
                                    continue;
                                }
                            };
                            let current_generation = generation;
                            let events = attempt_sender.clone();
                            let transport = transport.clone();
                            let browser = browser.clone();
                            let _ = status_sender.send(AuthorizationStatus::Starting);
                            let task = tokio::spawn(async move {
                                run_attempt(
                                    current_generation,
                                    core,
                                    request,
                                    transport,
                                    browser,
                                    events,
                                )
                                .await;
                            });
                            active = Some(ActiveAttempt {
                                generation: current_generation,
                                task,
                            });
                            let _ = reply.send(Ok(AuthorizationStatus::Starting));
                        }
                        AuthorizationCommand::Cancel { reply } => {
                            let status = if active.is_some() || active_refresh.is_some() {
                                abort_active(&mut active);
                                abort_refresh(&mut active_refresh, &mut pending_credentials);
                                AuthorizationStatus::Cancelled
                            } else {
                                *status_sender.borrow()
                            };
                            let _ = status_sender.send(status);
                            let _ = reply.send(Ok(status));
                        }
                        AuthorizationCommand::Disconnect { reply } => {
                            abort_active(&mut active);
                            abort_refresh(&mut active_refresh, &mut pending_credentials);
                            match repository.disconnect() {
                                Ok(()) => {
                                    credentials = None;
                                    let status = AuthorizationStatus::Disconnected;
                                    let _ = status_sender.send(status);
                                    let _ = reply.send(Ok(status));
                                }
                                Err(_) => {
                                    let status = AuthorizationStatus::CredentialStoreUnavailable;
                                    let _ = status_sender.send(status);
                                    let _ = reply.send(Err(AuthorizationTransportError::Unavailable));
                                }
                            }
                        }
                        AuthorizationCommand::Credential { reply } => {
                            let is_current = credentials
                                .as_ref()
                                .is_some_and(|current| current.expires_at() > now());
                            if is_current {
                                let current = credentials
                                    .as_ref()
                                    .expect("current credential presence checked above");
                                let _ = reply.send(Ok(authorized_credential(current)));
                            } else if credentials.is_some() {
                                pending_credentials.push(reply);
                                if active_refresh.is_none() {
                                    let previous = credentials
                                        .take()
                                        .expect("credential presence checked above");
                                    refresh_generation = refresh_generation.wrapping_add(1).max(1);
                                    let _ = status_sender.send(AuthorizationStatus::UnknownRestoring);
                                    active_refresh = Some(spawn_refresh(
                                        refresh_generation,
                                        previous,
                                        transport.clone(),
                                        refresh_sender.clone(),
                                    ));
                                }
                            } else {
                                let error = if *status_sender.borrow() == AuthorizationStatus::RefreshRequired {
                                    AuthorizationTransportError::RefreshRequired
                                } else {
                                    AuthorizationTransportError::Unavailable
                                };
                                let _ = reply.send(Err(error));
                            }
                        }
                    }
                }
                Some(event) = attempt_receiver.recv() => {
                    match event {
                        AttemptEvent::Status { generation: event_generation, status }
                            if active.as_ref().is_some_and(|attempt| attempt.generation == event_generation) =>
                        {
                            let _ = status_sender.send(status);
                        }
                        AttemptEvent::Finished {
                            generation: event_generation,
                            status,
                            credentials: exchanged_credentials,
                        } if active.as_ref().is_some_and(|attempt| attempt.generation == event_generation) => {
                            active = None;
                            if let Some(exchanged_credentials) = exchanged_credentials {
                                match repository.persist(&exchanged_credentials) {
                                    Ok(()) => {
                                        credentials = Some(exchanged_credentials);
                                        let _ = status_sender.send(AuthorizationStatus::Connected);
                                    }
                                    Err(_) => {
                                        let _ = status_sender.send(
                                            AuthorizationStatus::CredentialStoreUnavailable,
                                        );
                                    }
                                }
                            } else {
                                let _ = status_sender.send(status);
                            }
                        }
                        _ => {}
                    }
                }
                Some(event) = refresh_receiver.recv() => {
                    match event {
                        RefreshEvent::Finished {
                            generation: event_generation,
                            previous,
                            result,
                        } if active_refresh.as_ref().is_some_and(|refresh| refresh.generation == event_generation) => {
                            active_refresh = None;
                            match result {
                                Ok(refreshed) => {
                                    match repository.persist(&refreshed) {
                                        Ok(()) => {
                                            for reply in pending_credentials.drain(..) {
                                                let _ = reply.send(Ok(authorized_credential(&refreshed)));
                                            }
                                            credentials = Some(refreshed);
                                            let _ = status_sender.send(AuthorizationStatus::Connected);
                                        }
                                        Err(_) => {
                                            credentials = Some(previous);
                                            fail_credential_requests(
                                                &mut pending_credentials,
                                                AuthorizationTransportError::Unavailable,
                                            );
                                            let _ = status_sender.send(
                                                AuthorizationStatus::CredentialStoreUnavailable,
                                            );
                                        }
                                    }
                                }
                                Err(error) => {
                                    credentials = Some(previous);
                                    fail_credential_requests(&mut pending_credentials, error);
                                    let _ = status_sender.send(error.status());
                                }
                            }
                        }
                        _ => {}
                    }
                }
                else => break,
            }
        }
        abort_active(&mut active);
        abort_refresh(&mut active_refresh, &mut pending_credentials);
    });
    AuthorizationHandle { status, commands }
}

fn authorized_credential(credentials: &CredentialBundle) -> AuthorizedCredential {
    AuthorizedCredential {
        access_token: Zeroizing::new(credentials.access_token().to_owned()),
        expires_at: credentials.expires_at(),
        mailbox_identity: Zeroizing::new(credentials.mailbox_identity().to_owned()),
    }
}

fn spawn_refresh<T: AuthorizationTransport>(
    generation: u64,
    previous: CredentialBundle,
    transport: Arc<T>,
    events: mpsc::UnboundedSender<RefreshEvent>,
) -> ActiveRefresh {
    let task = tokio::spawn(async move {
        let result = transport.refresh(&previous, now()).await;
        let _ = events.send(RefreshEvent::Finished {
            generation,
            previous,
            result,
        });
    });
    ActiveRefresh { generation, task }
}

fn fail_credential_requests(
    pending: &mut Vec<oneshot::Sender<Result<AuthorizedCredential, AuthorizationTransportError>>>,
    error: AuthorizationTransportError,
) {
    for reply in pending.drain(..) {
        let _ = reply.send(Err(error));
    }
}

fn abort_active(active: &mut Option<ActiveAttempt>) {
    if let Some(attempt) = active.take() {
        attempt.task.abort();
    }
}

fn abort_refresh(
    active: &mut Option<ActiveRefresh>,
    pending: &mut Vec<oneshot::Sender<Result<AuthorizedCredential, AuthorizationTransportError>>>,
) {
    if let Some(refresh) = active.take() {
        refresh.task.abort();
    }
    fail_credential_requests(pending, AuthorizationTransportError::Unavailable);
}

async fn run_attempt<T, B>(
    generation: u64,
    mut core: AuthorizationCore,
    request: AuthorizationRequest,
    transport: Arc<T>,
    browser: Arc<B>,
    events: mpsc::UnboundedSender<AttemptEvent>,
) where
    T: AuthorizationTransport,
    B: AuthorizationBrowser,
{
    let listener = match LoopbackCallbackListener::bind(request.attempt_id()).await {
        Ok(listener) => listener,
        Err(_) => {
            finish(&events, generation, AuthorizationStatus::Failed, None);
            return;
        }
    };
    let redirect_uri = listener.redirect_uri();
    let authorization_url = match transport.authorization_url(&request, &redirect_uri) {
        Ok(url) => url,
        Err(error) => {
            finish(&events, generation, error.status(), None);
            return;
        }
    };
    let callback_started_at = now();
    if !core.await_callback(request.attempt_id(), callback_started_at) {
        finish(&events, generation, AuthorizationStatus::Failed, None);
        return;
    }
    publish(&events, generation, AuthorizationStatus::AwaitingBrowser);
    if let Err(error) = browser.open(&authorization_url) {
        finish(&events, generation, error.status(), None);
        return;
    }

    let cancellation = super::loopback::LoopbackCancellation::new();
    let callback = match listener
        .receive_until(Instant::now() + Duration::from_secs(300), cancellation)
        .await
    {
        Ok(callback) => callback,
        Err(_) => {
            finish(&events, generation, AuthorizationStatus::Failed, None);
            return;
        }
    };

    match callback.kind() {
        LoopbackCallbackKind::Denied => {
            let _ = core.deny_callback(callback.attempt_id(), callback.state(), now());
            finish(&events, generation, core.status(), None);
        }
        LoopbackCallbackKind::ProviderError => {
            let _ = core.error_callback(callback.attempt_id(), callback.state(), now());
            finish(&events, generation, core.status(), None);
        }
        LoopbackCallbackKind::AuthorizationCode => {
            if core.receive_callback(callback.attempt_id(), callback.state(), now())
                != CallbackOutcome::ExchangeReady
            {
                finish(&events, generation, core.status(), None);
                return;
            }
            publish(&events, generation, AuthorizationStatus::Exchanging);
            let Some(material) = core.exchange_material(callback.attempt_id()) else {
                finish(&events, generation, AuthorizationStatus::Failed, None);
                return;
            };
            let exchanged = transport
                .exchange(
                    callback.authorization_code().unwrap_or_default(),
                    material,
                    &redirect_uri,
                    now(),
                )
                .await;
            match exchanged {
                Ok(credentials) => {
                    let _ = core.exchange_succeeded(callback.attempt_id());
                    finish(
                        &events,
                        generation,
                        AuthorizationStatus::Connected,
                        Some(credentials),
                    );
                }
                Err(error) => {
                    let _ = core.exchange_failed(callback.attempt_id(), error.failure());
                    finish(&events, generation, core.status(), None);
                }
            }
        }
    }
}

fn publish(
    events: &mpsc::UnboundedSender<AttemptEvent>,
    generation: u64,
    status: AuthorizationStatus,
) {
    let _ = events.send(AttemptEvent::Status { generation, status });
}

fn finish(
    events: &mpsc::UnboundedSender<AttemptEvent>,
    generation: u64,
    status: AuthorizationStatus,
    credentials: Option<CredentialBundle>,
) {
    let _ = events.send(AttemptEvent::Finished {
        generation,
        status,
        credentials,
    });
}

fn now() -> Timestamp {
    Timestamp::from_system_time(SystemTime::now())
}

impl AuthorizationTransportError {
    const fn status(self) -> AuthorizationStatus {
        match self {
            Self::ConfigurationMissing => AuthorizationStatus::ConfigurationMissing,
            Self::RefreshRequired => AuthorizationStatus::RefreshRequired,
            Self::Unavailable => AuthorizationStatus::Failed,
        }
    }

    const fn failure(self) -> AuthorizationFailure {
        match self {
            Self::ConfigurationMissing => AuthorizationFailure::ConfigurationMissing,
            Self::RefreshRequired => AuthorizationFailure::RefreshRequired,
            Self::Unavailable => AuthorizationFailure::ExchangeFailed,
        }
    }
}

trait RuntimeFailureStatus {
    fn public_status_for_runtime(self) -> AuthorizationStatus;
}

impl RuntimeFailureStatus for AuthorizationFailure {
    fn public_status_for_runtime(self) -> AuthorizationStatus {
        match self {
            Self::ConfigurationMissing => AuthorizationStatus::ConfigurationMissing,
            Self::CredentialStoreUnavailable => AuthorizationStatus::CredentialStoreUnavailable,
            Self::RefreshRequired => AuthorizationStatus::RefreshRequired,
            Self::CallbackInvalid => AuthorizationStatus::CallbackInvalid,
            Self::ExchangeFailed | Self::RandomUnavailable => AuthorizationStatus::Failed,
        }
    }
}
