//! Production mailbox monitoring owner and Authorization bridge.

use std::{fmt, sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use tokio::time::timeout;

use crate::{
    authorization::{
        core::AuthorizationStatus,
        runtime::{AuthorizationHandle, AuthorizationTransportError},
    },
    clock::{Clock, SystemClock, Timestamp},
    interpretation::{
        classifier::{classify, ClassificationInput, ProviderInference},
        mime::{normalize_message, MimeHeader, MimePart},
    },
    mailbox::gmail::{FetchCompleteness, GmailFetch, GmailMailbox},
    settings::AcceptancePolicySnapshot,
    state_store::{
        acceptance::{
            AcceptanceBarrierOutcome, AcceptanceOutcome, DetectedMessageAcceptance,
            EncryptedAcceptanceCommitPort, MessageAcceptance,
        },
        history::{HistoryEntry, HistoryEntryId, HistoryProvider, SourceMessageDigest},
        seen_messages::SeenMessageIdentity,
        StateKey, SystemRandom,
    },
};

use super::scheduler::{
    CheckCompleteness, CheckFuture, IntakeFailure, IntakeScheduler, IntakeTransport, JitterSource,
    MigrationReadiness, MonitoringHealth, SecureJitter,
};

const MONITORING_COMMAND_DEADLINE: Duration = Duration::from_millis(400);

/// Shared production acceptance owner used by the intake pipeline.
pub type SharedAcceptance =
    Arc<Mutex<MessageAcceptance<EncryptedAcceptanceCommitPort<SystemRandom>>>>;

/// Receives a Detected OTP only after its verified acceptance commit.
///
/// Implementations receive the durable History record; they must not perform
/// additional acceptance mutations from inside the notification.
pub trait AcceptedCodeSink: Send + Sync + 'static {
    /// Publishes one committed Detected OTP to the Desktop Session.
    fn code_accepted(&self, entry: &HistoryEntry);
}

/// Live Message-interpretation wiring for the production transport.
///
/// The pipeline is the only production path from fetched Messages to durable
/// History: MIME normalization, classification, idempotent acceptance, and
/// publication all run through it.
pub struct IntakePipeline {
    acceptance: SharedAcceptance,
    key: StateKey,
    policy: AcceptancePolicySnapshot,
    sink: Arc<dyn AcceptedCodeSink>,
}

impl IntakePipeline {
    /// Wires the acceptance owner, its key, the acceptance policy, and the
    /// publication sink into one interpretation boundary.
    pub fn new(
        acceptance: SharedAcceptance,
        key: StateKey,
        policy: AcceptancePolicySnapshot,
        sink: Arc<dyn AcceptedCodeSink>,
    ) -> Self {
        Self {
            acceptance,
            key,
            policy,
            sink,
        }
    }
}

/// Gmail check adapter that obtains an unexpired credential from the sole
/// Authorization owner for every request.
pub struct AuthorizedGmailTransport {
    authorization: AuthorizationHandle,
    mailbox: GmailMailbox,
    pipeline: Option<IntakePipeline>,
}

impl AuthorizedGmailTransport {
    pub fn new(authorization: AuthorizationHandle, mailbox: GmailMailbox) -> Self {
        Self {
            authorization,
            mailbox,
            pipeline: None,
        }
    }

    /// Attaches the live Message-interpretation pipeline to the transport.
    pub fn with_pipeline(mut self, pipeline: IntakePipeline) -> Self {
        self.pipeline = Some(pipeline);
        self
    }
}

impl IntakeTransport for AuthorizedGmailTransport {
    fn check(&mut self) -> CheckFuture<'_> {
        Box::pin(async move {
            let credential = self
                .authorization
                .authorized_credential()
                .await
                .map_err(map_authorization_error)?;
            let fetch = self
                .mailbox
                .fetch_unread_authorized(&credential)
                .await
                .map_err(IntakeFailure::from)?;
            if let Some(pipeline) = &self.pipeline {
                interpret_fetch(&fetch, credential.mailbox_identity(), pipeline).await;
            }
            Ok(match fetch.completeness() {
                FetchCompleteness::Complete => CheckCompleteness::Complete,
                FetchCompleteness::Partial { .. } => CheckCompleteness::Partial,
            })
        })
    }
}

/// Runs every fetched Message through the interpretation boundary. Failures
/// to interpret or accept one Message never fail the check itself.
async fn interpret_fetch(fetch: &GmailFetch, mailbox_identity: &str, pipeline: &IntakePipeline) {
    let now = SystemClock.now();
    for message in fetch.messages() {
        let Some((seen_identity, entry)) = interpret_message(
            message.json(),
            message.id(),
            &pipeline.key,
            mailbox_identity,
            now,
        ) else {
            continue;
        };
        let mut acceptance = pipeline.acceptance.lock().await;
        match acceptance.accept(
            DetectedMessageAcceptance::new(seen_identity, entry.clone()),
            &pipeline.policy,
            now,
        ) {
            AcceptanceOutcome::Committed(_) => pipeline.sink.code_accepted(&entry),
            AcceptanceOutcome::BarrierPending => {
                if matches!(
                    acceptance.retry_barrier(),
                    AcceptanceBarrierOutcome::Committed(_)
                ) {
                    pipeline.sink.code_accepted(&entry);
                }
            }
            AcceptanceOutcome::AlreadySeen
            | AcceptanceOutcome::Uncommitted
            | AcceptanceOutcome::RecoveryRequired(_)
            | AcceptanceOutcome::Blocked
            | AcceptanceOutcome::Rejected(_) => {}
        }
    }
}

/// Pure interpretation of one raw Gmail Message detail into an idempotent
/// acceptance request. Returns `None` when the Message carries no acceptable
/// Detected OTP.
fn interpret_message(
    json: &[u8],
    message_id: &str,
    key: &StateKey,
    mailbox_identity: &str,
    now: Timestamp,
) -> Option<(SeenMessageIdentity, HistoryEntry)> {
    let detail: MessageDetail = serde_json::from_slice(json).ok()?;
    let payload = detail.payload.into_mime_part();
    let subject = header_value(&payload, "subject");
    let origin = header_value(&payload, "from");
    if origin.trim().is_empty() {
        return None;
    }
    let normalized = normalize_message(&payload).ok()?;
    let detected = classify(ClassificationInput::new(&normalized, subject, origin)).ok()?;

    let seen_identity = SeenMessageIdentity::derive(key, mailbox_identity, message_id);
    let source = SourceMessageDigest::new(seen_identity.as_str()).ok()?;
    let id = HistoryEntryId::derive(key, &source);
    let (provider_key, provider_display) = match detected.provider() {
        ProviderInference::Known(display) => (normalized_provider_key(display), display.to_owned()),
        ProviderInference::Unknown => ("unknown".to_owned(), "Unknown".to_owned()),
    };
    let provider = HistoryProvider::new(provider_key, provider_display).ok()?;
    let received_at = detail
        .internal_date
        .parse::<i64>()
        .map(Timestamp::from_unix_millis)
        .unwrap_or(now);
    let entry = HistoryEntry::new(
        id,
        detected.code(),
        origin.trim(),
        provider,
        received_at,
        source,
    )
    .ok()?;
    Some((seen_identity, entry))
}

fn header_value<'a>(payload: &'a MimePart, name: &str) -> &'a str {
    payload
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map_or("", |header| header.value.as_str())
}

fn normalized_provider_key(display: &str) -> String {
    display
        .chars()
        .flat_map(char::to_lowercase)
        .filter(|character| character.is_ascii_alphanumeric())
        .collect()
}

/// Raw Gmail Message detail envelope; content is dropped after interpretation.
#[derive(Deserialize)]
struct MessageDetail {
    #[serde(rename = "internalDate", default)]
    internal_date: String,
    payload: GmailMimePart,
}

/// Gmail's MIME tree shape, converted into the interpretation boundary's
/// transport-decoded [`MimePart`].
#[derive(Deserialize)]
struct GmailMimePart {
    #[serde(rename = "mimeType")]
    mime_type: String,
    #[serde(default)]
    headers: Vec<MimeHeader>,
    #[serde(default)]
    body: Option<GmailBody>,
    #[serde(default)]
    filename: String,
    #[serde(default)]
    parts: Vec<GmailMimePart>,
}

#[derive(Deserialize)]
struct GmailBody {
    #[serde(default)]
    data: Option<String>,
}

impl GmailMimePart {
    fn into_mime_part(self) -> MimePart {
        MimePart {
            mime_type: self.mime_type,
            headers: self.headers,
            body_data: self.body.and_then(|body| body.data),
            filename: self.filename,
            parts: self
                .parts
                .into_iter()
                .map(GmailMimePart::into_mime_part)
                .collect(),
        }
    }
}

fn map_authorization_error(error: AuthorizationTransportError) -> IntakeFailure {
    match error {
        AuthorizationTransportError::RefreshRequired => IntakeFailure::AuthorizationRequired,
        AuthorizationTransportError::ConfigurationMissing
        | AuthorizationTransportError::Unavailable => IntakeFailure::Unavailable,
    }
}

/// Cloneable command and health handle for the single monitoring owner.
#[derive(Clone)]
pub struct MonitoringHandle {
    health: watch::Receiver<MonitoringHealth>,
    commands: mpsc::Sender<MonitoringCommand>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitoringRuntimeError {
    Unavailable,
}

impl fmt::Display for MonitoringRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Mailbox monitoring is temporarily unavailable.")
    }
}

impl std::error::Error for MonitoringRuntimeError {}

impl MonitoringHandle {
    pub fn health(&self) -> MonitoringHealth {
        *self.health.borrow()
    }

    pub fn subscribe(&self) -> watch::Receiver<MonitoringHealth> {
        self.health.clone()
    }

    pub async fn start(&self) -> Result<MonitoringHealth, MonitoringRuntimeError> {
        self.send(|reply| MonitoringCommand::Start { reply }).await
    }

    pub async fn stop(&self) -> Result<MonitoringHealth, MonitoringRuntimeError> {
        self.send(|reply| MonitoringCommand::Stop { reply }).await
    }

    pub async fn check_now(&self) -> Result<MonitoringHealth, MonitoringRuntimeError> {
        self.send(|reply| MonitoringCommand::CheckNow { reply })
            .await
    }

    /// Task 20 drives this explicit gate after durable startup activation.
    pub async fn set_migration_readiness(
        &self,
        readiness: MigrationReadiness,
    ) -> Result<MonitoringHealth, MonitoringRuntimeError> {
        self.send(move |reply| MonitoringCommand::Migration { readiness, reply })
            .await
    }

    pub async fn shutdown(&self) -> Result<MonitoringHealth, MonitoringRuntimeError> {
        self.send(|reply| MonitoringCommand::Shutdown { reply })
            .await
    }

    async fn send(
        &self,
        command: impl FnOnce(oneshot::Sender<MonitoringHealth>) -> MonitoringCommand,
    ) -> Result<MonitoringHealth, MonitoringRuntimeError> {
        let (reply, receiver) = oneshot::channel();
        timeout(MONITORING_COMMAND_DEADLINE, async {
            self.commands
                .send(command(reply))
                .await
                .map_err(|_| MonitoringRuntimeError::Unavailable)?;
            receiver
                .await
                .map_err(|_| MonitoringRuntimeError::Unavailable)
        })
        .await
        .map_err(|_| MonitoringRuntimeError::Unavailable)?
    }
}

enum MonitoringCommand {
    Start {
        reply: oneshot::Sender<MonitoringHealth>,
    },
    Stop {
        reply: oneshot::Sender<MonitoringHealth>,
    },
    CheckNow {
        reply: oneshot::Sender<MonitoringHealth>,
    },
    Migration {
        readiness: MigrationReadiness,
        reply: oneshot::Sender<MonitoringHealth>,
    },
    Shutdown {
        reply: oneshot::Sender<MonitoringHealth>,
    },
}

/// Starts a safely stopped owner. Task 20 must explicitly publish migration
/// readiness before connected Authorization can start transport work.
pub fn spawn_monitoring<T, C, J>(
    scheduler: IntakeScheduler<T, C, J>,
    authorization: watch::Receiver<AuthorizationStatus>,
) -> MonitoringHandle
where
    T: IntakeTransport,
    C: Clock + 'static,
    J: JitterSource,
{
    let (health_sender, health) = watch::channel(scheduler.health());
    let (commands, command_receiver) = mpsc::channel(16);
    tokio::spawn(run_owner(
        scheduler,
        authorization,
        command_receiver,
        health_sender,
    ));
    MonitoringHandle { health, commands }
}

/// Builds the production Gmail-backed monitoring owner. The interpretation
/// pipeline is attached only after durable startup activation succeeded.
pub fn spawn_production_monitoring(
    authorization: AuthorizationHandle,
    pipeline: Option<IntakePipeline>,
) -> MonitoringHandle {
    let transport = AuthorizedGmailTransport::new(authorization.clone(), GmailMailbox::new());
    let transport = match pipeline {
        Some(pipeline) => transport.with_pipeline(pipeline),
        None => transport,
    };
    let scheduler = IntakeScheduler::new(transport, Arc::new(SystemClock), SecureJitter);
    spawn_monitoring(scheduler, authorization.subscribe())
}

async fn run_owner<T, C, J>(
    mut scheduler: IntakeScheduler<T, C, J>,
    mut authorization: watch::Receiver<AuthorizationStatus>,
    mut commands: mpsc::Receiver<MonitoringCommand>,
    health_sender: watch::Sender<MonitoringHealth>,
) where
    T: IntakeTransport,
    C: Clock + 'static,
    J: JitterSource,
{
    let mut scheduler_health = scheduler.subscribe_health();
    let mut readiness = MigrationReadiness::Pending;
    let mut desired = true;
    loop {
        tokio::select! {
            changed = authorization.changed() => {
                if changed.is_err() {
                    scheduler.shutdown().await;
                    break;
                }
                let authorization_status = *authorization.borrow_and_update();
                reconcile(&mut scheduler, readiness, authorization_status, desired).await;
                health_sender.send_replace(scheduler.health());
            }
            changed = scheduler_health.changed() => {
                if changed.is_ok() {
                    health_sender.send_replace(*scheduler_health.borrow_and_update());
                }
            }
            command = commands.recv() => {
                let Some(command) = command else {
                    scheduler.shutdown().await;
                    break;
                };
                match command {
                    MonitoringCommand::Start { reply } => {
                        desired = true;
                        let authorization_status = *authorization.borrow();
                        reconcile(&mut scheduler, readiness, authorization_status, desired).await;
                        let health = scheduler.health();
                        health_sender.send_replace(health);
                        let _ = reply.send(health);
                    }
                    MonitoringCommand::Stop { reply } => {
                        desired = false;
                        scheduler.shutdown().await;
                        let health = scheduler.health();
                        health_sender.send_replace(health);
                        let _ = reply.send(health);
                    }
                    MonitoringCommand::CheckNow { reply } => {
                        scheduler.check_now();
                        let _ = reply.send(scheduler.health());
                    }
                    MonitoringCommand::Migration { readiness: next, reply } => {
                        readiness = next;
                        let authorization_status = *authorization.borrow();
                        reconcile(&mut scheduler, readiness, authorization_status, desired).await;
                        let health = scheduler.health();
                        health_sender.send_replace(health);
                        let _ = reply.send(health);
                    }
                    MonitoringCommand::Shutdown { reply } => {
                        scheduler.shutdown().await;
                        let health = scheduler.health();
                        health_sender.send_replace(health);
                        let _ = reply.send(health);
                        break;
                    }
                }
            }
        }
    }
}

async fn reconcile<T, C, J>(
    scheduler: &mut IntakeScheduler<T, C, J>,
    readiness: MigrationReadiness,
    authorization: AuthorizationStatus,
    desired: bool,
) where
    T: IntakeTransport,
    C: Clock + 'static,
    J: JitterSource,
{
    if desired
        && readiness == MigrationReadiness::Ready
        && authorization == AuthorizationStatus::Connected
    {
        let _ = scheduler.start(readiness, authorization);
        return;
    }
    scheduler.disconnect().await;
    if authorization == AuthorizationStatus::RefreshRequired {
        scheduler.authorization_required();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use base64::Engine as _;

    use super::*;
    use crate::intake::scheduler::{CheckCompleteness, MonitoringHealthStatus};

    struct NoopTransport;

    impl IntakeTransport for NoopTransport {
        fn check(&mut self) -> CheckFuture<'_> {
            Box::pin(async { Ok(CheckCompleteness::Complete) })
        }
    }

    struct NoJitter;

    impl JitterSource for NoJitter {
        fn healthy_jitter_basis_points(&mut self) -> i32 {
            0
        }
    }

    fn test_handle(commands: mpsc::Sender<MonitoringCommand>) -> MonitoringHandle {
        let scheduler = IntakeScheduler::new(NoopTransport, Arc::new(SystemClock), NoJitter);
        let (_, health) = watch::channel(scheduler.health());
        MonitoringHandle { health, commands }
    }

    #[tokio::test]
    async fn saturated_command_queue_fails_within_the_aggregate_deadline() {
        let (commands, _receiver) = mpsc::channel(1);
        let (reply, _reply_receiver) = oneshot::channel();
        commands
            .try_send(MonitoringCommand::CheckNow { reply })
            .expect("fill the sole queue slot");
        let handle = test_handle(commands);
        let started = Instant::now();

        assert_eq!(
            handle.stop().await,
            Err(MonitoringRuntimeError::Unavailable)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(handle.health().status(), MonitoringHealthStatus::Stopped);
    }

    fn detail_json(body: &str, from: &str, subject: &str) -> Vec<u8> {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(body);
        serde_json::json!({
            "id": "message-1",
            "internalDate": "1700000000000",
            "payload": {
                "mimeType": "text/plain",
                "headers": [
                    { "name": "From", "value": from },
                    { "name": "Subject", "value": subject }
                ],
                "body": { "data": encoded, "size": body.len() }
            }
        })
        .to_string()
        .into_bytes()
    }

    fn test_key() -> StateKey {
        StateKey::from_bytes(&[3u8; 32]).expect("256-bit key")
    }

    #[test]
    fn interpret_message_detects_a_contextual_otp_with_provider_and_origin() {
        let json = detail_json(
            "Your Google verification code is 123456.",
            "Google <no-reply@accounts.google.com>",
            "Security code",
        );
        let now = Timestamp::from_unix_millis(1_700_000_000_000);

        let (seen, entry) = interpret_message(&json, "message-1", &test_key(), "person@example.com", now)
            .expect("contextual code must be detected");

        assert_eq!(entry.code(), "123456");
        assert_eq!(entry.provider().key(), "google");
        assert_eq!(entry.provider().display(), "Google");
        assert_eq!(entry.message_origin_display(), "Google <no-reply@accounts.google.com>");
        assert_eq!(entry.received_at().unix_millis(), 1_700_000_000_000);
        assert_eq!(entry.source_message_digest().as_str(), seen.as_str());
    }

    #[test]
    fn interpret_message_is_idempotent_per_mailbox_and_message() {
        let json = detail_json("Your code is 654321", "Example <otp@example.com>", "Login");
        let now = Timestamp::from_unix_millis(1_700_000_000_000);

        let first = interpret_message(&json, "message-1", &test_key(), "person@example.com", now);
        let repeat = interpret_message(&json, "message-1", &test_key(), "person@example.com", now);
        let other_mailbox =
            interpret_message(&json, "message-1", &test_key(), "other@example.com", now);
        let other_message =
            interpret_message(&json, "message-2", &test_key(), "person@example.com", now);

        assert_eq!(first.as_ref().map(|(seen, _)| seen.as_str()), repeat.as_ref().map(|(seen, _)| seen.as_str()));
        assert_ne!(first.as_ref().map(|(seen, _)| seen.as_str()), other_mailbox.as_ref().map(|(seen, _)| seen.as_str()));
        assert_ne!(first.as_ref().map(|(seen, _)| seen.as_str()), other_message.as_ref().map(|(seen, _)| seen.as_str()));
        assert_eq!(
            first.as_ref().map(|(_, entry)| entry.id().as_str()),
            repeat.as_ref().map(|(_, entry)| entry.id().as_str())
        );
    }

    #[test]
    fn interpret_message_rejects_non_otp_and_malformed_messages() {
        let now = Timestamp::from_unix_millis(1_700_000_000_000);
        let no_code = detail_json("Your order 12345678 has shipped.", "Shop <orders@example.com>", "");
        assert!(interpret_message(&no_code, "message-1", &test_key(), "person@example.com", now).is_none());

        let no_origin = detail_json("Your code is 123456", "", "");
        assert!(interpret_message(&no_origin, "message-1", &test_key(), "person@example.com", now).is_none());

        assert!(interpret_message(b"not json", "message-1", &test_key(), "person@example.com", now).is_none());
    }

    #[tokio::test]
    async fn unresponsive_owner_reply_fails_within_the_aggregate_deadline() {
        let (commands, mut receiver) = mpsc::channel(1);
        let owner = tokio::spawn(async move {
            let _held = receiver.recv().await;
            std::future::pending::<()>().await;
        });
        let handle = test_handle(commands);
        let started = Instant::now();

        assert_eq!(
            handle.shutdown().await,
            Err(MonitoringRuntimeError::Unavailable)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        owner.abort();
    }
}
