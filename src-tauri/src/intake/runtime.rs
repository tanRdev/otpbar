//! Production mailbox monitoring owner and Authorization bridge.

use std::{fmt, sync::Arc, time::Duration};

use serde::Serialize;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::timeout;

use crate::{
    authorization::{
        core::AuthorizationStatus,
        runtime::{AuthorizationHandle, AuthorizationTransportError},
    },
    clock::{Clock, SystemClock},
    mailbox::gmail::{FetchCompleteness, GmailMailbox},
};

use super::scheduler::{
    CheckCompleteness, CheckFuture, IntakeFailure, IntakeScheduler, IntakeTransport, JitterSource,
    MigrationReadiness, MonitoringHealth, SecureJitter,
};

const MONITORING_COMMAND_DEADLINE: Duration = Duration::from_millis(400);

/// Gmail check adapter that obtains an unexpired credential from the sole
/// Authorization owner for every request.
pub struct AuthorizedGmailTransport {
    authorization: AuthorizationHandle,
    mailbox: GmailMailbox,
}

impl AuthorizedGmailTransport {
    pub fn new(authorization: AuthorizationHandle, mailbox: GmailMailbox) -> Self {
        Self {
            authorization,
            mailbox,
        }
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
            Ok(match fetch.completeness() {
                FetchCompleteness::Complete => CheckCompleteness::Complete,
                FetchCompleteness::Partial { .. } => CheckCompleteness::Partial,
            })
        })
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

/// Builds the production Gmail-backed monitoring owner.
pub fn spawn_production_monitoring(authorization: AuthorizationHandle) -> MonitoringHandle {
    let transport = AuthorizedGmailTransport::new(authorization.clone(), GmailMailbox::new());
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
