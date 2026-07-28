//! Single-owner cancellable intake scheduler and Monitoring Health.

use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use rand::Rng as _;
use tokio::{
    sync::{watch, Notify},
    task::JoinHandle,
    time::timeout,
};

use crate::{
    authorization::core::AuthorizationStatus,
    clock::{Clock, Timestamp},
};

const HEALTHY_INTERVAL: Duration = Duration::from_secs(8);
const INITIAL_RETRY: Duration = Duration::from_secs(15);
const MAX_RETRY: Duration = Duration::from_secs(15 * 60);
const STALE_AFTER: Duration = Duration::from_secs(30);
const STOP_DEADLINE: Duration = Duration::from_secs(1);

/// Whether encrypted-state migration/recovery permits mailbox intake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationReadiness {
    Pending,
    Ready,
    Blocked,
}

/// Result of requesting the single scheduler owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerStart {
    Started,
    AlreadyRunning,
    NotReady,
}

/// Completeness of one transport check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckCompleteness {
    Complete,
    Partial,
}

/// Stable, redacted transport failures consumed by Monitoring Health.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntakeFailure {
    Offline,
    RateLimited { retry_after: Option<Duration> },
    PermissionDenied,
    AuthorizationRequired,
    Unavailable,
}

impl fmt::Display for IntakeFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Offline => "Mailbox monitoring is offline.",
            Self::RateLimited { .. } => "Mailbox monitoring was rate limited.",
            Self::PermissionDenied => "Mailbox read permission is required.",
            Self::AuthorizationRequired => "Mailbox Authorization must be renewed.",
            Self::Unavailable => "Mailbox monitoring is temporarily unavailable.",
        })
    }
}

impl std::error::Error for IntakeFailure {}

impl From<crate::mailbox::gmail::GmailError> for IntakeFailure {
    fn from(error: crate::mailbox::gmail::GmailError) -> Self {
        match error {
            crate::mailbox::gmail::GmailError::AuthorizationRequired => Self::AuthorizationRequired,
            crate::mailbox::gmail::GmailError::PermissionDenied => Self::PermissionDenied,
            crate::mailbox::gmail::GmailError::RateLimited { retry_after } => {
                Self::RateLimited { retry_after }
            }
            crate::mailbox::gmail::GmailError::Offline => Self::Offline,
            crate::mailbox::gmail::GmailError::ServerUnavailable
            | crate::mailbox::gmail::GmailError::MalformedResponse
            | crate::mailbox::gmail::GmailError::UnexpectedStatus => Self::Unavailable,
        }
    }
}

/// Public Monitoring Health state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitoringHealthStatus {
    Stopped,
    Checking,
    Healthy,
    Stale,
    Offline,
    RateLimited,
    PartiallyDegraded,
    PermissionDenied,
    Unavailable,
}

/// Secret-free Monitoring Health snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitoringHealth {
    status: MonitoringHealthStatus,
    last_success: Option<Timestamp>,
    next_action: Option<Timestamp>,
}

impl MonitoringHealth {
    const fn stopped() -> Self {
        Self {
            status: MonitoringHealthStatus::Stopped,
            last_success: None,
            next_action: None,
        }
    }

    /// Returns the public health classification.
    pub const fn status(self) -> MonitoringHealthStatus {
        self.status
    }

    /// Returns the last complete successful check time.
    pub const fn last_success(self) -> Option<Timestamp> {
        self.last_success
    }

    /// Returns the scheduled check or retry time when known.
    pub const fn next_action(self) -> Option<Timestamp> {
        self.next_action
    }
}

/// Borrowing future returned by the injected mailbox transport.
pub type CheckFuture<'a> =
    Pin<Box<dyn Future<Output = Result<CheckCompleteness, IntakeFailure>> + Send + 'a>>;

/// Cancellable mailbox-check boundary.
pub trait IntakeTransport: Send + 'static {
    fn check(&mut self) -> CheckFuture<'_>;
}

/// Injected healthy-interval jitter source.
pub trait JitterSource: Send + 'static {
    /// Returns a signed offset in basis points, clamped to ±1000 (±10%).
    fn healthy_jitter_basis_points(&mut self) -> i32;
}

/// Production cryptographically secure healthy-interval jitter.
#[derive(Debug, Clone, Copy, Default)]
pub struct SecureJitter;

impl JitterSource for SecureJitter {
    fn healthy_jitter_basis_points(&mut self) -> i32 {
        rand::rngs::OsRng.gen_range(-1_000..=1_000)
    }
}

#[derive(Default)]
struct CancellationState {
    cancelled: AtomicBool,
    notify: Notify,
}

#[derive(Default)]
struct ImmediateAdmissionState {
    requested: bool,
    not_before: Option<Timestamp>,
}

#[derive(Default)]
struct ImmediateSignal {
    state: Mutex<ImmediateAdmissionState>,
    notify: Notify,
}

impl ImmediateSignal {
    fn request(&self, now: Timestamp) -> bool {
        let should_notify = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.not_before.is_some_and(|not_before| now < not_before) {
                return false;
            }
            let should_notify = !state.requested;
            state.requested = true;
            should_notify
        };
        if should_notify {
            self.notify.notify_waiters();
        }
        true
    }

    fn suppress_until(&self, not_before: Timestamp) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.requested = false;
        state.not_before = Some(not_before);
    }

    fn allow_immediate(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .not_before = None;
    }

    fn reset(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.requested = false;
        state.not_before = None;
    }

    async fn requested(&self) {
        loop {
            let notified = self.notify.notified();
            let requested = {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let requested = state.requested;
                state.requested = false;
                requested
            };
            if requested {
                return;
            }
            notified.await;
        }
    }
}

#[derive(Clone, Default)]
struct Cancellation {
    state: Arc<CancellationState>,
}

impl Cancellation {
    fn cancel(&self) {
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

struct Running<T, J> {
    cancellation: Cancellation,
    task: JoinHandle<(T, J)>,
}

/// Single owner of one cancellable intake task.
pub struct IntakeScheduler<T, C, J> {
    idle: Option<(T, J)>,
    clock: Arc<C>,
    running: Option<Running<T, J>>,
    check_now: Arc<ImmediateSignal>,
    health_sender: watch::Sender<MonitoringHealth>,
    health_receiver: watch::Receiver<MonitoringHealth>,
}

impl<T, C, J> IntakeScheduler<T, C, J>
where
    T: IntakeTransport,
    C: Clock + 'static,
    J: JitterSource,
{
    /// Creates a stopped scheduler with injected transport, time, and jitter.
    pub fn new(transport: T, clock: Arc<C>, jitter: J) -> Self {
        let (health_sender, health_receiver) = watch::channel(MonitoringHealth::stopped());
        Self {
            idle: Some((transport, jitter)),
            clock,
            running: None,
            check_now: Arc::new(ImmediateSignal::default()),
            health_sender,
            health_receiver,
        }
    }

    /// Returns the latest secret-free Monitoring Health snapshot.
    pub fn health(&self) -> MonitoringHealth {
        *self.health_receiver.borrow()
    }

    /// Subscribes to Monitoring Health changes without exposing scheduler state.
    pub fn subscribe_health(&self) -> watch::Receiver<MonitoringHealth> {
        self.health_receiver.clone()
    }

    /// Starts exactly one owner only after storage migration and Authorization.
    pub fn start(
        &mut self,
        migration: MigrationReadiness,
        authorization: AuthorizationStatus,
    ) -> SchedulerStart {
        if migration != MigrationReadiness::Ready || authorization != AuthorizationStatus::Connected
        {
            return SchedulerStart::NotReady;
        }
        if self.running.is_some() {
            return SchedulerStart::AlreadyRunning;
        }
        let Some((transport, jitter)) = self.idle.take() else {
            return SchedulerStart::AlreadyRunning;
        };
        self.check_now.reset();
        let cancellation = Cancellation::default();
        let task_cancellation = cancellation.clone();
        let clock = Arc::clone(&self.clock);
        let check_now = Arc::clone(&self.check_now);
        let health = self.health_sender.clone();
        let task = tokio::spawn(async move {
            run_scheduler(
                transport,
                clock,
                jitter,
                task_cancellation,
                check_now,
                health,
            )
            .await
        });
        self.running = Some(Running { cancellation, task });
        SchedulerStart::Started
    }

    /// Stops the owner for app shutdown.
    pub async fn shutdown(&mut self) {
        self.stop().await;
    }

    /// Stops monitoring after Authorization disconnect.
    pub async fn disconnect(&mut self) {
        self.stop().await;
    }

    /// Coalesces an immediate user or connectivity-restored check.
    pub fn check_now(&self) {
        if self.running.is_none() {
            return;
        }
        self.check_now.request(self.clock.now());
    }

    /// Marks overdue health stale after wake and coalesces one immediate check.
    pub fn wake(&self) {
        if self.running.is_none() {
            return;
        }
        let now = self.clock.now();
        if !self.check_now.request(now) {
            return;
        }
        let current = self.health();
        if current
            .last_success
            .is_some_and(|last_success| elapsed_since(last_success, now) >= STALE_AFTER)
        {
            self.health_sender.send_replace(MonitoringHealth {
                status: MonitoringHealthStatus::Stale,
                last_success: current.last_success,
                next_action: Some(now),
            });
        }
    }

    async fn stop(&mut self) {
        let Some(running) = self.running.take() else {
            return;
        };
        running.cancellation.cancel();
        let mut task = running.task;
        match timeout(STOP_DEADLINE, &mut task).await {
            Ok(Ok(owned)) => self.idle = Some(owned),
            Ok(Err(_)) => {}
            Err(_) => {
                task.abort();
                let _ = task.await;
            }
        }
        self.check_now.reset();
        self.health_sender.send_replace(MonitoringHealth::stopped());
    }
}

impl<T, C, J> Drop for IntakeScheduler<T, C, J> {
    fn drop(&mut self) {
        if let Some(running) = self.running.take() {
            running.cancellation.cancel();
            running.task.abort();
        }
    }
}

async fn run_scheduler<T, C, J>(
    mut transport: T,
    clock: Arc<C>,
    mut jitter: J,
    cancellation: Cancellation,
    check_now: Arc<ImmediateSignal>,
    health: watch::Sender<MonitoringHealth>,
) -> (T, J)
where
    T: IntakeTransport,
    C: Clock + 'static,
    J: JitterSource,
{
    let mut policy = SchedulerPolicy::new();
    let mut wait = Duration::ZERO;
    loop {
        if !wait.is_zero() {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => break,
                () = check_now.requested() => {}
                () = clock.sleep(wait) => {}
            }
        }
        health.send_replace(MonitoringHealth {
            status: MonitoringHealthStatus::Checking,
            last_success: policy.last_success,
            next_action: None,
        });
        let check = transport.check();
        let result = tokio::select! {
            biased;
            () = cancellation.cancelled() => break,
            result = check => result,
        };
        let (snapshot, next_wait) = policy.record(result, clock.now(), &mut jitter);
        if snapshot.status == MonitoringHealthStatus::RateLimited {
            check_now.suppress_until(
                snapshot
                    .next_action
                    .unwrap_or(Timestamp::from_unix_millis(i64::MAX)),
            );
        } else {
            check_now.allow_immediate();
        }
        health.send_replace(snapshot);
        wait = next_wait;
    }
    (transport, jitter)
}

struct SchedulerPolicy {
    retry: Duration,
    last_success: Option<Timestamp>,
}

impl SchedulerPolicy {
    const fn new() -> Self {
        Self {
            retry: INITIAL_RETRY,
            last_success: None,
        }
    }

    fn record(
        &mut self,
        result: Result<CheckCompleteness, IntakeFailure>,
        now: Timestamp,
        jitter: &mut impl JitterSource,
    ) -> (MonitoringHealth, Duration) {
        match result {
            Ok(CheckCompleteness::Complete) => {
                self.last_success = Some(now);
                self.retry = INITIAL_RETRY;
                let delay = healthy_delay(jitter);
                (
                    MonitoringHealth {
                        status: MonitoringHealthStatus::Healthy,
                        last_success: self.last_success,
                        next_action: now.checked_add(delay),
                    },
                    delay,
                )
            }
            Ok(CheckCompleteness::Partial) => {
                self.retry_snapshot(MonitoringHealthStatus::PartiallyDegraded, now, None)
            }
            Err(IntakeFailure::Offline) => {
                self.retry_snapshot(MonitoringHealthStatus::Offline, now, None)
            }
            Err(IntakeFailure::RateLimited { retry_after }) => {
                self.retry_snapshot(MonitoringHealthStatus::RateLimited, now, retry_after)
            }
            Err(IntakeFailure::PermissionDenied) => {
                self.retry_snapshot(MonitoringHealthStatus::PermissionDenied, now, None)
            }
            Err(IntakeFailure::AuthorizationRequired | IntakeFailure::Unavailable) => {
                self.retry_snapshot(MonitoringHealthStatus::Unavailable, now, None)
            }
        }
    }

    fn retry_snapshot(
        &mut self,
        status: MonitoringHealthStatus,
        now: Timestamp,
        minimum: Option<Duration>,
    ) -> (MonitoringHealth, Duration) {
        let delay = minimum.map_or(self.retry, |minimum| self.retry.max(minimum));
        self.retry = self.retry.saturating_mul(2).min(MAX_RETRY);
        (
            MonitoringHealth {
                status,
                last_success: self.last_success,
                next_action: now.checked_add(delay),
            },
            delay,
        )
    }
}

fn elapsed_since(earlier: Timestamp, later: Timestamp) -> Duration {
    let milliseconds = later
        .unix_millis()
        .saturating_sub(earlier.unix_millis())
        .max(0);
    Duration::from_millis(milliseconds as u64)
}

fn healthy_delay(jitter: &mut impl JitterSource) -> Duration {
    let basis_points = jitter.healthy_jitter_basis_points().clamp(-1_000, 1_000);
    let base_millis = HEALTHY_INTERVAL.as_millis() as i128;
    let offset = base_millis * i128::from(basis_points) / 10_000;
    Duration::from_millis((base_millis + offset) as u64)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        future,
        sync::{
            atomic::{AtomicI64, AtomicUsize, Ordering},
            Arc, Barrier, Mutex,
        },
        thread,
        time::Duration,
    };

    use crate::{
        authorization::core::AuthorizationStatus,
        clock::{Clock, Sleep, Timestamp},
    };
    use tokio::sync::oneshot;

    use super::{
        CheckCompleteness, CheckFuture, ImmediateSignal, IntakeFailure, IntakeScheduler,
        IntakeTransport, JitterSource, MigrationReadiness, MonitoringHealth,
        MonitoringHealthStatus, SchedulerStart,
    };

    struct FakeClock {
        milliseconds: AtomicI64,
    }

    impl FakeClock {
        fn new(milliseconds: i64) -> Self {
            Self {
                milliseconds: AtomicI64::new(milliseconds),
            }
        }

        fn advance_wall(&self, duration: Duration) {
            self.milliseconds.fetch_add(
                i64::try_from(duration.as_millis()).unwrap(),
                Ordering::SeqCst,
            );
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Timestamp {
            Timestamp::from_unix_millis(self.milliseconds.load(Ordering::SeqCst))
        }

        fn sleep(&self, duration: Duration) -> Sleep<'_> {
            Box::pin(tokio::time::sleep(duration))
        }
    }

    struct FixedJitter(i32);

    impl JitterSource for FixedJitter {
        fn healthy_jitter_basis_points(&mut self) -> i32 {
            self.0
        }
    }

    type FakeOutcome = Option<Result<CheckCompleteness, IntakeFailure>>;

    struct FakeTransport {
        checks: Arc<AtomicUsize>,
        outcomes: Arc<Mutex<VecDeque<FakeOutcome>>>,
    }

    impl IntakeTransport for FakeTransport {
        fn check(&mut self) -> CheckFuture<'_> {
            self.checks.fetch_add(1, Ordering::SeqCst);
            let outcome = self.outcomes.lock().unwrap().pop_front().flatten();
            Box::pin(async move {
                match outcome {
                    Some(outcome) => outcome,
                    None => future::pending().await,
                }
            })
        }
    }

    struct GatedTransport {
        checks: Arc<AtomicUsize>,
        gate: Option<oneshot::Receiver<Result<CheckCompleteness, IntakeFailure>>>,
    }

    impl IntakeTransport for GatedTransport {
        fn check(&mut self) -> CheckFuture<'_> {
            self.checks.fetch_add(1, Ordering::SeqCst);
            let gate = self.gate.take();
            Box::pin(async move {
                match gate {
                    Some(gate) => gate.await.unwrap(),
                    None => future::pending().await,
                }
            })
        }
    }

    async fn yield_until(predicate: impl Fn() -> bool) {
        for _ in 0..100 {
            if predicate() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("condition was not reached");
    }

    async fn advance(clock: &FakeClock, duration: Duration) {
        clock.advance_wall(duration);
        tokio::time::advance(duration).await;
        tokio::task::yield_now().await;
    }

    #[tokio::test(start_paused = true)]
    async fn starts_only_when_migration_and_authorization_are_ready_with_one_owner() {
        let checks = Arc::new(AtomicUsize::new(0));
        let transport = FakeTransport {
            checks: Arc::clone(&checks),
            outcomes: Arc::new(Mutex::new(VecDeque::from([Some(Ok(
                CheckCompleteness::Complete,
            ))]))),
        };
        let mut scheduler =
            IntakeScheduler::new(transport, Arc::new(FakeClock::new(1_000)), FixedJitter(0));

        assert_eq!(
            scheduler.start(MigrationReadiness::Pending, AuthorizationStatus::Connected),
            SchedulerStart::NotReady
        );
        assert_eq!(
            scheduler.start(MigrationReadiness::Ready, AuthorizationStatus::Disconnected),
            SchedulerStart::NotReady
        );
        assert_eq!(checks.load(Ordering::SeqCst), 0);

        assert_eq!(
            scheduler.start(MigrationReadiness::Ready, AuthorizationStatus::Connected),
            SchedulerStart::Started
        );
        assert_eq!(
            scheduler.start(MigrationReadiness::Ready, AuthorizationStatus::Connected),
            SchedulerStart::AlreadyRunning
        );
        yield_until(|| checks.load(Ordering::SeqCst) == 1).await;
        scheduler.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn disconnect_stops_a_blocked_check_and_clean_restart_has_no_duplicate() {
        let checks = Arc::new(AtomicUsize::new(0));
        let transport = FakeTransport {
            checks: Arc::clone(&checks),
            outcomes: Arc::new(Mutex::new(VecDeque::from([None, None]))),
        };
        let mut scheduler =
            IntakeScheduler::new(transport, Arc::new(FakeClock::new(1_000)), FixedJitter(0));
        assert_eq!(
            scheduler.start(MigrationReadiness::Ready, AuthorizationStatus::Connected),
            SchedulerStart::Started
        );
        yield_until(|| checks.load(Ordering::SeqCst) == 1).await;

        tokio::time::timeout(Duration::from_secs(1), scheduler.disconnect())
            .await
            .expect("disconnect must stop within one second");
        assert_eq!(scheduler.health().status(), MonitoringHealthStatus::Stopped);

        assert_eq!(
            scheduler.start(MigrationReadiness::Ready, AuthorizationStatus::Connected),
            SchedulerStart::Started
        );
        assert_eq!(
            scheduler.start(MigrationReadiness::Ready, AuthorizationStatus::Connected),
            SchedulerStart::AlreadyRunning
        );
        yield_until(|| checks.load(Ordering::SeqCst) == 2).await;
        scheduler.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn healthy_interval_applies_exact_plus_or_minus_ten_percent_jitter() {
        for (basis_points, before, boundary) in [
            (
                -1_000,
                Duration::from_millis(7_199),
                Duration::from_millis(1),
            ),
            (
                1_000,
                Duration::from_millis(8_799),
                Duration::from_millis(1),
            ),
        ] {
            let checks = Arc::new(AtomicUsize::new(0));
            let clock = Arc::new(FakeClock::new(1_000));
            let transport = FakeTransport {
                checks: Arc::clone(&checks),
                outcomes: Arc::new(Mutex::new(VecDeque::from([
                    Some(Ok(CheckCompleteness::Complete)),
                    None,
                ]))),
            };
            let mut scheduler =
                IntakeScheduler::new(transport, Arc::clone(&clock), FixedJitter(basis_points));
            scheduler.start(MigrationReadiness::Ready, AuthorizationStatus::Connected);
            yield_until(|| checks.load(Ordering::SeqCst) == 1).await;

            advance(&clock, before).await;
            assert_eq!(checks.load(Ordering::SeqCst), 1);
            advance(&clock, boundary).await;
            yield_until(|| checks.load(Ordering::SeqCst) == 2).await;
            scheduler.shutdown().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn exponential_backoff_caps_at_fifteen_minutes_and_complete_resets_it() {
        let delays = [15_u64, 30, 60, 120, 240, 480, 900, 900];
        let mut outcomes = VecDeque::new();
        for _ in delays {
            outcomes.push_back(Some(Err(IntakeFailure::Offline)));
        }
        outcomes.push_back(Some(Ok(CheckCompleteness::Complete)));
        outcomes.push_back(Some(Err(IntakeFailure::Offline)));
        outcomes.push_back(None);
        let checks = Arc::new(AtomicUsize::new(0));
        let clock = Arc::new(FakeClock::new(1_000));
        let transport = FakeTransport {
            checks: Arc::clone(&checks),
            outcomes: Arc::new(Mutex::new(outcomes)),
        };
        let mut scheduler = IntakeScheduler::new(transport, Arc::clone(&clock), FixedJitter(0));
        scheduler.start(MigrationReadiness::Ready, AuthorizationStatus::Connected);

        for (index, seconds) in delays.into_iter().enumerate() {
            yield_until(|| checks.load(Ordering::SeqCst) == index + 1).await;
            let health = scheduler.health();
            assert_eq!(health.status(), MonitoringHealthStatus::Offline);
            assert_eq!(
                health.next_action().unwrap().unix_millis() - clock.now().unix_millis(),
                i64::try_from(seconds * 1_000).unwrap()
            );
            advance(&clock, Duration::from_secs(seconds)).await;
        }

        yield_until(|| checks.load(Ordering::SeqCst) == 9).await;
        assert_eq!(scheduler.health().status(), MonitoringHealthStatus::Healthy);
        advance(&clock, Duration::from_secs(8)).await;
        yield_until(|| checks.load(Ordering::SeqCst) == 10).await;
        assert_eq!(
            scheduler.health().next_action().unwrap().unix_millis() - clock.now().unix_millis(),
            15_000
        );
        scheduler.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn retry_after_partial_stale_and_sleep_wake_are_explicit_and_coalesced() {
        let checks = Arc::new(AtomicUsize::new(0));
        let clock = Arc::new(FakeClock::new(1_000));
        let transport = FakeTransport {
            checks: Arc::clone(&checks),
            outcomes: Arc::new(Mutex::new(VecDeque::from([
                Some(Err(IntakeFailure::RateLimited {
                    retry_after: Some(Duration::from_secs(120)),
                })),
                Some(Ok(CheckCompleteness::Partial)),
                Some(Ok(CheckCompleteness::Complete)),
                None,
            ]))),
        };
        let mut scheduler = IntakeScheduler::new(transport, Arc::clone(&clock), FixedJitter(0));
        scheduler.start(MigrationReadiness::Ready, AuthorizationStatus::Connected);
        yield_until(|| checks.load(Ordering::SeqCst) == 1).await;
        assert_eq!(
            scheduler.health().status(),
            MonitoringHealthStatus::RateLimited
        );
        assert_eq!(
            scheduler.health().next_action().unwrap().unix_millis() - clock.now().unix_millis(),
            120_000
        );
        scheduler.check_now();
        tokio::task::yield_now().await;
        assert_eq!(checks.load(Ordering::SeqCst), 1);

        advance(&clock, Duration::from_secs(120)).await;
        yield_until(|| checks.load(Ordering::SeqCst) == 2).await;
        assert_eq!(
            scheduler.health().status(),
            MonitoringHealthStatus::PartiallyDegraded
        );
        scheduler.check_now();
        yield_until(|| checks.load(Ordering::SeqCst) == 3).await;
        assert_eq!(scheduler.health().status(), MonitoringHealthStatus::Healthy);

        clock.advance_wall(Duration::from_secs(31));
        scheduler.wake();
        assert_eq!(scheduler.health().status(), MonitoringHealthStatus::Stale);
        yield_until(|| checks.load(Ordering::SeqCst) == 4).await;
        scheduler.check_now();
        scheduler.check_now();
        tokio::time::advance(Duration::from_secs(60 * 60)).await;
        tokio::task::yield_now().await;
        assert_eq!(checks.load(Ordering::SeqCst), 4);
        scheduler.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn in_flight_check_now_and_wake_cannot_bypass_new_retry_after() {
        for use_wake in [false, true] {
            let checks = Arc::new(AtomicUsize::new(0));
            let clock = Arc::new(FakeClock::new(1_000));
            let (release, gate) = oneshot::channel();
            let transport = GatedTransport {
                checks: Arc::clone(&checks),
                gate: Some(gate),
            };
            let mut scheduler = IntakeScheduler::new(transport, Arc::clone(&clock), FixedJitter(0));
            scheduler.start(MigrationReadiness::Ready, AuthorizationStatus::Connected);
            yield_until(|| checks.load(Ordering::SeqCst) == 1).await;
            assert_eq!(
                scheduler.health().status(),
                MonitoringHealthStatus::Checking
            );

            if use_wake {
                scheduler.wake();
            } else {
                scheduler.check_now();
            }
            release
                .send(Err(IntakeFailure::RateLimited {
                    retry_after: Some(Duration::from_secs(120)),
                }))
                .unwrap();
            yield_until(|| scheduler.health().status() == MonitoringHealthStatus::RateLimited)
                .await;
            tokio::task::yield_now().await;
            assert_eq!(checks.load(Ordering::SeqCst), 1);

            advance(&clock, Duration::from_secs(119)).await;
            assert_eq!(checks.load(Ordering::SeqCst), 1);
            advance(&clock, Duration::from_secs(1)).await;
            yield_until(|| checks.load(Ordering::SeqCst) == 2).await;
            scheduler.shutdown().await;
        }
    }

    #[test]
    fn stale_health_snapshot_cannot_enqueue_after_retry_deadline_is_installed() {
        let signal = Arc::new(ImmediateSignal::default());
        let snapshot_read = Arc::new(Barrier::new(2));
        let resume_enqueue = Arc::new(Barrier::new(2));
        let caller = thread::spawn({
            let signal = Arc::clone(&signal);
            let snapshot_read = Arc::clone(&snapshot_read);
            let resume_enqueue = Arc::clone(&resume_enqueue);
            move || {
                let stale_snapshot = MonitoringHealth {
                    status: MonitoringHealthStatus::Checking,
                    last_success: None,
                    next_action: None,
                };
                assert_eq!(stale_snapshot.status(), MonitoringHealthStatus::Checking);
                snapshot_read.wait();
                resume_enqueue.wait();
                signal.request(Timestamp::from_unix_millis(1_000))
            }
        });

        snapshot_read.wait();
        signal.suppress_until(Timestamp::from_unix_millis(121_000));
        resume_enqueue.wait();

        assert!(!caller.join().unwrap());
        assert!(
            !signal
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .requested
        );
        assert!(signal.request(Timestamp::from_unix_millis(121_000)));
    }

    #[tokio::test(start_paused = true)]
    async fn rate_limited_wake_is_ignored_early_and_allowed_when_due() {
        let checks = Arc::new(AtomicUsize::new(0));
        let clock = Arc::new(FakeClock::new(1_000));
        let transport = FakeTransport {
            checks: Arc::clone(&checks),
            outcomes: Arc::new(Mutex::new(VecDeque::from([
                Some(Err(IntakeFailure::RateLimited {
                    retry_after: Some(Duration::from_secs(120)),
                })),
                None,
            ]))),
        };
        let mut scheduler = IntakeScheduler::new(transport, Arc::clone(&clock), FixedJitter(0));
        scheduler.start(MigrationReadiness::Ready, AuthorizationStatus::Connected);
        yield_until(|| scheduler.health().status() == MonitoringHealthStatus::RateLimited).await;

        clock.advance_wall(Duration::from_secs(119));
        scheduler.wake();
        tokio::task::yield_now().await;
        assert_eq!(checks.load(Ordering::SeqCst), 1);

        clock.advance_wall(Duration::from_secs(1));
        scheduler.wake();
        yield_until(|| checks.load(Ordering::SeqCst) == 2).await;
        scheduler.wake();
        scheduler.wake();
        tokio::task::yield_now().await;
        assert_eq!(checks.load(Ordering::SeqCst), 2);
        scheduler.shutdown().await;
    }
}
