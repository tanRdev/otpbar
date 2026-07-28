use std::time::Duration;

use otpbar::{
    clipboard_lease::{ClipboardLease, CopyReceipt, LeaseDuration, LeaseError, LeaseTransition},
    clock::{Clock, Timestamp},
    domain::error::{ErrorCode, ErrorEnvelope, UserMessage},
    ports::Clipboard,
};
use serde::Serialize;
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
};
use zeroize::Zeroizing;

const REQUEST_CAPACITY: usize = 16;
const EXPIRY_UNAVAILABLE_MESSAGE: &str = "Clipboard expiry cannot safely clear on this platform because atomic ownership verification is unavailable; copied content was left unchanged.";
const EXPIRY_PERMISSION_DENIED_MESSAGE: &str =
    "Clipboard access was denied during expiry; copied content was left unchanged.";
const EXPIRY_CLEAR_FAILED_MESSAGE: &str =
    "Clipboard expiry failed; copied content was left unchanged.";

/// Non-secret status emitted by the single clipboard actor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ClipboardLeaseEvent {
    /// OTPBar most recently wrote the current leased value.
    Owned {
        /// Projected wall-clock deadline in Unix epoch milliseconds.
        expires_at: i64,
    },
    /// OTPBar has no active clipboard lease.
    Idle {
        /// Why the previously active lease became idle.
        reason: ClipboardIdleReason,
    },
    /// Clipboard ownership could not complete as requested.
    Degraded {
        /// Stable non-secret failure classification.
        code: ClipboardDegradedCode,
        /// Safe user-facing explanation.
        message: String,
        /// Whether retrying may succeed without a platform change.
        retryable: bool,
    },
}

/// Safe reason why no clipboard lease remains active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardIdleReason {
    /// The owned value reached expiry and was cleared.
    Expired,
    /// Another application replaced the clipboard value.
    OwnershipLost,
    /// Application shutdown relinquished ownership without clipboard I/O.
    Shutdown,
}

/// Stable non-secret categories for degraded clipboard behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardDegradedCode {
    /// The requested clipboard write did not complete.
    CopyUnavailable,
    /// Clipboard access was denied during expiry.
    PermissionDenied,
    /// An ordinary compare-and-clear operation failed.
    ClearFailed,
    /// The platform adapter lacks atomic compare-and-clear.
    AtomicCompareAndClearUnavailable,
}

/// Sink for safe lease status. Implementations never receive clipboard text.
pub trait LeaseEventSink: Send + Sync + 'static {
    /// Publishes one non-secret authoritative lease transition.
    fn publish(&self, event: ClipboardLeaseEvent);
}

#[derive(Clone)]
/// Cloneable request handle for the process-local clipboard actor.
pub struct ClipboardActorHandle {
    requests: mpsc::Sender<Request>,
    shutdown: watch::Sender<bool>,
    stopped: watch::Receiver<bool>,
}

impl ClipboardActorHandle {
    /// Requests a managed copy and waits for its safe typed outcome.
    pub async fn copy(&self, value: String, duration: LeaseDuration) -> Result<(), ErrorEnvelope> {
        let (reply, response) = oneshot::channel();
        self.requests
            .send(Request::Copy {
                value: Zeroizing::new(value),
                duration,
                reply,
            })
            .await
            .map_err(|_| actor_unavailable())?;
        response.await.map_err(|_| actor_unavailable())?
    }

    /// Stops the actor after aborting its timer and relinquishing lease state.
    ///
    /// Shutdown never performs clipboard I/O.
    pub async fn shutdown(&self) {
        let mut stopped = self.stopped.clone();
        let _ = self.shutdown.send(true);
        if !*stopped.borrow() {
            let _ = stopped.changed().await;
        }
    }
}

enum Request {
    Copy {
        value: Zeroizing<String>,
        duration: LeaseDuration,
        reply: oneshot::Sender<Result<(), ErrorEnvelope>>,
    },
    Expire {
        receipt: CopyReceipt,
    },
}

struct ExpiryTimer {
    lease_id: otpbar::clipboard_lease::LeaseId,
    task: JoinHandle<()>,
}

impl ExpiryTimer {
    fn cancel(self) {
        self.task.abort();
    }
}

/// Starts the single owner of clipboard I/O, lease state, and expiry timers.
///
/// The returned handle communicates exclusively through channels; callers
/// never lock actor-owned state around clipboard operations.
pub fn spawn_clipboard_actor<P, C, S>(clipboard: P, clock: C, events: S) -> ClipboardActorHandle
where
    P: Clipboard + Send + 'static,
    C: Clock + Clone + Send + Sync + 'static,
    S: LeaseEventSink,
{
    let (requests, receiver) = mpsc::channel(REQUEST_CAPACITY);
    let (shutdown, shutdown_receiver) = watch::channel(false);
    let (stopped_sender, stopped) = watch::channel(false);
    let handle = ClipboardActorHandle {
        requests: requests.clone(),
        shutdown,
        stopped,
    };
    tokio::spawn(run_actor(
        clipboard,
        clock,
        events,
        requests,
        receiver,
        shutdown_receiver,
        stopped_sender,
    ));
    handle
}

async fn run_actor<P, C, S>(
    mut clipboard: P,
    clock: C,
    events: S,
    requests: mpsc::Sender<Request>,
    mut receiver: mpsc::Receiver<Request>,
    mut shutdown: watch::Receiver<bool>,
    stopped: watch::Sender<bool>,
) where
    P: Clipboard + Send + 'static,
    C: Clock + Clone + Send + Sync + 'static,
    S: LeaseEventSink,
{
    let mut lease = ClipboardLease::new();
    let mut timer: Option<ExpiryTimer> = None;

    loop {
        let request = tokio::select! {
            biased;
            result = shutdown.changed() => {
                if result.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
            request = receiver.recv() => {
                let Some(request) = request else {
                    break;
                };
                request
            }
        };

        match request {
            Request::Copy {
                value,
                duration,
                reply,
            } => {
                cancel_timer(&mut timer);
                match lease.copy(&mut clipboard, value.as_str(), duration, clock.now()) {
                    Ok(receipt) => {
                        events.publish(ClipboardLeaseEvent::Owned {
                            expires_at: receipt.expires_at.unix_millis(),
                        });
                        timer = Some(schedule_expiry(requests.clone(), clock.clone(), receipt));
                        let _ = reply.send(Ok(()));
                    }
                    Err(lease_error) => {
                        let retryable = matches!(
                            lease_error,
                            LeaseError::WriteFailed | LeaseError::ClearFailed
                        );
                        let error = lease_error_envelope(lease_error);
                        events.publish(ClipboardLeaseEvent::Degraded {
                            code: ClipboardDegradedCode::CopyUnavailable,
                            message: error.to_string(),
                            retryable,
                        });
                        let _ = reply.send(Err(error));
                    }
                }
            }
            Request::Expire { receipt } => {
                cancel_timer_for(&mut timer, receipt.lease_id);
                match lease.expire(receipt.lease_id, clock.now(), &mut clipboard) {
                    LeaseTransition::NotYetExpired => {
                        timer = Some(schedule_expiry(requests.clone(), clock.clone(), receipt));
                    }
                    LeaseTransition::ExpiredAndCleared => {
                        events.publish(ClipboardLeaseEvent::Idle {
                            reason: ClipboardIdleReason::Expired,
                        });
                    }
                    LeaseTransition::OwnershipLost => {
                        events.publish(ClipboardLeaseEvent::Idle {
                            reason: ClipboardIdleReason::OwnershipLost,
                        });
                    }
                    LeaseTransition::Failed(error) => {
                        events.publish(expiry_failure_event(error));
                    }
                    LeaseTransition::Superseded | LeaseTransition::Canceled => {}
                }
            }
        }
    }

    cancel_timer(&mut timer);
    lease.cancel();
    events.publish(ClipboardLeaseEvent::Idle {
        reason: ClipboardIdleReason::Shutdown,
    });
    let _ = stopped.send(true);
}

fn schedule_expiry<C>(
    requests: mpsc::Sender<Request>,
    clock: C,
    receipt: CopyReceipt,
) -> ExpiryTimer
where
    C: Clock + Send + 'static,
{
    let remaining = remaining_duration(clock.now(), receipt.expires_at);
    let lease_id = receipt.lease_id;
    let task = tokio::spawn(async move {
        clock.sleep(remaining).await;
        let _ = requests.send(Request::Expire { receipt }).await;
    });
    ExpiryTimer { lease_id, task }
}

fn remaining_duration(now: Timestamp, expires_at: Timestamp) -> Duration {
    let milliseconds = expires_at
        .unix_millis()
        .saturating_sub(now.unix_millis())
        .max(1) as u64;
    Duration::from_millis(milliseconds)
}

fn cancel_timer(timer: &mut Option<ExpiryTimer>) {
    if let Some(timer) = timer.take() {
        timer.cancel();
    }
}

fn cancel_timer_for(timer: &mut Option<ExpiryTimer>, lease_id: otpbar::clipboard_lease::LeaseId) {
    if timer
        .as_ref()
        .is_some_and(|timer| timer.lease_id == lease_id)
    {
        cancel_timer(timer);
    }
}

/// Maps every internal lease failure to one safe public command error.
pub(crate) fn lease_error_envelope(error: LeaseError) -> ErrorEnvelope {
    match error {
        LeaseError::PermissionDenied => ErrorEnvelope::new(
            ErrorCode::ClipboardPermissionDenied,
            UserMessage::ClipboardPermissionRequired,
            false,
        ),
        LeaseError::WriteFailed | LeaseError::ClearFailed => ErrorEnvelope::new(
            ErrorCode::ClipboardUnavailable,
            UserMessage::ClipboardTemporarilyUnavailable,
            true,
        ),
        LeaseError::InvalidDuration | LeaseError::IdentityExhausted => ErrorEnvelope::new(
            ErrorCode::ClipboardUnavailable,
            UserMessage::ClipboardTemporarilyUnavailable,
            false,
        ),
        LeaseError::AtomicCompareAndClearUnavailable => ErrorEnvelope::new(
            ErrorCode::ClipboardAtomicClearUnavailable,
            UserMessage::ClipboardAtomicClearUnavailable,
            false,
        ),
    }
}

fn expiry_failure_event(error: LeaseError) -> ClipboardLeaseEvent {
    let (code, message, retryable) = match error {
        LeaseError::PermissionDenied => (
            ClipboardDegradedCode::PermissionDenied,
            EXPIRY_PERMISSION_DENIED_MESSAGE,
            false,
        ),
        LeaseError::ClearFailed => (
            ClipboardDegradedCode::ClearFailed,
            EXPIRY_CLEAR_FAILED_MESSAGE,
            true,
        ),
        LeaseError::AtomicCompareAndClearUnavailable => (
            ClipboardDegradedCode::AtomicCompareAndClearUnavailable,
            EXPIRY_UNAVAILABLE_MESSAGE,
            false,
        ),
        LeaseError::WriteFailed | LeaseError::InvalidDuration | LeaseError::IdentityExhausted => (
            ClipboardDegradedCode::ClearFailed,
            EXPIRY_CLEAR_FAILED_MESSAGE,
            false,
        ),
    };
    ClipboardLeaseEvent::Degraded {
        code,
        message: message.to_owned(),
        retryable,
    }
}

fn actor_unavailable() -> ErrorEnvelope {
    ErrorEnvelope::new(
        ErrorCode::ClipboardUnavailable,
        UserMessage::ClipboardTemporarilyUnavailable,
        true,
    )
    .with_internal_detail("clipboard actor unavailable")
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        pin::Pin,
        sync::{
            atomic::{AtomicI64, AtomicUsize, Ordering},
            Arc, Mutex,
        },
        task::{Context, Poll},
    };

    use otpbar::{
        clock::Sleep,
        domain::error::ErrorEnvelope,
        ports::{Clipboard, ClipboardClearOutcome},
    };

    use super::*;

    #[derive(Clone, Default)]
    struct FakeClock {
        milliseconds: Arc<AtomicI64>,
        canceled_sleeps: Arc<AtomicUsize>,
    }

    impl FakeClock {
        fn advance(&self, duration: Duration) {
            self.milliseconds.fetch_add(
                i64::try_from(duration.as_millis()).expect("test duration fits"),
                Ordering::SeqCst,
            );
        }

        fn canceled_sleeps(&self) -> usize {
            self.canceled_sleeps.load(Ordering::SeqCst)
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Timestamp {
            Timestamp::from_unix_millis(self.milliseconds.load(Ordering::SeqCst))
        }

        fn sleep(&self, duration: Duration) -> Sleep<'_> {
            Box::pin(TrackedSleep {
                sleep: Box::pin(tokio::time::sleep(duration)),
                canceled_sleeps: self.canceled_sleeps.clone(),
                completed: false,
            })
        }
    }

    struct TrackedSleep {
        sleep: Pin<Box<tokio::time::Sleep>>,
        canceled_sleeps: Arc<AtomicUsize>,
        completed: bool,
    }

    impl Future for TrackedSleep {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
            match self.sleep.as_mut().poll(context) {
                Poll::Ready(()) => {
                    self.completed = true;
                    Poll::Ready(())
                }
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl Drop for TrackedSleep {
        fn drop(&mut self) {
            if !self.completed {
                self.canceled_sleeps.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    #[derive(Default)]
    struct ClipboardState {
        value: Option<String>,
        clears: usize,
        fail_write: bool,
        fail_clear: bool,
        deny_clear: bool,
        atomic_clear_unavailable: bool,
    }

    #[derive(Clone, Default)]
    struct FakeClipboard {
        state: Arc<Mutex<ClipboardState>>,
    }

    impl FakeClipboard {
        fn value(&self) -> Option<String> {
            self.state.lock().expect("clipboard lock").value.clone()
        }

        fn replace_externally(&self, value: &str) {
            self.state.lock().expect("clipboard lock").value = Some(value.to_owned());
        }

        fn fail_clear(&self) {
            self.state.lock().expect("clipboard lock").fail_clear = true;
        }

        fn deny_clear(&self) {
            self.state.lock().expect("clipboard lock").deny_clear = true;
        }

        fn block_atomic_clear(&self) {
            self.state
                .lock()
                .expect("clipboard lock")
                .atomic_clear_unavailable = true;
        }

        fn fail_write(&self) {
            self.state.lock().expect("clipboard lock").fail_write = true;
        }

        fn clears(&self) -> usize {
            self.state.lock().expect("clipboard lock").clears
        }
    }

    impl Clipboard for FakeClipboard {
        fn read_text(&self) -> Result<Option<String>, ErrorEnvelope> {
            Ok(self.value())
        }

        fn write_text(&mut self, value: &str) -> Result<(), ErrorEnvelope> {
            let mut state = self.state.lock().expect("clipboard lock");
            if state.fail_write {
                return Err(actor_unavailable());
            }
            state.value = Some(value.to_owned());
            Ok(())
        }

        fn clear_if_text(
            &mut self,
            expected: &str,
        ) -> Result<ClipboardClearOutcome, ErrorEnvelope> {
            let mut state = self.state.lock().expect("clipboard lock");
            if state.deny_clear {
                return Err(ErrorEnvelope::new(
                    ErrorCode::ClipboardPermissionDenied,
                    UserMessage::ClipboardPermissionRequired,
                    false,
                ));
            }
            if state.atomic_clear_unavailable {
                return Err(ErrorEnvelope::new(
                    ErrorCode::ClipboardAtomicClearUnavailable,
                    UserMessage::ClipboardAtomicClearUnavailable,
                    false,
                ));
            }
            if state.fail_clear {
                return Err(actor_unavailable());
            }
            if state.value.as_deref() == Some(expected) {
                state.value = None;
                state.clears += 1;
                Ok(ClipboardClearOutcome::Cleared)
            } else {
                Ok(ClipboardClearOutcome::Changed)
            }
        }
    }

    #[derive(Clone, Default)]
    struct MemoryEvents {
        events: Arc<Mutex<Vec<ClipboardLeaseEvent>>>,
    }

    impl MemoryEvents {
        fn snapshot(&self) -> Vec<ClipboardLeaseEvent> {
            self.events.lock().expect("events lock").clone()
        }
    }

    impl LeaseEventSink for MemoryEvents {
        fn publish(&self, event: ClipboardLeaseEvent) {
            self.events.lock().expect("events lock").push(event);
        }
    }

    async fn elapse(clock: &FakeClock, duration: Duration) {
        clock.advance(duration);
        tokio::time::advance(duration).await;
        tokio::task::yield_now().await;
    }

    #[tokio::test(start_paused = true)]
    async fn replacement_cancels_the_prior_timer_and_only_expires_the_new_value() {
        let clipboard = FakeClipboard::default();
        let clock = FakeClock::default();
        let events = MemoryEvents::default();
        let actor = spawn_clipboard_actor(clipboard.clone(), clock.clone(), events);

        actor
            .copy("111111".to_owned(), LeaseDuration::FifteenSeconds)
            .await
            .expect("first copy");
        elapse(&clock, Duration::from_secs(5)).await;
        actor
            .copy("222222".to_owned(), LeaseDuration::ThirtySeconds)
            .await
            .expect("replacement copy");
        tokio::task::yield_now().await;

        assert_eq!(clock.canceled_sleeps(), 1);
        elapse(&clock, Duration::from_secs(10)).await;
        assert_eq!(clipboard.value().as_deref(), Some("222222"));
        assert_eq!(clipboard.clears(), 0);

        elapse(&clock, Duration::from_secs(20)).await;
        assert_eq!(clipboard.value(), None);
        assert_eq!(clipboard.clears(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn queued_stale_expiry_cannot_cancel_the_replacement_timer() {
        let clipboard = FakeClipboard::default();
        let clock = FakeClock::default();
        let actor =
            spawn_clipboard_actor(clipboard.clone(), clock.clone(), MemoryEvents::default());

        actor
            .copy("121212".to_owned(), LeaseDuration::FifteenSeconds)
            .await
            .expect("first copy");
        actor
            .copy("232323".to_owned(), LeaseDuration::ThirtySeconds)
            .await
            .expect("replacement copy");

        // A separate lease owner yields the same first process-local LeaseId,
        // letting the test inject the old timer message after replacement.
        let mut receipt_source = ClipboardLease::new();
        let mut receipt_clipboard = FakeClipboard::default();
        let stale_receipt = receipt_source
            .copy(
                &mut receipt_clipboard,
                "old",
                LeaseDuration::FifteenSeconds,
                Timestamp::from_unix_millis(0),
            )
            .expect("stale receipt");
        actor
            .requests
            .send(Request::Expire {
                receipt: stale_receipt,
            })
            .await
            .expect("inject stale expiry");
        tokio::task::yield_now().await;

        elapse(&clock, Duration::from_secs(30)).await;
        assert_eq!(clipboard.value(), None);
        assert_eq!(clipboard.clears(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn external_change_publishes_ownership_lost_without_mutation() {
        let clipboard = FakeClipboard::default();
        let clock = FakeClock::default();
        let events = MemoryEvents::default();
        let actor = spawn_clipboard_actor(clipboard.clone(), clock.clone(), events.clone());

        actor
            .copy("333333".to_owned(), LeaseDuration::FifteenSeconds)
            .await
            .expect("copy");
        clipboard.replace_externally("unrelated");
        elapse(&clock, Duration::from_secs(15)).await;

        assert_eq!(clipboard.value().as_deref(), Some("unrelated"));
        assert_eq!(clipboard.clears(), 0);
        assert!(events.snapshot().contains(&ClipboardLeaseEvent::Idle {
            reason: ClipboardIdleReason::OwnershipLost,
        }));
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_rechecks_authoritative_wall_time_after_the_timer_fires() {
        let clipboard = FakeClipboard::default();
        let clock = FakeClock::default();
        let actor =
            spawn_clipboard_actor(clipboard.clone(), clock.clone(), MemoryEvents::default());

        actor
            .copy("343434".to_owned(), LeaseDuration::FifteenSeconds)
            .await
            .expect("copy");

        tokio::time::advance(Duration::from_secs(15)).await;
        tokio::task::yield_now().await;
        assert_eq!(clipboard.value().as_deref(), Some("343434"));
        assert_eq!(clipboard.clears(), 0);

        elapse(&clock, Duration::from_secs(15)).await;
        assert_eq!(clipboard.value(), None);
        assert_eq!(clipboard.clears(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn ordinary_clear_failure_is_retryable_and_not_misclassified() {
        let clipboard = FakeClipboard::default();
        clipboard.fail_clear();
        let clock = FakeClock::default();
        let events = MemoryEvents::default();
        let actor = spawn_clipboard_actor(clipboard.clone(), clock.clone(), events.clone());

        actor
            .copy("444444".to_owned(), LeaseDuration::FifteenSeconds)
            .await
            .expect("copy");
        elapse(&clock, Duration::from_secs(15)).await;

        assert_eq!(clipboard.value().as_deref(), Some("444444"));
        let serialized = serde_json::to_string(&events.snapshot()).expect("events serialize");
        assert!(serialized.contains("\"code\":\"clear_failed\""));
        assert!(serialized.contains("\"retryable\":true"));
        assert!(serialized.contains("left unchanged"));
        assert!(!serialized.contains("atomic_compare_and_clear_unavailable"));
        assert!(!serialized.contains("444444"));
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_permission_denial_has_its_own_non_retryable_status() {
        let clipboard = FakeClipboard::default();
        clipboard.deny_clear();
        let clock = FakeClock::default();
        let events = MemoryEvents::default();
        let actor = spawn_clipboard_actor(clipboard.clone(), clock.clone(), events.clone());

        actor
            .copy("454545".to_owned(), LeaseDuration::FifteenSeconds)
            .await
            .expect("copy");
        elapse(&clock, Duration::from_secs(15)).await;

        let serialized = serde_json::to_string(&events.snapshot()).expect("events serialize");
        assert!(serialized.contains("\"code\":\"permission_denied\""));
        assert!(serialized.contains("\"retryable\":false"));
        assert!(!serialized.contains("atomic_compare_and_clear_unavailable"));
        assert!(!serialized.contains("454545"));
    }

    #[tokio::test(start_paused = true)]
    async fn atomic_clear_limitation_has_exact_safe_degraded_status() {
        let clipboard = FakeClipboard::default();
        clipboard.block_atomic_clear();
        let clock = FakeClock::default();
        let events = MemoryEvents::default();
        let actor = spawn_clipboard_actor(clipboard.clone(), clock.clone(), events.clone());

        actor
            .copy("464646".to_owned(), LeaseDuration::FifteenSeconds)
            .await
            .expect("copy");
        elapse(&clock, Duration::from_secs(15)).await;

        assert_eq!(clipboard.value().as_deref(), Some("464646"));
        let serialized = serde_json::to_string(&events.snapshot()).expect("events serialize");
        assert!(serialized.contains("\"code\":\"atomic_compare_and_clear_unavailable\""));
        assert!(serialized.contains("atomic ownership verification is unavailable"));
        assert!(serialized.contains("\"retryable\":false"));
        assert!(!serialized.contains("464646"));
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_aborts_the_timer_and_never_touches_clipboard_content() {
        let clipboard = FakeClipboard::default();
        let clock = FakeClock::default();
        let events = MemoryEvents::default();
        let actor = spawn_clipboard_actor(clipboard.clone(), clock.clone(), events.clone());

        actor
            .copy("555555".to_owned(), LeaseDuration::FifteenSeconds)
            .await
            .expect("copy");
        actor.shutdown().await;
        elapse(&clock, Duration::from_secs(60)).await;

        assert_eq!(clipboard.value().as_deref(), Some("555555"));
        assert_eq!(clipboard.clears(), 0);
        assert!(events.snapshot().contains(&ClipboardLeaseEvent::Idle {
            reason: ClipboardIdleReason::Shutdown,
        }));
        let error = actor
            .copy("ignored".to_owned(), LeaseDuration::FifteenSeconds)
            .await
            .expect_err("stopped actor rejects new work");
        assert_eq!(error.code(), ErrorCode::ClipboardUnavailable);
    }

    #[tokio::test]
    async fn copy_failures_return_only_a_safe_typed_error() {
        let clipboard = FakeClipboard::default();
        clipboard.fail_write();
        let actor = spawn_clipboard_actor(clipboard, FakeClock::default(), MemoryEvents::default());

        let error = actor
            .copy("666666".to_owned(), LeaseDuration::ThirtySeconds)
            .await
            .expect_err("write fails");
        let serialized = serde_json::to_string(&error).expect("error serializes");
        assert!(serialized.contains("clipboard_unavailable"));
        assert!(!serialized.contains("666666"));
        assert!(!serialized.contains("clipboard actor unavailable"));
    }
}
