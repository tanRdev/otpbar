use std::fmt;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::clock::Timestamp;
use crate::domain::error::ErrorCode;
use crate::ports::{Clipboard, ClipboardClearOutcome};

/// Opaque identity used to make stale expiry tasks harmless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LeaseId(u64);

/// Non-secret result returned after a successful copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyReceipt {
    /// Identity that the scheduled expiry must present.
    pub lease_id: LeaseId,
    /// Wall-clock projection for UI countdowns. Ownership checks remain authoritative.
    pub expires_at: Timestamp,
}

/// Product-approved clipboard expiry durations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LeaseDuration {
    /// Fifteen seconds.
    FifteenSeconds,
    /// Thirty seconds, the product default.
    #[default]
    ThirtySeconds,
    /// Sixty seconds.
    SixtySeconds,
}

impl LeaseDuration {
    fn as_duration(self) -> Duration {
        Duration::from_secs(match self {
            Self::FifteenSeconds => 15,
            Self::ThirtySeconds => 30,
            Self::SixtySeconds => 60,
        })
    }
}

impl TryFrom<Duration> for LeaseDuration {
    type Error = LeaseError;

    fn try_from(value: Duration) -> Result<Self, Self::Error> {
        match value.as_secs() {
            15 if value.subsec_nanos() == 0 => Ok(Self::FifteenSeconds),
            30 if value.subsec_nanos() == 0 => Ok(Self::ThirtySeconds),
            60 if value.subsec_nanos() == 0 => Ok(Self::SixtySeconds),
            _ => Err(LeaseError::InvalidDuration),
        }
    }
}

/// Current authoritative lease state. Clipboard contents are deliberately absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseStatus {
    /// OTPBar owns no clipboard lease.
    Idle,
    /// OTPBar most recently wrote a value and has not observed ownership loss.
    Owned {
        /// Active lease identity.
        lease_id: LeaseId,
        /// Projected expiry timestamp.
        expires_at: Timestamp,
    },
}

/// Safe failure categories for clipboard lease operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseError {
    /// The platform denied clipboard access.
    PermissionDenied,
    /// A clipboard write failed.
    WriteFailed,
    /// Clearing an owned value failed.
    ClearFailed,
    /// The platform cannot atomically compare and clear clipboard text.
    AtomicCompareAndClearUnavailable,
    /// The expiry instant cannot be represented.
    InvalidDuration,
    /// No further unique identities can be issued in this process.
    IdentityExhausted,
}

/// Observable result of expiry, cancellation, or shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseTransition {
    /// The referenced lease is no longer active; no clipboard I/O occurred.
    Superseded,
    /// The active lease has not reached its expiry; no clipboard I/O occurred.
    NotYetExpired,
    /// The active value was still owned and was cleared.
    ExpiredAndCleared,
    /// Another app replaced the clipboard; OTPBar did not mutate it.
    OwnershipLost,
    /// The timer was canceled without changing clipboard contents.
    Canceled,
    /// Clipboard I/O failed; ownership is relinquished conservatively.
    Failed(LeaseError),
}

struct ActiveLease {
    id: LeaseId,
    value: Zeroizing<String>,
    expires_at: Timestamp,
}

impl fmt::Debug for ActiveLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActiveLease")
            .field("id", &self.id)
            .field("value", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Owns at most one clipboard lease and rejects all stale timers.
#[derive(Debug, Default)]
pub struct ClipboardLease {
    active: Option<ActiveLease>,
    last_id: u64,
}

impl ClipboardLease {
    /// Creates an idle lease owner.
    pub const fn new() -> Self {
        Self {
            active: None,
            last_id: 0,
        }
    }

    /// Writes a value and atomically replaces lease ownership after the write succeeds.
    pub fn copy(
        &mut self,
        clipboard: &mut impl Clipboard,
        value: &str,
        duration: LeaseDuration,
        now: Timestamp,
    ) -> Result<CopyReceipt, LeaseError> {
        let expires_at = now
            .checked_add(duration.as_duration())
            .ok_or(LeaseError::InvalidDuration)?;
        let next_id = self
            .last_id
            .checked_add(1)
            .ok_or(LeaseError::IdentityExhausted)?;
        // A platform write may mutate and still return an error. Relinquish the
        // previous claim before crossing that indeterminate boundary.
        self.active = None;
        clipboard.write_text(value).map_err(map_write_error)?;

        let lease_id = LeaseId(next_id);
        self.last_id = next_id;
        self.active = Some(ActiveLease {
            id: lease_id,
            value: Zeroizing::new(value.to_owned()),
            expires_at,
        });
        Ok(CopyReceipt {
            lease_id,
            expires_at,
        })
    }

    /// Returns the current non-secret state.
    pub fn status(&self) -> LeaseStatus {
        match self.active.as_ref() {
            Some(active) => LeaseStatus::Owned {
                lease_id: active.id,
                expires_at: active.expires_at,
            },
            None => LeaseStatus::Idle,
        }
    }

    /// Handles a scheduled expiry, clearing only the still-active exact value.
    pub fn expire(
        &mut self,
        lease_id: LeaseId,
        now: Timestamp,
        clipboard: &mut impl Clipboard,
    ) -> LeaseTransition {
        let Some(active) = self.active.as_ref() else {
            return LeaseTransition::Superseded;
        };
        if active.id != lease_id {
            return LeaseTransition::Superseded;
        }
        if now < active.expires_at {
            return LeaseTransition::NotYetExpired;
        }

        match clipboard.clear_if_text(active.value.as_str()) {
            Ok(ClipboardClearOutcome::Cleared) => {
                self.active = None;
                LeaseTransition::ExpiredAndCleared
            }
            Ok(ClipboardClearOutcome::Changed) => {
                self.active = None;
                LeaseTransition::OwnershipLost
            }
            Err(error) => {
                self.active = None;
                LeaseTransition::Failed(map_clear_error(&error))
            }
        }
    }

    /// Cancels the active timer without mutating clipboard content.
    pub fn cancel(&mut self) -> LeaseTransition {
        self.active = None;
        LeaseTransition::Canceled
    }

    /// Performs the same exact ownership check during orderly shutdown.
    pub fn shutdown(&mut self, clipboard: &mut impl Clipboard) -> LeaseTransition {
        let Some((lease_id, expires_at)) = self
            .active
            .as_ref()
            .map(|active| (active.id, active.expires_at))
        else {
            return LeaseTransition::Canceled;
        };
        self.expire(lease_id, expires_at, clipboard)
    }
}

fn permission_denied(error: &crate::domain::error::ErrorEnvelope) -> bool {
    error.code() == ErrorCode::ClipboardPermissionDenied
}

fn map_write_error(error: crate::domain::error::ErrorEnvelope) -> LeaseError {
    if permission_denied(&error) {
        LeaseError::PermissionDenied
    } else {
        LeaseError::WriteFailed
    }
}

fn map_clear_error(error: &crate::domain::error::ErrorEnvelope) -> LeaseError {
    match error.code() {
        ErrorCode::ClipboardPermissionDenied => LeaseError::PermissionDenied,
        ErrorCode::ClipboardAtomicClearUnavailable => LeaseError::AtomicCompareAndClearUnavailable,
        ErrorCode::StorageUnavailable | ErrorCode::ClipboardUnavailable => LeaseError::ClearFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::{ErrorCode, ErrorEnvelope, UserMessage};
    use crate::ports::Clipboard;
    use std::time::Duration;

    #[derive(Default)]
    struct FakeClipboard {
        value: Option<String>,
        clears: usize,
        fail_write: bool,
        fail_clear: bool,
        deny_write: bool,
        deny_clear: bool,
        mutate_then_fail_write: bool,
        mutate_then_fail_clear: bool,
        atomic_clear_unavailable: bool,
    }

    impl Clipboard for FakeClipboard {
        fn read_text(&self) -> Result<Option<String>, ErrorEnvelope> {
            Ok(self.value.clone())
        }

        fn write_text(&mut self, value: &str) -> Result<(), ErrorEnvelope> {
            if self.deny_write {
                return Err(permission_error());
            }
            if self.mutate_then_fail_write {
                self.value = Some(value.to_owned());
                return Err(storage_error());
            }
            if self.fail_write {
                return Err(storage_error());
            }
            self.value = Some(value.to_owned());
            Ok(())
        }

        fn clear_if_text(
            &mut self,
            expected: &str,
        ) -> Result<ClipboardClearOutcome, ErrorEnvelope> {
            if self.deny_clear {
                return Err(permission_error());
            }
            if self.atomic_clear_unavailable {
                return Err(atomic_clear_error());
            }
            if self.mutate_then_fail_clear {
                self.value = None;
                return Err(storage_error());
            }
            if self.fail_clear {
                return Err(storage_error());
            }
            if self.value.as_deref() == Some(expected) {
                self.value = None;
                self.clears += 1;
                Ok(ClipboardClearOutcome::Cleared)
            } else {
                Ok(ClipboardClearOutcome::Changed)
            }
        }
    }

    fn storage_error() -> ErrorEnvelope {
        ErrorEnvelope::new(
            ErrorCode::StorageUnavailable,
            UserMessage::LocalDataUnavailable,
            true,
        )
    }

    fn permission_error() -> ErrorEnvelope {
        ErrorEnvelope::new(
            ErrorCode::ClipboardPermissionDenied,
            UserMessage::ClipboardPermissionRequired,
            false,
        )
    }

    fn atomic_clear_error() -> ErrorEnvelope {
        ErrorEnvelope::new(
            ErrorCode::ClipboardAtomicClearUnavailable,
            UserMessage::ClipboardAtomicClearUnavailable,
            false,
        )
    }

    #[test]
    fn replacing_a_lease_makes_the_old_expiry_inert() {
        let mut clipboard = FakeClipboard::default();
        let mut leases = ClipboardLease::new();
        let first = leases
            .copy(
                &mut clipboard,
                "111111",
                LeaseDuration::ThirtySeconds,
                Timestamp::from_unix_millis(0),
            )
            .expect("first copy");
        let second = leases
            .copy(
                &mut clipboard,
                "222222",
                LeaseDuration::ThirtySeconds,
                Timestamp::from_unix_millis(1_000),
            )
            .expect("replacement copy");

        assert_eq!(
            leases.expire(
                first.lease_id,
                Timestamp::from_unix_millis(30_000),
                &mut clipboard,
            ),
            LeaseTransition::Superseded
        );
        assert_eq!(clipboard.value.as_deref(), Some("222222"));
        assert_eq!(clipboard.clears, 0);
        assert_ne!(first.lease_id, second.lease_id);
    }

    #[test]
    fn external_change_loses_ownership_without_mutating_clipboard() {
        let mut clipboard = FakeClipboard::default();
        let mut leases = ClipboardLease::new();
        let copy = leases
            .copy(
                &mut clipboard,
                "111111",
                LeaseDuration::ThirtySeconds,
                Timestamp::from_unix_millis(0),
            )
            .expect("copy");
        clipboard.value = Some("someone else's value".to_owned());

        assert_eq!(
            leases.expire(
                copy.lease_id,
                Timestamp::from_unix_millis(30_000),
                &mut clipboard,
            ),
            LeaseTransition::OwnershipLost
        );
        assert_eq!(clipboard.value.as_deref(), Some("someone else's value"));
        assert_eq!(clipboard.clears, 0);
        assert_eq!(leases.status(), LeaseStatus::Idle);
    }

    #[test]
    fn matching_active_lease_clears_exactly_once() {
        let mut clipboard = FakeClipboard::default();
        let mut leases = ClipboardLease::new();
        let copy = leases
            .copy(
                &mut clipboard,
                "111111",
                LeaseDuration::ThirtySeconds,
                Timestamp::from_unix_millis(0),
            )
            .expect("copy");

        assert_eq!(
            leases.expire(
                copy.lease_id,
                Timestamp::from_unix_millis(30_000),
                &mut clipboard,
            ),
            LeaseTransition::ExpiredAndCleared
        );
        assert_eq!(
            leases.expire(
                copy.lease_id,
                Timestamp::from_unix_millis(30_000),
                &mut clipboard,
            ),
            LeaseTransition::Superseded
        );
        assert_eq!(clipboard.clears, 1);
    }

    #[test]
    fn clipboard_failures_are_typed_and_never_claim_success() {
        let mut clipboard = FakeClipboard {
            fail_write: true,
            ..FakeClipboard::default()
        };
        let mut leases = ClipboardLease::new();
        assert_eq!(
            leases.copy(
                &mut clipboard,
                "111111",
                LeaseDuration::ThirtySeconds,
                Timestamp::from_unix_millis(0),
            ),
            Err(LeaseError::WriteFailed)
        );
        assert_eq!(leases.status(), LeaseStatus::Idle);

        clipboard.fail_write = false;
        let copy = leases
            .copy(
                &mut clipboard,
                "111111",
                LeaseDuration::ThirtySeconds,
                Timestamp::from_unix_millis(0),
            )
            .expect("copy");
        clipboard.fail_clear = true;
        assert_eq!(
            leases.expire(
                copy.lease_id,
                Timestamp::from_unix_millis(30_000),
                &mut clipboard,
            ),
            LeaseTransition::Failed(LeaseError::ClearFailed)
        );
        assert_eq!(leases.status(), LeaseStatus::Idle);
    }

    #[test]
    fn shutdown_only_clears_content_still_owned_by_the_active_lease() {
        let mut clipboard = FakeClipboard::default();
        let mut leases = ClipboardLease::new();
        leases
            .copy(
                &mut clipboard,
                "111111",
                LeaseDuration::ThirtySeconds,
                Timestamp::from_unix_millis(0),
            )
            .expect("copy");
        clipboard.value = Some("replacement".to_owned());
        assert_eq!(
            leases.shutdown(&mut clipboard),
            LeaseTransition::OwnershipLost
        );
        assert_eq!(clipboard.value.as_deref(), Some("replacement"));
    }

    #[test]
    fn only_product_approved_durations_can_be_constructed() {
        assert_eq!(
            LeaseDuration::try_from(Duration::from_secs(15)),
            Ok(LeaseDuration::FifteenSeconds)
        );
        assert_eq!(
            LeaseDuration::try_from(Duration::from_secs(30)),
            Ok(LeaseDuration::ThirtySeconds)
        );
        assert_eq!(
            LeaseDuration::try_from(Duration::from_secs(60)),
            Ok(LeaseDuration::SixtySeconds)
        );
        assert_eq!(
            LeaseDuration::try_from(Duration::from_secs(1)),
            Err(LeaseError::InvalidDuration)
        );
    }

    #[test]
    fn indeterminate_failed_write_relinquishes_prior_ownership() {
        let mut clipboard = FakeClipboard::default();
        let mut leases = ClipboardLease::new();
        leases
            .copy(
                &mut clipboard,
                "111111",
                LeaseDuration::ThirtySeconds,
                Timestamp::from_unix_millis(0),
            )
            .expect("first copy");
        clipboard.mutate_then_fail_write = true;

        assert_eq!(
            leases.copy(
                &mut clipboard,
                "222222",
                LeaseDuration::ThirtySeconds,
                Timestamp::from_unix_millis(1_000),
            ),
            Err(LeaseError::WriteFailed)
        );
        assert_eq!(leases.status(), LeaseStatus::Idle);
    }

    #[test]
    fn early_expiry_is_inert_until_the_authoritative_deadline() {
        let mut clipboard = FakeClipboard::default();
        let mut leases = ClipboardLease::new();
        let copy = leases
            .copy(
                &mut clipboard,
                "111111",
                LeaseDuration::ThirtySeconds,
                Timestamp::from_unix_millis(0),
            )
            .expect("copy");

        assert_eq!(
            leases.expire(
                copy.lease_id,
                Timestamp::from_unix_millis(29_999),
                &mut clipboard,
            ),
            LeaseTransition::NotYetExpired
        );
        assert_eq!(clipboard.value.as_deref(), Some("111111"));
        assert!(matches!(leases.status(), LeaseStatus::Owned { .. }));
    }

    #[test]
    fn indeterminate_clear_failure_relinquishes_ownership() {
        let mut clipboard = FakeClipboard::default();
        let mut leases = ClipboardLease::new();
        let copy = leases
            .copy(
                &mut clipboard,
                "111111",
                LeaseDuration::ThirtySeconds,
                Timestamp::from_unix_millis(0),
            )
            .expect("copy");
        clipboard.mutate_then_fail_clear = true;

        assert_eq!(
            leases.expire(
                copy.lease_id,
                Timestamp::from_unix_millis(30_000),
                &mut clipboard,
            ),
            LeaseTransition::Failed(LeaseError::ClearFailed)
        );
        assert_eq!(leases.status(), LeaseStatus::Idle);
    }

    #[test]
    fn permission_denial_is_distinct_for_write_and_clear() {
        let mut clipboard = FakeClipboard {
            deny_write: true,
            ..FakeClipboard::default()
        };
        let mut leases = ClipboardLease::new();
        assert_eq!(
            leases.copy(
                &mut clipboard,
                "111111",
                LeaseDuration::ThirtySeconds,
                Timestamp::from_unix_millis(0),
            ),
            Err(LeaseError::PermissionDenied)
        );

        clipboard.deny_write = false;
        let copy = leases
            .copy(
                &mut clipboard,
                "111111",
                LeaseDuration::ThirtySeconds,
                Timestamp::from_unix_millis(0),
            )
            .expect("copy");
        clipboard.deny_clear = true;
        assert_eq!(
            leases.expire(
                copy.lease_id,
                Timestamp::from_unix_millis(30_000),
                &mut clipboard,
            ),
            LeaseTransition::Failed(LeaseError::PermissionDenied)
        );
        assert_eq!(leases.status(), LeaseStatus::Idle);
    }

    #[test]
    fn atomic_compare_and_clear_unavailability_is_preserved() {
        let mut clipboard = FakeClipboard::default();
        let mut leases = ClipboardLease::new();
        let copy = leases
            .copy(
                &mut clipboard,
                "111111",
                LeaseDuration::ThirtySeconds,
                Timestamp::from_unix_millis(0),
            )
            .expect("copy");
        clipboard.atomic_clear_unavailable = true;

        assert_eq!(
            leases.expire(
                copy.lease_id,
                Timestamp::from_unix_millis(30_000),
                &mut clipboard,
            ),
            LeaseTransition::Failed(LeaseError::AtomicCompareAndClearUnavailable)
        );
        assert_eq!(leases.status(), LeaseStatus::Idle);
    }
}
