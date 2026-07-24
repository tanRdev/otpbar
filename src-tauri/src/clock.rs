use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Boxed wait returned by an injectable clock.
pub type Sleep<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// A persisted UTC instant represented as Unix epoch milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(i64);

impl Timestamp {
    /// Creates a timestamp from Unix epoch milliseconds.
    pub const fn from_unix_millis(milliseconds: i64) -> Self {
        Self(milliseconds)
    }

    /// Converts system time to signed Unix epoch milliseconds, saturating at
    /// the representable timestamp bounds.
    pub fn from_system_time(time: SystemTime) -> Self {
        match time.duration_since(UNIX_EPOCH) {
            Ok(duration) => {
                let milliseconds = i64::try_from(duration.as_millis()).unwrap_or(i64::MAX);
                Self(milliseconds)
            }
            Err(error) => {
                let milliseconds = error.duration().as_nanos().div_ceil(1_000_000);
                let minimum_magnitude = (i64::MAX as u128) + 1;
                if milliseconds >= minimum_magnitude {
                    Self(i64::MIN)
                } else {
                    Self(-(milliseconds as i64))
                }
            }
        }
    }

    /// Returns this timestamp as Unix epoch milliseconds.
    pub const fn unix_millis(self) -> i64 {
        self.0
    }

    /// Adds a duration, returning `None` if milliseconds cannot be represented.
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        let milliseconds = i64::try_from(duration.as_millis()).ok()?;
        self.0.checked_add(milliseconds).map(Self)
    }
}

/// Injectable wall-time and monotonic-wait boundary.
pub trait Clock: Send + Sync {
    /// Returns the current UTC wall-clock timestamp.
    fn now(&self) -> Timestamp;

    /// Waits using a monotonic timer.
    fn sleep(&self, duration: Duration) -> Sleep<'_>;
}

/// Production clock backed by system UTC and Tokio's monotonic timer.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_system_time(SystemTime::now())
    }

    fn sleep(&self, duration: Duration) -> Sleep<'_> {
        Box::pin(tokio::time::sleep(duration))
    }
}
