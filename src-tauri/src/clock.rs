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
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        let milliseconds = i64::try_from(duration.as_millis()).unwrap_or(i64::MAX);
        Timestamp::from_unix_millis(milliseconds)
    }

    fn sleep(&self, duration: Duration) -> Sleep<'_> {
        Box::pin(tokio::time::sleep(duration))
    }
}
