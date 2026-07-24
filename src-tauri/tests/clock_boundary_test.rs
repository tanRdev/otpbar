use std::sync::Mutex;
use std::time::{Duration, UNIX_EPOCH};

use otpbar::clock::{Clock, Sleep, Timestamp};

struct FakeClock {
    now: Mutex<Timestamp>,
}

impl FakeClock {
    fn at(timestamp: Timestamp) -> Self {
        Self {
            now: Mutex::new(timestamp),
        }
    }

    fn advance(&self, duration: Duration) {
        let mut now = self.now.lock().expect("fake clock lock should be healthy");
        *now = now
            .checked_add(duration)
            .expect("test duration should fit a timestamp");
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Timestamp {
        *self.now.lock().expect("fake clock lock should be healthy")
    }

    fn sleep(&self, _duration: Duration) -> Sleep<'_> {
        Box::pin(std::future::ready(()))
    }
}

#[tokio::test]
async fn domain_time_is_injectable_without_waiting_for_wall_time() {
    let clock = FakeClock::at(Timestamp::from_unix_millis(1_000));

    clock.sleep(Duration::from_secs(30)).await;
    clock.advance(Duration::from_secs(30));

    assert_eq!(clock.now().unix_millis(), 31_000);
}

#[test]
fn system_time_before_unix_epoch_preserves_its_negative_timestamp() {
    let before_epoch = UNIX_EPOCH
        .checked_sub(Duration::from_millis(1_500))
        .expect("test platform should represent a pre-epoch instant");

    let timestamp = Timestamp::from_system_time(before_epoch);

    assert_eq!(timestamp.unix_millis(), -1_500);
}

#[test]
fn submillisecond_time_before_epoch_rounds_down_to_negative_one() {
    let just_before_epoch = UNIX_EPOCH
        .checked_sub(Duration::from_nanos(1))
        .expect("test platform should represent a pre-epoch instant");

    let timestamp = Timestamp::from_system_time(just_before_epoch);

    assert_eq!(timestamp.unix_millis(), -1);
}

#[test]
fn system_time_after_timestamp_range_clamps_to_maximum() {
    let beyond_maximum = UNIX_EPOCH
        .checked_add(Duration::from_millis((i64::MAX as u64) + 1))
        .expect("test platform should represent an instant beyond Timestamp");

    let timestamp = Timestamp::from_system_time(beyond_maximum);

    assert_eq!(timestamp.unix_millis(), i64::MAX);
}

#[test]
fn system_time_before_timestamp_range_clamps_to_minimum() {
    let minimum = UNIX_EPOCH
        .checked_sub(Duration::from_millis((i64::MAX as u64) + 1))
        .expect("test platform should represent Timestamp minimum");
    let beyond_minimum = minimum
        .checked_sub(Duration::from_millis(1))
        .expect("test platform should represent an instant beyond Timestamp");

    assert_eq!(Timestamp::from_system_time(minimum).unix_millis(), i64::MIN);
    assert_eq!(
        Timestamp::from_system_time(beyond_minimum).unix_millis(),
        i64::MIN
    );
}
