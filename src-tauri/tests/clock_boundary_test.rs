use std::sync::Mutex;
use std::time::Duration;

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
