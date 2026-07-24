use std::time::Duration;

use otpbar::polling::wait_for_poll_tick;

#[tokio::test(start_paused = true)]
async fn poll_tick_waits_for_the_configured_interval() {
    let started = tokio::time::Instant::now();

    wait_for_poll_tick(Duration::from_secs(30)).await;

    assert_eq!(started.elapsed(), Duration::from_secs(30));
}
