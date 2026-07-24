use std::time::Duration;

#[tokio::test(start_paused = true)]
async fn paused_clock_advances_without_waiting_in_real_time() {
    let started = tokio::time::Instant::now();

    tokio::time::advance(Duration::from_secs(30)).await;

    assert_eq!(started.elapsed(), Duration::from_secs(30));
}
