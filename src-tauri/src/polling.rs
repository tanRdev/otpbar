use std::time::Duration;

/// Waits until the next configured Gmail polling tick.
pub async fn wait_for_poll_tick(interval: Duration) {
    tokio::time::sleep(interval).await;
}
