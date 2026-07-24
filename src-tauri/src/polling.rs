use std::time::Duration;

pub async fn wait_for_poll_tick(interval: Duration) {
    tokio::time::sleep(interval).await;
}
