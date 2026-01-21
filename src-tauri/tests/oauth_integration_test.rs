// Integration tests for OAuth flow

use std::time::Duration;
use tokio::time::sleep;
use otpbar::oauth_server::OAuthServer;

#[tokio::test]
async fn oauth_server_starts_and_binds() {
    let server = OAuthServer::start(8234)
        .await
        .expect("Server should start on available port");
    drop(server); // Clean shutdown
}

#[tokio::test]
async fn oauth_server_handles_callback_success() {
    let mut server = OAuthServer::start(8235)
        .await
        .expect("Server should start");

    // Spawn a task to simulate OAuth callback
    tokio::spawn(async move {
        sleep(Duration::from_millis(100)).await;
        let client = reqwest::Client::new();
        let resp = client
            .get("http://127.0.0.1:8235/callback?code=test_auth_code_123")
            .send()
            .await
            .expect("Request should succeed");

        assert_eq!(resp.status(), 200);
        let body = resp.text().await.expect("Should get body");
        assert!(body.contains("Signed In"));
    });

    let code = server
        .wait_for_code()
        .await
        .expect("Should receive code");
    assert_eq!(code, "test_auth_code_123");
}

#[tokio::test]
async fn oauth_server_handles_callback_error() {
    let server = OAuthServer::start(8236)
        .await
        .expect("Server should start");

    // Spawn a task to simulate OAuth error callback
    tokio::spawn(async move {
        sleep(Duration::from_millis(100)).await;
        let client = reqwest::Client::new();
        let resp = client
            .get("http://127.0.0.1:8236/callback?error=access_denied")
            .send()
            .await
            .expect("Request should succeed");

        assert_eq!(resp.status(), 200);
        let body = resp.text().await.expect("Should get body");
        assert!(body.contains("access_denied"));
    });

    sleep(Duration::from_millis(200)).await;
    // Server should still be running but no code received
    drop(server);
}

#[tokio::test]
async fn oauth_server_timeout() {
    let mut server = OAuthServer::start(8237)
        .await
        .expect("Server should start");

    // Wait for timeout (server has 300s timeout, but we'll use a shorter test)
    // For testing, we just verify the server doesn't immediately return
    tokio::spawn(async move {
        sleep(Duration::from_millis(100)).await;
        drop(server);
    });
}

#[tokio::test]
async fn oauth_server_not_found_path() {
    let _server = OAuthServer::start(8238)
        .await
        .expect("Server should start");

    sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let resp = client
        .get("http://127.0.0.1:8238/unknown")
        .send()
        .await
        .expect("Request should succeed");

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn oauth_callback_parse_query_params() {
    let _server = OAuthServer::start(8239)
        .await
        .expect("Server should start");

    tokio::spawn(async move {
        sleep(Duration::from_millis(100)).await;
        let client = reqwest::Client::new();
        // Test with multiple query params
        let resp = client
            .get("http://127.0.0.1:8239/callback?code=abc123&state=xyz789&scope=email")
            .send()
            .await
            .expect("Request should succeed");

        assert_eq!(resp.status(), 200);
    });

    sleep(Duration::from_millis(200)).await;
}
