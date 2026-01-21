use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeEntry {
    pub code: String,
    pub sender: String,
    pub provider: String,
    pub timestamp: i64,
    pub message_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    pub success: bool,
    pub error: Option<String>,
}

// Forward declaration - actual module is in main.rs
pub struct AppState {
    pub gmail_client: tokio::sync::Mutex<Option<crate::gmail::GmailClient>>,
    pub recent_codes: tokio::sync::Mutex<Vec<CodeEntry>>,
    pub last_notification: std::sync::Mutex<u64>,
    pub is_polling: std::sync::Mutex<bool>,
}
