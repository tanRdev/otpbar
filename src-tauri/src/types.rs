use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardConfig {
    pub timeout_seconds: u64,
}

impl Default for ClipboardConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyPreferences {
    pub auto_copy_enabled: bool,
    pub provider_auto_copy: HashMap<String, bool>,
}

impl Default for PrivacyPreferences {
    fn default() -> Self {
        let mut provider_auto_copy = HashMap::new();
        provider_auto_copy.insert("default".to_string(), true);

        Self {
            auto_copy_enabled: true,
            provider_auto_copy,
        }
    }
}

// Forward declaration - actual module is in main.rs
pub struct AppState {
    pub gmail_client: tokio::sync::Mutex<Option<crate::gmail::GmailClient>>,
    pub recent_codes: tokio::sync::Mutex<Vec<CodeEntry>>,
    pub last_notification: tokio::sync::Mutex<u64>,
    pub is_polling: tokio::sync::Mutex<bool>,
    pub clipboard_config: tokio::sync::Mutex<ClipboardConfig>,
    pub privacy_preferences: tokio::sync::Mutex<PrivacyPreferences>,
    pub clipboard_tasks: tokio::sync::Mutex<Vec<tauri::async_runtime::JoinHandle<()>>>,
    pub processed_codes: tokio::sync::Mutex<HashSet<String>>,
}
