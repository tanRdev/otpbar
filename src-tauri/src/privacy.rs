use crate::history;
use crate::keychain::KeychainManager;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct PrivacyData {
    #[serde(rename = "dataLocations")]
    data_locations: DataLocations,
    #[serde(rename = "permissions")]
    permissions: Permissions,
    #[serde(rename = "activity")]
    activity: Activity,
    #[serde(rename = "retention")]
    retention: Retention,
}

#[derive(Debug, Serialize)]
struct DataLocations {
    #[serde(rename = "configPath")]
    config_path: String,
    #[serde(rename = "historyPath")]
    history_path: String,
    #[serde(rename = "keychainItems")]
    keychain_items: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Permissions {
    #[serde(rename = "scopes")]
    scopes: Vec<String>,
    #[serde(rename = "hasAccessToken")]
    has_access_token: bool,
    #[serde(rename = "hasRefreshToken")]
    has_refresh_token: bool,
}

#[derive(Debug, Serialize)]
struct Activity {
    #[serde(rename = "totalCodes")]
    total_codes: usize,
    #[serde(rename = "lastActivity")]
    last_activity: Option<i64>,
    #[serde(rename = "historyRetention")]
    history_retention: u32, // 0 means forever, otherwise days
}

#[derive(Debug, Serialize)]
struct Retention {
    #[serde(rename = "maxHistorySize")]
    max_history_size: usize,
    #[serde(rename = "currentSize")]
    current_size: usize,
}

const GMAIL_SCOPES: &[&str] = &["https://www.googleapis.com/auth/gmail.readonly"];

pub fn get_privacy_data() -> Result<PrivacyData, String> {
    // Get data locations
    let config_path = history::get_history_path()
        .map(|p| p.parent().unwrap().to_path_buf())
        .unwrap_or_else(|_| {
            dirs::config_dir()
                .map(|p| p.join("otpbar"))
                .unwrap_or_else(|| std::path::PathBuf::from("~/Library/Application Support/otpbar"))
        });

    let history_path = history::get_history_path()
        .unwrap_or_else(|_| std::path::PathBuf::from("code_history.json"));

    let config_path_str = config_path.to_string_lossy().to_string();
    let history_path_str = history_path.to_string_lossy().to_string();

    // Get keychain items
    let keychain_items = vec![
        "gmail-access-token".to_string(),
        "gmail-refresh-token".to_string(),
        "gmail-token-expiry".to_string(),
    ];

    // Get permissions
    let scopes: Vec<String> = GMAIL_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();

    let has_access_token = KeychainManager::get_access_token()
        .unwrap_or(None)
        .is_some();

    let has_refresh_token = KeychainManager::get_refresh_token()
        .unwrap_or(None)
        .is_some();

    // Get activity data
    let codes = history::load_history();
    let total_codes = codes.len();
    let last_activity = codes.first().map(|c| c.timestamp);

    // Currently we don't have a time-based retention, just size-based
    // Return 0 to indicate "forever" for now
    let history_retention = 0u32;

    // Get retention info
    let max_history_size = 50; // From history.rs
    let current_size = codes.len();

    Ok(PrivacyData {
        data_locations: DataLocations {
            config_path: config_path_str,
            history_path: history_path_str,
            keychain_items,
        },
        permissions: Permissions {
            scopes,
            has_access_token,
            has_refresh_token,
        },
        activity: Activity {
            total_codes,
            last_activity,
            history_retention,
        },
        retention: Retention {
            max_history_size,
            current_size,
        },
    })
}

pub fn clear_history() -> Result<(), String> {
    history::save_history(&[]);
    Ok(())
}
