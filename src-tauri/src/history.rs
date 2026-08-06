use std::fs;
use std::path::PathBuf;

const HISTORY_FILE: &str = "code_history.json";

/// Locates the config directory via the legacy history path convention.
///
/// The plaintext history file itself is never read or written by the app:
/// `state_store::migration` imports any surviving legacy file into the
/// encrypted store at startup and then deletes it. This helper only derives
/// the directory for display purposes.
pub fn get_history_path() -> Result<PathBuf, String> {
    let mut path = dirs::config_dir().ok_or("Failed to get config directory")?;
    path.push("otpbar");
    fs::create_dir_all(&path).map_err(|e| format!("Failed to create config directory: {}", e))?;
    path.push(HISTORY_FILE);
    Ok(path)
}
