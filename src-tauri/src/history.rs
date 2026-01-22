use crate::types::CodeEntry;
use std::fs;
use std::path::PathBuf;

const HISTORY_FILE: &str = "code_history.json";
const MAX_HISTORY_SIZE: usize = 50;

pub fn get_history_path() -> Result<PathBuf, String> {
    let mut path = dirs::config_dir().ok_or("Failed to get config directory")?;
    path.push("otpbar");
    fs::create_dir_all(&path).map_err(|e| format!("Failed to create config directory: {}", e))?;
    path.push(HISTORY_FILE);
    Ok(path)
}

pub fn load_history() -> Vec<CodeEntry> {
    match get_history_path() {
        Ok(path) if path.exists() => match fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<Vec<CodeEntry>>(&content) {
                Ok(entries) => {
                    log::info!("Loaded {} codes from history", entries.len());
                    entries
                }
                Err(e) => {
                    log::warn!("Failed to parse history file: {}", e);
                    Vec::new()
                }
            },
            Err(e) => {
                log::warn!("Failed to read history file: {}", e);
                Vec::new()
            }
        },
        _ => Vec::new(),
    }
}

pub fn save_history(codes: &[CodeEntry]) {
    match get_history_path() {
        Ok(path) => {
            let to_save = codes
                .iter()
                .take(MAX_HISTORY_SIZE)
                .cloned()
                .collect::<Vec<_>>();
            match serde_json::to_string_pretty(&to_save) {
                Ok(json) => {
                    if let Err(e) = fs::write(&path, json) {
                        log::warn!("Failed to save history: {}", e);
                    }
                }
                Err(e) => {
                    log::warn!("Failed to serialize history: {}", e);
                }
            }
        }
        Err(e) => {
            log::warn!("Failed to get history path: {}", e);
        }
    }
}
