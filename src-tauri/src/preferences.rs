use crate::types::PrivacyPreferences;
use std::fs;
use std::path::PathBuf;

const PREFERENCES_FILE: &str = "preferences.json";

pub fn get_preferences_path() -> Result<PathBuf, String> {
    let mut path = dirs::config_dir()
        .ok_or("Failed to get config directory")?;
    path.push("otpbar");
    fs::create_dir_all(&path)
        .map_err(|e| format!("Failed to create config directory: {}", e))?;
    path.push(PREFERENCES_FILE);
    Ok(path)
}

pub fn load_preferences() -> PrivacyPreferences {
    match get_preferences_path() {
        Ok(path) if path.exists() => {
            match fs::read_to_string(&path) {
                Ok(content) => {
                    match serde_json::from_str::<PrivacyPreferences>(&content) {
                        Ok(prefs) => {
                            log::info!("Loaded preferences from disk");
                            prefs
                        }
                        Err(e) => {
                            log::warn!("Failed to parse preferences file: {}", e);
                            PrivacyPreferences::default()
                        }
                    }
                }
                Err(e) => {
                    log::warn!("Failed to read preferences file: {}", e);
                    PrivacyPreferences::default()
                }
            }
        }
        _ => {
            log::info!("No preferences file found, using defaults");
            PrivacyPreferences::default()
        }
    }
}

pub fn save_preferences(prefs: &PrivacyPreferences) {
    match get_preferences_path() {
        Ok(path) => {
            match serde_json::to_string_pretty(prefs) {
                Ok(json) => {
                    if let Err(e) = fs::write(&path, json) {
                        log::warn!("Failed to save preferences: {}", e);
                    } else {
                        log::info!("Saved preferences to disk");
                    }
                }
                Err(e) => {
                    log::warn!("Failed to serialize preferences: {}", e);
                }
            }
        }
        Err(e) => {
            log::warn!("Failed to get preferences path: {}", e);
        }
    }
}
