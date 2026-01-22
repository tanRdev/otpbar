use keyring::Entry;

pub struct KeychainManager;

impl KeychainManager {
    pub fn get_refresh_token() -> Result<Option<String>, String> {
        let entry = Entry::new("otpbar", "gmail-refresh-token")
            .map_err(|e| e.to_string())?;
        entry.get_password()
            .map(Some)
            .map_err(|e| e.to_string())
    }

    pub fn set_refresh_token(token: &str) -> Result<(), String> {
        let entry = Entry::new("otpbar", "gmail-refresh-token")
            .map_err(|e| e.to_string())?;
        entry.set_password(token)
            .map_err(|e| e.to_string())
    }

    pub fn get_access_token() -> Result<Option<String>, String> {
        let entry = Entry::new("otpbar", "gmail-access-token")
            .map_err(|e| e.to_string())?;
        entry.get_password()
            .map(Some)
            .map_err(|e| e.to_string())
    }

    pub fn set_access_token(token: &str) -> Result<(), String> {
        let entry = Entry::new("otpbar", "gmail-access-token")
            .map_err(|e| e.to_string())?;
        entry.set_password(token)
            .map_err(|e| e.to_string())
    }

    pub fn get_token_expiry() -> Result<Option<i64>, String> {
        let entry = Entry::new("otpbar", "gmail-token-expiry")
            .map_err(|e| e.to_string())?;
        entry.get_password()
            .map(|s| s.parse().ok())
            .map_err(|e| e.to_string())
    }

    pub fn set_token_expiry(expiry_ts: i64) -> Result<(), String> {
        let entry = Entry::new("otpbar", "gmail-token-expiry")
            .map_err(|e| e.to_string())?;
        entry.set_password(&expiry_ts.to_string())
            .map_err(|e| e.to_string())
    }

    pub fn delete_all_credentials() -> Result<(), String> {
        let _ = Entry::new("otpbar", "gmail-refresh-token")
            .and_then(|e| e.delete_credential());
        let _ = Entry::new("otpbar", "gmail-access-token")
            .and_then(|e| e.delete_credential());
        let _ = Entry::new("otpbar", "gmail-token-expiry")
            .and_then(|e| e.delete_credential());
        Ok(())
    }
}
