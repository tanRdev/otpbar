use crate::keychain::KeychainManager;
use chrono::Utc;
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const GMAIL_SCOPES: &[&str] = &["https://www.googleapis.com/auth/gmail.readonly"];
const OAUTH_REDIRECT_URI: &str = "http://localhost:8234/callback";

#[derive(Debug, Clone)]
pub struct EmailMessage {
    pub id: String,
    pub from: String,
    pub subject: String,
    pub snippet: String,
    pub body: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
}

#[derive(Deserialize)]
struct MessageListResponse {
    messages: Option<Vec<Message>>,
}

#[derive(Deserialize)]
struct Message {
    id: String,
}

#[derive(Deserialize)]
struct MessageDetail {
    #[serde(default)]
    payload: Option<Payload>,
    #[serde(default)]
    snippet: String,
}

#[derive(Deserialize, Default)]
struct Payload {
    #[serde(default)]
    headers: Vec<Header>,
    #[serde(default)]
    body: Option<BodyPart>,
    #[serde(default)]
    parts: Option<Vec<Part>>,
}

#[derive(Deserialize)]
struct Header {
    name: String,
    value: String,
}

#[derive(Deserialize, Default)]
struct BodyPart {
    #[serde(default)]
    data: String,
}

#[derive(Deserialize, Default)]
struct Part {
    #[serde(default)]
    body: Option<BodyPart>,
    #[serde(default)]
    parts: Option<Vec<Part>>,
}

pub struct GmailClient {
    authenticated: bool,
    client_id: String,
    client_secret: String,
    http_client: Client,
}

impl GmailClient {
    pub async fn new() -> Result<Self, String> {
        let client_id = std::env::var("GOOGLE_CLIENT_ID")
            .unwrap_or_else(|_| "".to_string());
        let client_secret = std::env::var("GOOGLE_CLIENT_SECRET")
            .unwrap_or_else(|_| "".to_string());

        if client_id.is_empty() || client_secret.is_empty() {
            println!("WARNING: GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET not set. Authentication will fail.");
        }

        Ok(GmailClient {
            authenticated: false,
            client_id,
            client_secret,
            http_client: Client::new(),
        })
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    pub fn get_auth_url(&self) -> String {
        format!(
            "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope={}&prompt=consent&access_type=offline",
            urlencoding::encode(&self.client_id),
            urlencoding::encode(OAUTH_REDIRECT_URI),
            urlencoding::encode(&GMAIL_SCOPES.join(" "))
        )
    }

    pub async fn exchange_code(&mut self, code: &str) -> Result<(), String> {
        let params = [
            ("code", code),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
            ("redirect_uri", OAUTH_REDIRECT_URI),
            ("grant_type", "authorization_code"),
        ];

        let resp: TokenResponse = self
            .http_client
            .post("https://oauth2.googleapis.com/token")
            .form(&params)
            .send()
            .await
            .map_err(|e| format!("Token request failed: {}", e))?
            .json()
            .await
            .map_err(|e| format!("Failed to parse token response: {}", e))?;

        KeychainManager::set_access_token(&resp.access_token)?;

        let expiry = Utc::now().timestamp() + resp.expires_in.unwrap_or(3600) as i64;
        KeychainManager::set_token_expiry(expiry)?;

        if let Some(refresh_token) = resp.refresh_token {
            KeychainManager::set_refresh_token(&refresh_token)?;
        } else {
            let existing = KeychainManager::get_refresh_token()?;
            if existing.is_none() {
                return Err("No refresh token received".to_string());
            }
        }

        self.authenticated = true;
        log::info!("OAuth exchange successful, user authenticated");
        Ok(())
    }

    async fn refresh_access_token(&self) -> Result<String, String> {
        let refresh_token = KeychainManager::get_refresh_token()?
            .ok_or("No refresh token stored")?;

        let params = [
            ("refresh_token", refresh_token),
            ("client_id", self.client_id.clone()),
            ("client_secret", self.client_secret.clone()),
            ("grant_type", "refresh_token".to_string()),
        ];

        let resp: TokenResponse = self
            .http_client
            .post("https://oauth2.googleapis.com/token")
            .form(&params)
            .send()
            .await
            .map_err(|e| format!("Refresh request failed: {}", e))?
            .json()
            .await
            .map_err(|e| format!("Failed to parse refresh response: {}", e))?;

        let expiry = Utc::now().timestamp() + resp.expires_in.unwrap_or(3600) as i64;
        KeychainManager::set_access_token(&resp.access_token)?;
        KeychainManager::set_token_expiry(expiry)?;

        Ok(resp.access_token)
    }

    async fn get_valid_access_token(&self) -> Result<String, String> {
        if let Ok(Some(expiry)) = KeychainManager::get_token_expiry() {
            let now = Utc::now().timestamp();
            if now >= expiry - 60 {
                return self.refresh_access_token().await;
            }
        }

        KeychainManager::get_access_token()?
            .ok_or_else(|| "No access token stored".to_string())
    }

    /// Validate credentials by making a test API call to Gmail
    async fn validate_credentials(&self) -> Result<(), String> {
        let access_token = self.get_valid_access_token().await?;

        // Make a lightweight API call to verify the token works
        self.http_client
            .get("https://gmail.googleapis.com/gmail/v1/users/me/profile")
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| format!("Credential validation request failed: {}", e))?
            .error_for_status()
            .map_err(|e| format!("Invalid credentials: {}", e))?;

        Ok(())
    }

    pub async fn try_restore_auth(&mut self) -> bool {
        if self.client_id.is_empty() || self.client_secret.is_empty() {
            return false;
        }

        match KeychainManager::get_refresh_token() {
            Ok(Some(_)) => {
                match self.validate_credentials().await {
                    Ok(_) => {
                        self.authenticated = true;
                        log::info!("Successfully restored and validated Gmail authentication from keychain");
                        true
                    }
                    Err(e) => {
                        log::warn!("Gmail credential validation failed: {}", e);
                        // Clear invalid credentials so user can re-auth
                        let _ = self.clear_auth().await;
                        false
                    }
                }
            }
            _ => false,
        }
    }

    pub async fn get_recent_unread(&self) -> Result<Vec<EmailMessage>, String> {
        let access_token = self.get_valid_access_token().await?;

        let list_url = format!(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages?q=is%3Aunread%20newer_than:1d&maxResults=25"
        );

        let list_resp: MessageListResponse = self
            .http_client
            .get(&list_url)
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| format!("Gmail API request failed: {}", e))?
            .json()
            .await
            .map_err(|e| format!("Failed to parse message list: {}", e))?;

        let messages = list_resp.messages.unwrap_or_default();
        let mut results = Vec::new();

        for msg in messages {
            match self.fetch_message_detail(&msg.id, &access_token).await {
                Ok(detail) => results.push(detail),
                Err(e) => {
                    // SECURITY: Hash message ID to prevent correlation with Gmail logs
                    let id_hash = hash_message_id(&msg.id);
                    log::warn!("Failed to fetch message {}: {}", id_hash, e);
                }
            }
        }

        Ok(results)
    }

    async fn fetch_message_detail(
        &self,
        msg_id: &str,
        access_token: &str,
    ) -> Result<EmailMessage, String> {
        let url = format!(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/{}?format=full",
            msg_id
        );

        let resp: MessageDetail = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| format!("Message fetch failed: {}", e))?
            .json()
            .await
            .map_err(|e| format!("Failed to parse message: {}", e))?;

        let payload = resp.payload.unwrap_or_default();

        let mut from = String::new();
        let mut subject = String::new();

        for header in &payload.headers {
            match header.name.to_lowercase().as_str() {
                "from" => from = header.value.clone(),
                "subject" => subject = header.value.clone(),
                _ => {}
            }
        }

        let body = self.extract_body_text(&payload);

        Ok(EmailMessage {
            id: msg_id.to_string(),
            from,
            subject,
            snippet: resp.snippet,
            body,
        })
    }

    fn extract_body_text(&self, payload: &Payload) -> String {
        if let Some(body) = &payload.body {
            if !body.data.is_empty() {
                if let Ok(decoded) = base64_url_decode(&body.data) {
                    if let Ok(text) = String::from_utf8(decoded) {
                        return text;
                    }
                }
            }
        }

        if let Some(parts) = &payload.parts {
            for part in parts {
                let text = self.extract_part_text(part);
                if !text.is_empty() {
                    return text;
                }
            }
        }

        String::new()
    }

    fn extract_part_text(&self, part: &Part) -> String {
        if let Some(body) = &part.body {
            if !body.data.is_empty() {
                if let Ok(decoded) = base64_url_decode(&body.data) {
                    if let Ok(text) = String::from_utf8(decoded) {
                        return text;
                    }
                }
            }
        }

        if let Some(parts) = &part.parts {
            for part in parts {
                let text = self.extract_part_text(part);
                if !text.is_empty() {
                    return text;
                }
            }
        }

        String::new()
    }

    pub async fn clear_auth(&mut self) -> Result<(), String> {
        KeychainManager::delete_all_credentials()?;
        self.authenticated = false;
        Ok(())
    }
}

fn base64_url_decode(input: &str) -> Result<Vec<u8>, String> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let input = input.replace('-', "+").replace('_', "/");
    let input_len = input.len();
    let padded_len = (input_len + 3) & !3;
    let mut padded = input.into_bytes();
    padded.resize(padded_len, b'=');

    STANDARD.decode(&padded).map_err(|e| e.to_string())
}

// SECURITY: Hash message IDs for logging to prevent correlation with Gmail API logs
fn hash_message_id(id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(id.as_bytes());
    format!("{:x}", hasher.finalize())
}
