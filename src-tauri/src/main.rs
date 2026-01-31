#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// LOG SECURITY POLICY:
// All sensitive data MUST be redacted from logs:
// - OTP codes: Replace with "******" (never log actual codes)
// - Sender emails: Use provider name only, truncate if needed
// - Message IDs: Hash or truncate (no Gmail correlation)
// - Access tokens: Never log, use "[REDACTED]"
// - Email bodies: Never log full content
mod gmail;
mod history;
mod keychain;
mod oauth_server;
mod otp;
mod preferences;
mod privacy;
mod types;

use regex::Regex;
use std::sync::LazyLock;
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager, PhysicalPosition, PhysicalSize, State, WindowEvent,
};

static SENDER_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([^<@]+)").expect("Sender name regex should be valid")
});
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_notification::NotificationExt;
use tauri_plugin_opener::OpenerExt;
use types::{AppState, ClipboardConfig, CodeEntry, PrivacyPreferences};

const DEFAULT_POLL_INTERVAL_MS: u64 = 8000;
const NOTIFICATION_COOLDOWN_MS: u64 = 3000;
const DEFAULT_CLIPBOARD_TIMEOUT_SECONDS: u64 = 30;

fn get_poll_interval() -> u64 {
    std::env::var("OTPBAR_POLL_INTERVAL_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_POLL_INTERVAL_MS)
}

fn notifications_enabled() -> bool {
    std::env::var("OTPBAR_NOTIFICATIONS_ENABLED")
        .ok()
        .and_then(|s| s.parse::<bool>().ok())
        .unwrap_or(true)
}

fn get_clipboard_timeout() -> u64 {
    std::env::var("OTPBAR_CLIPBOARD_TIMEOUT_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_CLIPBOARD_TIMEOUT_SECONDS)
}

// Declare GmailClient at the top level so it can be used in types
pub use gmail::GmailClient;

fn main() {
    dotenvy::dotenv().ok();

    // Initialize logger
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let poll_interval = get_poll_interval();
    if poll_interval != DEFAULT_POLL_INTERVAL_MS {
        log::info!("Custom polling interval configured: {}ms", poll_interval);
    }

    let notif_enabled = notifications_enabled();
    log::info!(
        "Notifications: {}",
        if notif_enabled { "enabled" } else { "disabled" }
    );

    let clipboard_timeout = get_clipboard_timeout();
    log::info!("Clipboard timeout: {}s", clipboard_timeout);

    let loaded_prefs = preferences::load_preferences();
    log::info!("Auto-copy enabled: {}", loaded_prefs.auto_copy_enabled);

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init())
        .manage(AppState {
            gmail_client: tokio::sync::Mutex::new(None),
            recent_codes: tokio::sync::Mutex::new(Vec::new()),
            last_notification: tokio::sync::Mutex::new(0),
            is_polling: tokio::sync::Mutex::new(false),
            clipboard_config: tokio::sync::Mutex::new(ClipboardConfig {
                timeout_seconds: clipboard_timeout,
            }),
            privacy_preferences: tokio::sync::Mutex::new(loaded_prefs),
            clipboard_tasks: tokio::sync::Mutex::new(Vec::new()),
            processed_codes: tokio::sync::Mutex::new(std::collections::HashSet::new()),
        })
        .setup(|app| {
            setup_menubar(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_codes,
            get_auth_status,
            start_auth,
            copy_code,
            copy_code_with_expiry,
            logout,
            quit_app,
            hide_window,
            extract_provider,
            get_clipboard_config,
            set_clipboard_timeout,
            get_privacy_data,
            clear_history,
            get_preferences,
            set_auto_copy_enabled,
            set_provider_auto_copy,
        ])
        .on_window_event(|window, event| {
            if let WindowEvent::Focused(is_focused) = event {
                if !is_focused {
                    let _ = window.hide();
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn setup_menubar(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    // Hide dock icon on macOS
    #[cfg(target_os = "macos")]
    app.set_activation_policy(tauri::ActivationPolicy::Accessory);

    let handle = app.handle().clone();

    // Load code history from disk
    let saved_codes = history::load_history();
    let handle_clone = handle.clone();
    tauri::async_runtime::spawn(async move {
        let state: State<AppState> = handle_clone.state();
        *state.recent_codes.lock().await = saved_codes;
    });

    // Create quit menu item
    let quit_i = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&quit_i])?;

    // Create tray icon - decode PNG to RGBA
    let icon_bytes = include_bytes!("../icons/tray-icon.png");
    let decoded_image =
        image::load_from_memory(icon_bytes).expect("Tray icon image should be valid PNG");
    let rgba_image = decoded_image.to_rgba8();
    let (width, height) = rgba_image.dimensions();
    let tray_icon = tauri::image::Image::new(rgba_image.as_raw().as_slice(), width, height);

    let _tray = TrayIconBuilder::with_id("main")
        .icon(tray_icon)
        .icon_as_template(true)
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| {
            if event.id.as_ref() == "quit" {
                app.exit(0);
            }
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                rect,
                ..
            } = event
            {
                let app = tray.app_handle();
                if let Some(window) = app.get_webview_window("main") {
                    if window.is_visible().unwrap_or(false) {
                        let _ = window.hide();
                    } else {
                        let window_size = window.outer_size().unwrap_or_default();
                        let icon_position: PhysicalPosition<f64> = rect.position.to_physical(1.0);
                        let icon_size: PhysicalSize<f64> = rect.size.to_physical(1.0);

                        // Center window horizontally relative to tray icon
                        let x = icon_position.x as i32 + (icon_size.width as i32 / 2)
                            - (window_size.width as i32 / 2);
                        // Position below the tray icon (assuming top bar)
                        let y = icon_position.y as i32 + icon_size.height as i32;

                        let _ = window.set_position(PhysicalPosition::new(x, y));
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
            }
        })
        .build(app)?;

    // Start Gmail initialization in background
    let handle_for_spawn = handle.clone();
    tauri::async_runtime::spawn(async move {
        if let Ok(mut client) = GmailClient::new().await {
            if client.try_restore_auth().await {
                let state: State<AppState> = handle_for_spawn.state();
                *state.gmail_client.lock().await = Some(client);
                start_polling(&handle_for_spawn).await;
            } else {
                let state: State<AppState> = handle_for_spawn.state();
                *state.gmail_client.lock().await = Some(client);
            }
        }
    });

    Ok(())
}

async fn start_polling(handle: &tauri::AppHandle) {
    let state: State<AppState> = handle.state();

    // Atomic check-and-set to prevent race condition
    let mut is_polling_guard = state.is_polling.lock().await;
    if *is_polling_guard {
        log::warn!("Polling already active, skipping duplicate start");
        return;
    }
    *is_polling_guard = true;
    drop(is_polling_guard);
    let poll_interval = get_poll_interval();
    log::info!("Started Gmail polling (interval: {}ms)", poll_interval);

    let handle_clone = handle.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(poll_interval)).await;

            let state: State<AppState> = handle_clone.state();
            
            // Batch read configuration values to minimize lock contention
            let (auto_copy_enabled, provider_prefs, clipboard_timeout, notif_cooldown) = {
                let prefs = state.privacy_preferences.lock().await;
                let config = state.clipboard_config.lock().await;
                let last_notif = state.last_notification.lock().await;
                let now = chrono::Utc::now().timestamp_millis() as u64;
                let time_since_last = now.saturating_sub(*last_notif);
                (
                    prefs.auto_copy_enabled,
                    prefs.provider_auto_copy.clone(),
                    config.timeout_seconds,
                    time_since_last >= NOTIFICATION_COOLDOWN_MS,
                )
            };
            
            let mut client_guard = state.gmail_client.lock().await;

            if let Some(client) = client_guard.as_mut() {
                match client.get_recent_unread().await {
                    Ok(messages) => {
                        // Process messages and batch state updates
                        let mut codes_guard = state.recent_codes.lock().await;
                        let mut processed_guard = state.processed_codes.lock().await;
                        let mut last_notif_guard = state.last_notification.lock().await;
                        
                        for msg in messages {
                            let text = format!("{} {} {}", msg.subject, msg.snippet, msg.body);
                            if let Some(otp_code) = otp::extract_otp(&text) {
                                // O(1) duplicate check using HashSet
                                let dedup_key = format!("{}:{}", msg.id, otp_code);
                                let is_duplicate = processed_guard.contains(&dedup_key);

                                if !is_duplicate {
                                    let provider = otp::extract_provider(&msg.from);
                                    log::info!("OTP detected: ****** from provider {}", provider);
                                    let entry = CodeEntry {
                                        code: otp_code.clone(),
                                        sender: extract_sender_name(&msg.from),
                                        provider: provider.clone(),
                                        timestamp: chrono::Utc::now().timestamp_millis(),
                                        message_id: msg.id,
                                    };

                                    // Check if auto-copy is enabled for this provider
                                    let should_auto_copy = if !auto_copy_enabled {
                                        false
                                    } else {
                                        provider_prefs
                                            .get(&provider)
                                            .or_else(|| provider_prefs.get("default"))
                                            .copied()
                                            .unwrap_or(true)
                                    };

                                    if should_auto_copy {
                                        let state_clone = state.clone();
                                        drop(codes_guard);
                                        drop(processed_guard);
                                        drop(last_notif_guard);
                                        
                                        copy_to_clipboard_with_expiry(
                                            otp_code.clone(),
                                            handle_clone.clone(),
                                            clipboard_timeout,
                                            state_clone,
                                        )
                                        .await;
                                        
                                        codes_guard = state.recent_codes.lock().await;
                                        processed_guard = state.processed_codes.lock().await;
                                        last_notif_guard = state.last_notification.lock().await;
                                    }

                                    if notifications_enabled() && notif_cooldown {
                                        let _ = handle_clone
                                            .notification()
                                            .builder()
                                            .title("OTP Copied")
                                            .body(format!("Code from {}", entry.sender))
                                            .show();
                                        *last_notif_guard = chrono::Utc::now().timestamp_millis() as u64;
                                    }

                                    codes_guard.insert(0, entry);
                                    processed_guard.insert(dedup_key);
                                    if codes_guard.len() > 10 {
                                        codes_guard.truncate(10);
                                        let codes_to_keep: std::collections::HashSet<String> = codes_guard
                                            .iter()
                                            .map(|c| format!("{}:{}", c.message_id, c.code))
                                            .collect();
                                        processed_guard.retain(|k| codes_to_keep.contains(k));
                                    }
                                }
                            }
                        }
                        
                        history::save_history(&codes_guard);
                        
                        if let Some(window) = handle_clone.get_webview_window("main") {
                            let _ = window.emit("codes-updated", codes_guard.clone());
                        }
                        
                        drop(codes_guard);
                        drop(processed_guard);
                        drop(last_notif_guard);
                    }
                    Err(e) => {
                        log::error!("Gmail polling failed: {}", e);
                    }
                }
            }
            drop(client_guard);
        }
    });
}

fn extract_sender_name(from: &str) -> String {
    if let Some(caps) = SENDER_NAME_RE.captures(from) {
        caps[1].trim().to_string()
    } else {
        from.to_string()
    }
}

async fn copy_to_clipboard_with_expiry(
    text: String,
    app_handle: tauri::AppHandle,
    timeout_seconds: u64,
    state: State<'_, AppState>,
) {
    if let Err(e) = app_handle.clipboard().write_text(text.clone()) {
        log::error!("Failed to write to clipboard: {}", e);
        return;
    }

    let app_clone = app_handle.clone();
    let handle = tauri::async_runtime::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(timeout_seconds)).await;
        if let Err(e) = app_clone.clipboard().write_text("") {
            log::error!("Failed to clear clipboard: {}", e);
        } else {
            log::info!("Clipboard cleared after {}s timeout", timeout_seconds);
        }
    });
    
    state.clipboard_tasks.lock().await.push(handle);
}

// Tauri commands - must return Result for async commands with State
#[tauri::command]
async fn get_codes(state: State<'_, AppState>) -> Result<Vec<CodeEntry>, ()> {
    Ok(state.recent_codes.lock().await.clone())
}

#[tauri::command]
async fn get_auth_status(state: State<'_, AppState>) -> Result<bool, ()> {
    Ok(state
        .gmail_client
        .lock()
        .await
        .as_ref()
        .map(|c| c.is_authenticated())
        .unwrap_or(false))
}

#[tauri::command]
async fn start_auth(
    state: State<'_, AppState>,
    window: tauri::Window,
) -> Result<types::AuthResult, String> {
    let mut client_guard = state.gmail_client.lock().await;
    let client = client_guard.as_mut().ok_or("No Gmail client")?;

    let auth_url = client.get_auth_url();

    // Try ports 8234-8240 with fallback logic
    const PORTS: &[u16] = &[8234, 8235, 8236, 8237, 8238, 8239, 8240];
    let mut oauth_server = None;
    let mut last_error = None;
    
    for &port in PORTS {
        match oauth_server::OAuthServer::start(port).await {
            Ok(server) => {
                oauth_server = Some(server);
                log::info!("OAuth server started on port {}", port);
                break;
            }
            Err(e) => {
                log::warn!("Failed to start OAuth server on port {}: {}", port, e);
                last_error = Some(e);
            }
        }
    }
    
    let mut oauth_server = oauth_server.ok_or_else(|| {
        format!("Failed to start OAuth server on any port: {:?}", last_error)
    })?;

    window
        .app_handle()
        .opener()
        .open_url(&auth_url, None::<String>)
        .map_err(|e| e.to_string())?;

    let code = oauth_server.wait_for_code().await?;

    client.exchange_code(&code).await?;

    let handle = window.app_handle().clone();
    drop(client_guard);
    start_polling(&handle).await;

    Ok(types::AuthResult {
        success: true,
        error: None,
    })
}

#[tauri::command]
async fn copy_code(code: String, app: tauri::AppHandle) -> Result<bool, String> {
    app.clipboard()
        .write_text(code)
        .map_err(|e| e.to_string())?;
    Ok(true)
}

#[tauri::command]
async fn copy_code_with_expiry(
    code: String,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let timeout = {
        let config = state.clipboard_config.lock().await;
        config.timeout_seconds
    };

    app.clipboard()
        .write_text(code.clone())
        .map_err(|e| format!("Failed to write to clipboard: {}", e))?;

    let app_clone = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(timeout)).await;
        if let Err(e) = app_clone.clipboard().write_text("") {
            log::error!("Failed to clear clipboard: {}", e);
        } else {
            log::info!("Clipboard cleared after {}s timeout", timeout);
        }
    });

    Ok(true)
}

#[tauri::command]
async fn get_clipboard_config(state: State<'_, AppState>) -> Result<ClipboardConfig, String> {
    Ok(state.clipboard_config.lock().await.clone())
}

#[tauri::command]
async fn set_clipboard_timeout(
    timeout_seconds: u64,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut config = state.clipboard_config.lock().await;
    config.timeout_seconds = timeout_seconds;
    log::info!("Clipboard timeout updated to {}s", timeout_seconds);
    Ok(())
}

#[tauri::command]
async fn logout(state: State<'_, AppState>, _app: tauri::AppHandle) -> Result<bool, String> {
    let mut client_guard = state.gmail_client.lock().await;
    if let Some(client) = client_guard.as_mut() {
        client.clear_auth().await.map_err(|e| e.to_string())?;
    }
    state.recent_codes.lock().await.clear();
    history::save_history(&[]);
    Ok(true)
}

#[tauri::command]
async fn quit_app(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    // Cancel all pending clipboard timeout tasks
    let mut tasks = state.clipboard_tasks.lock().await;
    for handle in tasks.drain(..) {
        handle.abort();
    }
    drop(tasks);
    
    // Clear clipboard for security
    let _ = app.clipboard().write_text("");
    
    app.exit(0);
    Ok(())
}

#[tauri::command]
async fn hide_window(window: tauri::Window) -> Result<(), String> {
    window.hide().map_err(|e| e.to_string())
}

#[tauri::command]
fn extract_provider(sender: String) -> String {
    otp::extract_provider(&sender)
}

#[tauri::command]
fn get_privacy_data() -> Result<privacy::PrivacyData, String> {
    privacy::get_privacy_data()
}

#[tauri::command]
async fn clear_history(state: State<'_, AppState>) -> Result<(), String> {
    privacy::clear_history()?;
    state.recent_codes.lock().await.clear();
    Ok(())
}

#[tauri::command]
async fn get_preferences(state: State<'_, AppState>) -> Result<PrivacyPreferences, String> {
    Ok(state.privacy_preferences.lock().await.clone())
}

#[tauri::command]
async fn set_auto_copy_enabled(enabled: bool, state: State<'_, AppState>) -> Result<(), String> {
    let mut prefs = state.privacy_preferences.lock().await;
    prefs.auto_copy_enabled = enabled;
    preferences::save_preferences(&prefs);
    log::info!("Auto-copy enabled: {}", enabled);
    Ok(())
}

#[tauri::command]
async fn set_provider_auto_copy(
    provider: String,
    enabled: bool,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut prefs = state.privacy_preferences.lock().await;
    prefs.provider_auto_copy.insert(provider, enabled);
    preferences::save_preferences(&prefs);
    log::info!("Provider auto-copy updated");
    Ok(())
}
