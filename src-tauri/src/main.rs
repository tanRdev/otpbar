#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod gmail;
mod keychain;
mod oauth_server;
mod otp;
mod types;

use types::{AppState, CodeEntry};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager, State, WindowEvent, Emitter, PhysicalPosition, PhysicalSize};
use tauri_plugin_notification::NotificationExt;
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_shell::ShellExt;

const DEFAULT_POLL_INTERVAL_MS: u64 = 8000;
const NOTIFICATION_COOLDOWN_MS: u64 = 3000;

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
    log::info!("Notifications: {}", if notif_enabled { "enabled" } else { "disabled" });

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_notification::init())
        .manage(AppState {
            gmail_client: tokio::sync::Mutex::new(None),
            recent_codes: tokio::sync::Mutex::new(Vec::new()),
            last_notification: std::sync::Mutex::new(0),
            is_polling: std::sync::Mutex::new(false),
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
            logout,
            quit_app,
            hide_window,
            extract_provider,
        ])
        .on_window_event(|window, event| match event {
            WindowEvent::Focused(is_focused) => {
                if !is_focused {
                    let _ = window.hide();
                }
            }
            _ => {}
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn setup_menubar(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    // Hide dock icon on macOS
    #[cfg(target_os = "macos")]
    app.set_activation_policy(tauri::ActivationPolicy::Accessory);

    let handle = app.handle().clone();

    // Create quit menu item
    let quit_i = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&quit_i])?;

    // Create tray icon - decode PNG to RGBA
    let icon_bytes = include_bytes!("../icons/tray-icon.png");
    let decoded_image = image::load_from_memory(icon_bytes).unwrap();
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
            match event {
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    rect,
                    ..
                } => {
                    let app = tray.app_handle();
                    if let Some(window) = app.get_webview_window("main") {
                        if window.is_visible().unwrap_or(false) {
                            let _ = window.hide();
                        } else {
                            let window_size = window.outer_size().unwrap_or_default();
                            let icon_position: PhysicalPosition<f64> = rect.position.to_physical(1.0);
                            let icon_size: PhysicalSize<f64> = rect.size.to_physical(1.0);

                            // Center window horizontally relative to tray icon
                            let x = icon_position.x as i32 + (icon_size.width as i32 / 2) - (window_size.width as i32 / 2);
                            // Position below the tray icon (assuming top bar)
                            let y = icon_position.y as i32 + icon_size.height as i32;

                            let _ = window.set_position(PhysicalPosition::new(x, y));
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                }
                _ => {}
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

    if *state.is_polling.lock().unwrap() {
        log::warn!("Polling already active, skipping duplicate start");
        return;
    }
    *state.is_polling.lock().unwrap() = true;
    let poll_interval = get_poll_interval();
    log::info!("Started Gmail polling (interval: {}ms)", poll_interval);

    let handle_clone = handle.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(poll_interval)).await;

            let state: State<AppState> = handle_clone.state();
            let mut client_guard = state.gmail_client.lock().await;

            if let Some(client) = client_guard.as_mut() {
                match client.get_recent_unread().await {
                    Ok(messages) => {
                        for msg in messages {
                            let text = format!("{} {} {}", msg.subject, msg.snippet, msg.body);
                            if let Some(otp_code) = otp::extract_otp(&text) {
                                let mut codes = state.recent_codes.lock().await;

                                let is_duplicate = codes.iter()
                                    .any(|c| c.code == otp_code && c.message_id == msg.id);

                                if !is_duplicate {
                                    let provider = otp::extract_provider(&msg.from);
                                    log::info!("OTP detected: {} from provider {}", otp_code, provider);
                                    let entry = CodeEntry {
                                        code: otp_code.clone(),
                                        sender: extract_sender_name(&msg.from),
                                        provider,
                                        timestamp: chrono::Utc::now().timestamp_millis(),
                                        message_id: msg.id,
                                    };

                                    let _ = handle_clone.clipboard().write_text(otp_code.clone());

                                    if notifications_enabled() {
                                        let mut last_notif = state.last_notification.lock().unwrap();
                                        let now = chrono::Utc::now().timestamp_millis() as u64;
                                        if now - *last_notif >= NOTIFICATION_COOLDOWN_MS {
                                            let _ = handle_clone.notification()
                                                .builder()
                                                .title("OTP Copied")
                                                .body(format!("{} from {}", otp_code, entry.sender))
                                                .show();
                                            *last_notif = now;
                                        }
                                    }

                                    codes.insert(0, entry);
                                    if codes.len() > 10 {
                                        codes.truncate(10);
                                    }

                                    if let Some(window) = handle_clone.get_webview_window("main") {
                                        let _ = window.emit("codes-updated", codes.clone());
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Gmail polling failed: {}", e);
                    }
                }
            }
        }
    });
}

fn extract_sender_name(from: &str) -> String {
    let re = regex::Regex::new(r"^([^<@]+)").unwrap();
    if let Some(caps) = re.captures(from) {
        caps[1].trim().to_string()
    } else {
        from.to_string()
    }
}

// Tauri commands - must return Result for async commands with State
#[tauri::command]
async fn get_codes(state: State<'_, AppState>) -> Result<Vec<CodeEntry>, ()> {
    Ok(state.recent_codes.lock().await.clone())
}

#[tauri::command]
async fn get_auth_status(state: State<'_, AppState>) -> Result<bool, ()> {
    Ok(state.gmail_client.lock().await.as_ref()
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

    let mut oauth_server = oauth_server::OAuthServer::start(8234).await?;

    window.app_handle().shell().open(&auth_url, None)
        .map_err(|e| e.to_string())?;

    let code = oauth_server.wait_for_code().await?;

    client.exchange_code(&code).await?;

    let handle = window.app_handle().clone();
    drop(client_guard);
    start_polling(&handle).await;

    Ok(types::AuthResult { success: true, error: None })
}

#[tauri::command]
async fn copy_code(code: String, app: tauri::AppHandle) -> Result<bool, String> {
    app.clipboard().write_text(code)
        .map_err(|e| e.to_string())?;
    Ok(true)
}

#[tauri::command]
async fn logout(state: State<'_, AppState>, _app: tauri::AppHandle) -> Result<bool, String> {
    let mut client_guard = state.gmail_client.lock().await;
    if let Some(client) = client_guard.as_mut() {
        client.clear_auth().await
            .map_err(|e| e.to_string())?;
    }
    state.recent_codes.lock().await.clear();
    Ok(true)
}

#[tauri::command]
async fn quit_app(app: tauri::AppHandle) {
    app.exit(0);
}

#[tauri::command]
async fn hide_window(window: tauri::Window) -> Result<(), String> {
    window.hide().map_err(|e| e.to_string())
}

#[tauri::command]
fn extract_provider(sender: String) -> String {
    otp::extract_provider(&sender)
}
