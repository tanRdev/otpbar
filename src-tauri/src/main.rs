#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// LOG SECURITY POLICY:
// All sensitive data MUST be redacted from logs:
// - OTP codes: Replace with "******" (never log actual codes)
// - Sender emails: Use provider name only, truncate if needed
// - Message IDs: Hash or truncate (no Gmail correlation)
// - Access tokens: Never log, use "[REDACTED]"
// - Email bodies: Never log full content
mod clipboard_adapter;
mod clipboard_runtime;
mod history;
#[cfg(target_os = "macos")]
mod pasteboard_clipboard;
mod preferences;
mod privacy;
mod types;

use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager, PhysicalPosition, PhysicalSize, RunEvent, State, WindowEvent,
};
use tauri_plugin_opener::OpenerExt;
use types::{AppState, ClipboardConfig, CodeEntry, PrivacyPreferences};

#[cfg(not(target_os = "macos"))]
use clipboard_adapter::{TauriClipboardAdapter, ATOMIC_CLEAR_LIMITATION};
use clipboard_runtime::{
    lease_error_envelope, spawn_clipboard_actor, ClipboardActorHandle, ClipboardLeaseEvent,
    LeaseEventSink,
};
use otpbar::{
    authorization::{
        core::AuthorizationStatus,
        credentials::CredentialRepository,
        google::{GoogleAuthorization, GoogleConfiguration},
        runtime::{
            spawn_authorization, AuthorizationBrowser, AuthorizationHandle,
            AuthorizationTransportError, ConfigurationMissingTransport,
        },
    },
    clipboard_lease::LeaseDuration,
    clock::{Clock, SystemClock},
    domain::error::{CommandEnvelope, ErrorEnvelope},
    intake::{
        runtime::{
            spawn_production_monitoring, AcceptedCodeSink, IntakePipeline, MonitoringHandle,
            MonitoringRuntimeError, SharedAcceptance,
        },
        scheduler::{MigrationReadiness, MonitoringHealth},
    },
    settings::{AcceptancePolicySnapshot, Settings},
    state_store::{
        acceptance::{AcceptanceStartup, MessageAcceptance},
        history::HistoryEntry,
        FirstRunCreationOutcome, KeychainSecretStore, MigrationStartupOutcome, PlaintextMigration,
        SecretStartupOutcome, StartupOutcome, StateKey, StateStoreInitializer, SystemRandom,
    },
};
use std::{sync::Arc, time::Duration};

const DEFAULT_CLIPBOARD_TIMEOUT_SECONDS: u64 = 30;

const CLIPBOARD_LEASE_EVENT: &str = "clipboard-lease-status";
const AUTHORIZATION_STATUS_EVENT: &str = "authorization-status";
const MONITORING_HEALTH_EVENT: &str = "monitoring-health";
const CODES_UPDATED_EVENT: &str = "codes-updated";
const MAX_RECENT_CODES: usize = 50;

#[derive(Clone)]
struct TauriLeaseEventSink(tauri::AppHandle);

impl LeaseEventSink for TauriLeaseEventSink {
    fn publish(&self, event: ClipboardLeaseEvent) {
        if let Err(error) = self.0.emit(CLIPBOARD_LEASE_EVENT, event) {
            log::warn!("Clipboard lease status could not be published: {}", error);
        }
    }
}

#[derive(Clone)]
struct TauriAuthorizationBrowser(tauri::AppHandle);

impl AuthorizationBrowser for TauriAuthorizationBrowser {
    fn open(&self, url: &str) -> Result<(), AuthorizationTransportError> {
        self.0
            .opener()
            .open_url(url, None::<String>)
            .map_err(|_| AuthorizationTransportError::Unavailable)
    }
}

fn publish_authorization_status(app: tauri::AppHandle, authorization: AuthorizationHandle) {
    tauri::async_runtime::spawn(async move {
        let mut statuses = authorization.subscribe();
        if app
            .emit(AUTHORIZATION_STATUS_EVENT, *statuses.borrow())
            .is_err()
        {
            log::warn!("Authorization status could not be published.");
        }
        while statuses.changed().await.is_ok() {
            let status = *statuses.borrow_and_update();
            if app.emit(AUTHORIZATION_STATUS_EVENT, status).is_err() {
                log::warn!("Authorization status could not be published.");
            }
        }
    });
}

fn publish_monitoring_health(app: tauri::AppHandle, monitoring: MonitoringHandle) {
    tauri::async_runtime::spawn(async move {
        let mut health = monitoring.subscribe();
        let _ = app.emit(MONITORING_HEALTH_EVENT, *health.borrow());
        while health.changed().await.is_ok() {
            if app
                .emit(MONITORING_HEALTH_EVENT, *health.borrow_and_update())
                .is_err()
            {
                log::warn!("Monitoring Health could not be published.");
            }
        }
    });
}

fn get_clipboard_timeout() -> u64 {
    std::env::var("OTPBAR_CLIPBOARD_TIMEOUT_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|seconds| matches!(seconds, 15 | 30 | 60))
        .unwrap_or(DEFAULT_CLIPBOARD_TIMEOUT_SECONDS)
}

fn history_entry_to_code_entry(entry: &HistoryEntry) -> CodeEntry {
    CodeEntry {
        code: entry.code().to_string(),
        sender: entry.message_origin_display().to_string(),
        provider: entry.provider().display().to_string(),
        timestamp: entry.received_at().unix_millis(),
        message_id: entry.id().as_str().to_string(),
    }
}

/// Publishes committed History records to the Desktop Session.
struct TauriAcceptedCodeSink(tauri::AppHandle);

impl AcceptedCodeSink for TauriAcceptedCodeSink {
    fn code_accepted(&self, entry: &HistoryEntry) {
        let app = self.0.clone();
        let code = history_entry_to_code_entry(entry);
        tauri::async_runtime::spawn(async move {
            let state = app.state::<AppState>();
            let snapshot = {
                let mut codes = state.recent_codes.lock().await;
                codes.retain(|existing| existing.message_id != code.message_id);
                codes.insert(0, code);
                codes.truncate(MAX_RECENT_CODES);
                codes.clone()
            };
            if let Err(error) = app.emit(CODES_UPDATED_EVENT, snapshot) {
                log::warn!("Codes-updated event could not be published: {}", error);
            }
        });
    }
}

/// Activated acceptance owner plus the key and policy the intake pipeline needs.
struct ActiveAcceptance {
    acceptance: SharedAcceptance,
    key: StateKey,
    policy: AcceptancePolicySnapshot,
}

fn state_store_path() -> Option<std::path::PathBuf> {
    let mut path = dirs::config_dir()?;
    path.push("otpbar");
    std::fs::create_dir_all(&path).ok()?;
    path.push("state.bin");
    Some(path)
}

/// Runs the durable startup sequence: exclusive store lock, Keychain key,
/// legacy plaintext migration, effect cancellation. Returns `None` when any
/// step requires recovery; the caller must leave intake stopped in that case.
fn activate_state_store() -> Option<ActiveAcceptance> {
    let path = state_store_path()?;
    let initializer = match StateStoreInitializer::open(path) {
        Ok(initializer) => initializer,
        Err(_) => {
            log::error!("State store lock could not be acquired; intake stays stopped.");
            return None;
        }
    };
    let mut random = SystemRandom;
    let secret = match initializer.initialize_from_secrets(&KeychainSecretStore) {
        Ok(secret) => secret,
        Err(_) => {
            log::error!("State key could not be read; intake stays stopped.");
            return None;
        }
    };
    let (outcome, key) = match secret {
        SecretStartupOutcome::Initialized { outcome, key } => (outcome, key),
        SecretStartupOutcome::FirstRunNeedsKey(capability) => {
            match capability.create(&mut KeychainSecretStore, &mut random) {
                Ok(FirstRunCreationOutcome::KeyCreated { key, outcome }) => (outcome, key),
                _ => {
                    log::error!("First-run state key could not be created; intake stays stopped.");
                    return None;
                }
            }
        }
        SecretStartupOutcome::RecoveryRequired(_) => {
            log::error!("State store requires recovery; intake stays stopped.");
            return None;
        }
    };
    let now = SystemClock.now();
    let migration =
        PlaintextMigration.migrate_startup(outcome, &key, &mut random, now.unix_millis());
    let acceptance = match migration {
        MigrationStartupOutcome::Unchanged(StartupOutcome::Absent(store)) => {
            MessageAcceptance::from_absent_store(store, key.clone(), random)
        }
        MigrationStartupOutcome::Unchanged(StartupOutcome::LoadedMustCancelEffects(loaded))
        | MigrationStartupOutcome::Migrated(loaded) => {
            match MessageAcceptance::restore_loaded(loaded, key.clone(), random, now) {
                Ok(AcceptanceStartup::Ready(acceptance)) => acceptance,
                Ok(AcceptanceStartup::BarrierPending(_)) => {
                    log::warn!("Startup cancellation is durability-pending; intake stays stopped.");
                    return None;
                }
                Err(_) => {
                    log::error!("Startup state could not be activated; intake stays stopped.");
                    return None;
                }
            }
        }
        MigrationStartupOutcome::Unchanged(StartupOutcome::RecoveryRequired(_))
        | MigrationStartupOutcome::RecoveryRequired { .. } => {
            log::error!("State migration requires recovery; intake stays stopped.");
            return None;
        }
    };
    let policy = acceptance
        .acceptance_policy()
        .unwrap_or_else(|| AcceptancePolicySnapshot::from(Settings::new().snapshot()));
    Some(ActiveAcceptance {
        acceptance: std::sync::Arc::new(tokio::sync::Mutex::new(acceptance)),
        key,
        policy,
    })
}

fn app_context<R: tauri::Runtime>() -> tauri::Context<R> {
    tauri::generate_context!()
}

fn main() {
    dotenvy::dotenv().ok();

    // Initialize logger
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let clipboard_timeout = get_clipboard_timeout();
    log::info!("Clipboard timeout: {}s", clipboard_timeout);

    let loaded_prefs = preferences::load_preferences();
    log::info!("Auto-copy enabled: {}", loaded_prefs.auto_copy_enabled);

    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init())
        .manage(AppState {
            recent_codes: tokio::sync::Mutex::new(Vec::new()),
            clipboard_config: tokio::sync::Mutex::new(ClipboardConfig {
                timeout_seconds: clipboard_timeout,
            }),
            privacy_preferences: tokio::sync::Mutex::new(loaded_prefs),
        })
        .setup(|app| {
            let app_handle = app.handle().clone();
            #[cfg(target_os = "macos")]
            let clipboard_actor = spawn_clipboard_actor(
                pasteboard_clipboard::PasteboardClipboard::new(),
                SystemClock,
                TauriLeaseEventSink(app_handle.clone()),
            );
            #[cfg(not(target_os = "macos"))]
            let clipboard_actor = {
                log::warn!("{}", ATOMIC_CLEAR_LIMITATION);
                spawn_clipboard_actor(
                    TauriClipboardAdapter::new(app_handle.clone()),
                    SystemClock,
                    TauriLeaseEventSink(app_handle.clone()),
                )
            };
            app.manage(clipboard_actor);
            let browser = Arc::new(TauriAuthorizationBrowser(app_handle.clone()));
            let repository = CredentialRepository::new(KeychainSecretStore);
            let authorization = match GoogleConfiguration::from_build() {
                Ok(configuration) => spawn_authorization(
                    repository,
                    Arc::new(GoogleAuthorization::new(configuration)),
                    browser,
                    SystemRandom,
                ),
                Err(_) => spawn_authorization(
                    repository,
                    Arc::new(ConfigurationMissingTransport),
                    browser,
                    SystemRandom,
                ),
            };
            publish_authorization_status(app_handle, authorization.clone());
            let activation = activate_state_store();
            let pipeline = activation.as_ref().map(|active| {
                IntakePipeline::new(
                    active.acceptance.clone(),
                    active.key.clone(),
                    active.policy.clone(),
                    Arc::new(TauriAcceptedCodeSink(app.handle().clone())),
                )
            });
            let monitoring = spawn_production_monitoring(authorization.clone(), pipeline);
            publish_monitoring_health(app.handle().clone(), monitoring.clone());
            if let Some(active) = activation {
                let initial_codes: Vec<CodeEntry> = tauri::async_runtime::block_on(async {
                    active
                        .acceptance
                        .lock()
                        .await
                        .history_entries()
                        .iter()
                        .map(history_entry_to_code_entry)
                        .collect()
                });
                let state = app.state::<AppState>();
                *tauri::async_runtime::block_on(state.recent_codes.lock()) = initial_codes;
                app.manage(Some(active.acceptance));
                let handle = monitoring.clone();
                tauri::async_runtime::spawn(async move {
                    if handle
                        .set_migration_readiness(MigrationReadiness::Ready)
                        .await
                        .is_err()
                    {
                        log::error!("Migration readiness never reached the monitoring owner.");
                    }
                });
            } else {
                app.manage(None::<SharedAcceptance>);
            }
            app.manage(monitoring);
            app.manage(authorization);
            setup_menubar(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_codes,
            get_authorization_status,
            begin_authorization,
            cancel_authorization,
            disconnect_authorization,
            get_monitoring_health,
            start_monitoring,
            stop_monitoring,
            check_monitoring_now,
            copy_code,
            copy_code_with_expiry,
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
        .build(app_context())
        .expect("error while building Tauri application")
        .run(|app, event| {
            if matches!(event, RunEvent::ExitRequested { .. } | RunEvent::Exit) {
                if let (Some(monitoring), Some(authorization)) = (
                    app.try_state::<MonitoringHandle>(),
                    app.try_state::<AuthorizationHandle>(),
                ) {
                    let _ = tauri::async_runtime::block_on(tokio::time::timeout(
                        Duration::from_millis(900),
                        async {
                            let _ = tokio::join!(monitoring.shutdown(), authorization.cancel());
                        },
                    ));
                }
                if let Some(actor) = app.try_state::<ClipboardActorHandle>() {
                    tauri::async_runtime::block_on(actor.shutdown());
                }
            }
        });
}

fn setup_menubar(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    // Hide dock icon on macOS
    #[cfg(target_os = "macos")]
    app.set_activation_policy(tauri::ActivationPolicy::Accessory);

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

    Ok(())
}

fn lease_duration(timeout_seconds: u64) -> Result<LeaseDuration, ErrorEnvelope> {
    LeaseDuration::try_from(Duration::from_secs(timeout_seconds)).map_err(lease_error_envelope)
}

// Tauri commands - must return Result for async commands with State
#[tauri::command]
async fn get_codes(state: State<'_, AppState>) -> Result<Vec<CodeEntry>, ()> {
    Ok(state.recent_codes.lock().await.clone())
}

#[tauri::command]
fn get_authorization_status(authorization: State<'_, AuthorizationHandle>) -> AuthorizationStatus {
    authorization.status()
}

#[tauri::command]
async fn begin_authorization(
    authorization: State<'_, AuthorizationHandle>,
) -> Result<AuthorizationStatus, AuthorizationTransportError> {
    authorization.begin().await
}

#[tauri::command]
async fn cancel_authorization(
    authorization: State<'_, AuthorizationHandle>,
) -> Result<AuthorizationStatus, AuthorizationTransportError> {
    authorization.cancel().await
}

#[tauri::command]
async fn disconnect_authorization(
    authorization: State<'_, AuthorizationHandle>,
    monitoring: State<'_, MonitoringHandle>,
) -> Result<AuthorizationStatus, AuthorizationTransportError> {
    let (_, disconnected) = tokio::join!(monitoring.stop(), authorization.disconnect());
    disconnected
}

#[tauri::command]
fn get_monitoring_health(monitoring: State<'_, MonitoringHandle>) -> MonitoringHealth {
    monitoring.health()
}

#[tauri::command]
async fn start_monitoring(
    monitoring: State<'_, MonitoringHandle>,
) -> Result<MonitoringHealth, MonitoringRuntimeError> {
    monitoring.start().await
}

#[tauri::command]
async fn stop_monitoring(
    monitoring: State<'_, MonitoringHandle>,
) -> Result<MonitoringHealth, MonitoringRuntimeError> {
    monitoring.stop().await
}

#[tauri::command]
async fn check_monitoring_now(
    monitoring: State<'_, MonitoringHandle>,
) -> Result<MonitoringHealth, MonitoringRuntimeError> {
    monitoring.check_now().await
}

#[tauri::command]
async fn copy_code(
    code: String,
    state: State<'_, AppState>,
    actor: State<'_, ClipboardActorHandle>,
) -> Result<CommandEnvelope<bool>, ErrorEnvelope> {
    let timeout = state.clipboard_config.lock().await.timeout_seconds;
    Ok(copy_command(code, timeout, &actor).await)
}

#[tauri::command]
async fn copy_code_with_expiry(
    code: String,
    state: State<'_, AppState>,
    actor: State<'_, ClipboardActorHandle>,
) -> Result<CommandEnvelope<bool>, ErrorEnvelope> {
    let timeout = state.clipboard_config.lock().await.timeout_seconds;
    Ok(copy_command(code, timeout, &actor).await)
}

async fn copy_command(
    code: String,
    timeout_seconds: u64,
    actor: &ClipboardActorHandle,
) -> CommandEnvelope<bool> {
    let duration = match lease_duration(timeout_seconds) {
        Ok(duration) => duration,
        Err(error) => return CommandEnvelope::failure(error),
    };

    match actor.copy(code, duration).await {
        Ok(()) => CommandEnvelope::success(true),
        Err(error) => CommandEnvelope::failure(error),
    }
}

#[tauri::command]
async fn get_clipboard_config(state: State<'_, AppState>) -> Result<ClipboardConfig, String> {
    Ok(state.clipboard_config.lock().await.clone())
}

#[tauri::command]
async fn set_clipboard_timeout(
    timeout_seconds: u64,
    state: State<'_, AppState>,
) -> Result<(), ErrorEnvelope> {
    lease_duration(timeout_seconds)?;
    let mut config = state.clipboard_config.lock().await;
    config.timeout_seconds = timeout_seconds;
    log::info!("Clipboard timeout updated to {}s", timeout_seconds);
    Ok(())
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
    otpbar::otp::extract_provider(&sender)
}

#[tauri::command]
async fn get_privacy_data(state: State<'_, AppState>) -> Result<privacy::PrivacyData, String> {
    let codes = state.recent_codes.lock().await.clone();
    privacy::get_privacy_data(&codes)
}

#[tauri::command]
async fn clear_history(
    state: State<'_, AppState>,
    acceptance: State<'_, Option<SharedAcceptance>>,
) -> Result<(), String> {
    if let Some(acceptance) = acceptance.as_ref() {
        acceptance.lock().await.clear_history(SystemClock.now());
    }
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

#[cfg(test)]
mod ipc_acl_tests {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };

    use otpbar::{
        domain::error::ErrorEnvelope,
        ports::{Clipboard, ClipboardClearOutcome},
    };
    use tauri::{
        ipc::{CallbackFn, InvokeBody},
        test::{get_ipc_response, mock_builder, MockRuntime, INVOKE_KEY},
        webview::InvokeRequest,
        Manager, State, WebviewWindowBuilder,
    };

    use super::*;

    #[derive(Clone, Default)]
    struct MockClipboard {
        value: Arc<Mutex<Option<String>>>,
    }

    impl Clipboard for MockClipboard {
        fn read_text(&self) -> Result<Option<String>, ErrorEnvelope> {
            Ok(self.value.lock().expect("clipboard lock").clone())
        }

        fn write_text(&mut self, value: &str) -> Result<(), ErrorEnvelope> {
            *self.value.lock().expect("clipboard lock") = Some(value.to_owned());
            Ok(())
        }

        fn clear_if_text(
            &mut self,
            expected: &str,
        ) -> Result<ClipboardClearOutcome, ErrorEnvelope> {
            let mut value = self.value.lock().expect("clipboard lock");
            if value.as_deref() == Some(expected) {
                *value = None;
                Ok(ClipboardClearOutcome::Cleared)
            } else {
                Ok(ClipboardClearOutcome::Changed)
            }
        }
    }

    #[derive(Clone, Copy)]
    struct NoopLeaseEvents;

    impl LeaseEventSink for NoopLeaseEvents {
        fn publish(&self, _event: ClipboardLeaseEvent) {}
    }

    #[derive(Default)]
    struct DeniedPluginCall(AtomicBool);

    mod clipboard_plugin {
        use super::*;

        #[tauri::command]
        pub fn clear(called: State<'_, DeniedPluginCall>) {
            called.0.store(true, Ordering::SeqCst);
        }

        pub fn init() -> tauri::plugin::TauriPlugin<MockRuntime> {
            tauri::plugin::Builder::new("clipboard-manager")
                .invoke_handler(tauri::generate_handler![clear])
                .build()
        }
    }

    fn invoke_request(command: &str, body: serde_json::Value) -> InvokeRequest {
        InvokeRequest {
            cmd: command.to_owned(),
            callback: CallbackFn(0),
            error: CallbackFn(1),
            url: "tauri://localhost".parse().expect("valid local Tauri URL"),
            body: InvokeBody::Json(body),
            headers: Default::default(),
            invoke_key: INVOKE_KEY.to_owned(),
        }
    }

    fn test_app(clipboard: MockClipboard) -> (tauri::App<MockRuntime>, Arc<MockClipboard>) {
        let observed_clipboard = Arc::new(clipboard.clone());
        let actor = spawn_clipboard_actor(clipboard, SystemClock, NoopLeaseEvents);
        let app = mock_builder()
            .plugin(clipboard_plugin::init())
            .manage(AppState {
                recent_codes: tokio::sync::Mutex::new(Vec::new()),
                clipboard_config: tokio::sync::Mutex::new(ClipboardConfig::default()),
                privacy_preferences: tokio::sync::Mutex::new(PrivacyPreferences::default()),
            })
            .manage(actor)
            .manage(DeniedPluginCall::default())
            .invoke_handler(tauri::generate_handler![copy_code, copy_code_with_expiry])
            .build(app_context())
            .expect("mock Tauri app builds");
        (app, observed_clipboard)
    }

    fn main_webview(app: &tauri::App<MockRuntime>) -> tauri::WebviewWindow<MockRuntime> {
        app.get_webview_window("main").unwrap_or_else(|| {
            WebviewWindowBuilder::new(app, "main", Default::default())
                .build()
                .expect("main mock webview builds")
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn main_webview_acl_allows_copy_command_and_reaches_handler() {
        let (app, clipboard) = test_app(MockClipboard::default());
        let webview = main_webview(&app);

        let response = get_ipc_response(
            &webview,
            invoke_request("copy_code", serde_json::json!({ "code": "123456" })),
        )
        .expect("copy command is allowed")
        .deserialize::<serde_json::Value>()
        .expect("copy response is JSON");

        assert_eq!(
            response,
            serde_json::json!({ "status": "success", "data": true })
        );
        assert_eq!(
            clipboard.value.lock().expect("clipboard lock").as_deref(),
            Some("123456")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn main_webview_acl_denies_direct_clipboard_plugin_command() {
        let (app, _) = test_app(MockClipboard::default());
        let webview = main_webview(&app);

        let error = get_ipc_response(
            &webview,
            invoke_request("plugin:clipboard-manager|clear", serde_json::json!({})),
        )
        .expect_err("direct clipboard clear must be denied");

        assert!(
            error.to_string().contains("not allowed"),
            "unexpected ACL error: {error}"
        );
        assert!(
            !app.state::<DeniedPluginCall>().0.load(Ordering::SeqCst),
            "denied plugin handler must not execute"
        );
    }
}
