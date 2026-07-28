use std::{env, fs};

fn main() {
    println!("cargo:rerun-if-env-changed=GOOGLE_CLIENT_ID");
    println!("cargo:rerun-if-changed=../.env");
    if let Some(client_id) = build_client_id() {
        println!("cargo:rustc-env=GOOGLE_CLIENT_ID={client_id}");
    }

    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "get_codes",
            "get_authorization_status",
            "begin_authorization",
            "cancel_authorization",
            "disconnect_authorization",
            "copy_code",
            "copy_code_with_expiry",
            "quit_app",
            "hide_window",
            "extract_provider",
            "get_clipboard_config",
            "set_clipboard_timeout",
            "get_privacy_data",
            "clear_history",
            "get_preferences",
            "set_auto_copy_enabled",
            "set_provider_auto_copy",
        ]),
    ))
    .expect("failed to build Tauri permissions");
}

fn build_client_id() -> Option<String> {
    env::var("GOOGLE_CLIENT_ID")
        .ok()
        .or_else(|| {
            fs::read_to_string("../.env").ok().and_then(|source| {
                source.lines().find_map(|line| {
                    line.strip_prefix("GOOGLE_CLIENT_ID=")
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_owned)
                })
            })
        })
        .filter(|value| !value.contains(['\r', '\n']))
}
