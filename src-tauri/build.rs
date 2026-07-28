fn main() {
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "get_codes",
            "get_auth_status",
            "start_auth",
            "copy_code",
            "copy_code_with_expiry",
            "logout",
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
