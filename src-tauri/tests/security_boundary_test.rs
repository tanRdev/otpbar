use std::{collections::BTreeSet, fs, path::PathBuf};

use tauri::{
    ipc::{CallbackFn, InvokeBody},
    test::{get_ipc_response, mock_builder, MockRuntime, INVOKE_KEY},
    webview::InvokeRequest,
    Manager, WebviewWindowBuilder,
};

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_json(path: &str) -> serde_json::Value {
    let source = fs::read_to_string(crate_root().join(path)).expect("configuration file exists");
    serde_json::from_str(&source).expect("configuration is valid JSON")
}

#[tauri::command]
fn get_codes() -> &'static str {
    "declared"
}

#[tauri::command]
fn begin_authorization() -> &'static str {
    "authorization declared"
}

#[tauri::command]
fn get_authorization_status() -> &'static str {
    "authorization declared"
}

#[tauri::command]
fn cancel_authorization() -> &'static str {
    "authorization declared"
}

#[tauri::command]
fn disconnect_authorization() -> &'static str {
    "authorization declared"
}

#[tauri::command]
fn delete_all_local_data() -> &'static str {
    "must remain unreachable"
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

fn app_context() -> tauri::Context<MockRuntime> {
    tauri::generate_context!()
}

#[test]
fn production_csp_allows_only_bundled_scripts_and_required_local_protocols() {
    let config = read_json("tauri.conf.json");
    let csp = &config["app"]["security"]["csp"];

    assert_eq!(
        csp,
        &serde_json::json!({
            "default-src": ["'self'"],
            "script-src": ["'self'"],
            "style-src": ["'self'", "'unsafe-inline'"],
            "img-src": ["'self'", "data:"],
            "font-src": ["'self'"],
            "connect-src": ["ipc:", "http://ipc.localhost"],
            "object-src": ["'none'"],
            "base-uri": ["'none'"],
            "form-action": ["'none'"],
            "frame-src": ["'none'"],
            "frame-ancestors": ["'none'"]
        })
    );

    let script_sources = csp["script-src"].as_array().expect("script-src array");
    assert!(!script_sources.iter().any(|source| {
        matches!(
            source.as_str(),
            Some("'unsafe-inline'" | "'unsafe-eval'" | "http:" | "https:" | "*")
        )
    }));
    assert_eq!(config["app"]["security"]["freezePrototype"], true);
    assert_eq!(
        config["app"]["security"]["dangerousDisableAssetCspModification"],
        false
    );
}

#[test]
fn sole_main_window_has_only_event_listening_and_registered_app_commands() {
    let capability = read_json("capabilities/main.json");
    let actual = capability["permissions"]
        .as_array()
        .expect("permissions array")
        .iter()
        .map(|permission| permission.as_str().expect("permission string"))
        .collect::<BTreeSet<_>>();
    let expected = [
        "core:event:allow-listen",
        "core:event:allow-unlisten",
        "allow-get-codes",
        "allow-get-authorization-status",
        "allow-begin-authorization",
        "allow-cancel-authorization",
        "allow-disconnect-authorization",
        "allow-copy-code",
        "allow-copy-code-with-expiry",
        "allow-quit-app",
        "allow-hide-window",
        "allow-extract-provider",
        "allow-get-clipboard-config",
        "allow-set-clipboard-timeout",
        "allow-get-privacy-data",
        "allow-clear-history",
        "allow-get-preferences",
        "allow-set-auto-copy-enabled",
        "allow-set-provider-auto-copy",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();

    assert_eq!(capability["windows"], serde_json::json!(["main"]));
    assert!(capability.get("webviews").is_none());
    assert_eq!(actual, expected);
    assert!(!actual.iter().any(|permission| {
        permission.starts_with("shell:")
            || permission.starts_with("opener:")
            || permission.starts_with("notification:")
            || permission.starts_with("clipboard-manager:")
            || permission == &"core:default"
    }));
}

#[test]
fn production_bundle_loads_only_the_main_capability_and_bundled_frontend() {
    let config = read_json("tauri.conf.json");
    let windows = config["app"]["windows"].as_array().expect("windows array");

    assert_eq!(windows.len(), 1);
    assert_eq!(windows[0]["label"], "main");
    assert!(windows[0].get("url").is_none());
    assert_eq!(
        config["app"]["security"]["capabilities"],
        serde_json::json!(["main"])
    );
    assert_eq!(config["build"]["frontendDist"], "../dist");
    assert_eq!(config["bundle"]["active"], true);
}

#[test]
fn real_tauri_acl_allows_declared_main_command_and_denies_other_authority() {
    let app = mock_builder()
        .invoke_handler(tauri::generate_handler![
            get_codes,
            get_authorization_status,
            begin_authorization,
            cancel_authorization,
            disconnect_authorization,
            delete_all_local_data
        ])
        .build(app_context())
        .expect("mock Tauri app builds from production context");
    let main = app.get_webview_window("main").unwrap_or_else(|| {
        WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("main mock webview builds")
    });
    let secondary = WebviewWindowBuilder::new(&app, "secondary", Default::default())
        .build()
        .expect("secondary mock webview builds");

    let allowed = get_ipc_response(&main, invoke_request("get_codes", serde_json::json!({})))
        .expect("declared command is allowed for main")
        .deserialize::<String>()
        .expect("declared response is a string");
    assert_eq!(allowed, "declared");
    for command in [
        "get_authorization_status",
        "begin_authorization",
        "cancel_authorization",
        "disconnect_authorization",
    ] {
        let authorization = get_ipc_response(&main, invoke_request(command, serde_json::json!({})))
            .expect("declared Authorization command is allowed")
            .deserialize::<String>()
            .expect("Authorization response is a string");
        assert_eq!(authorization, "authorization declared");
    }

    let secondary_error = get_ipc_response(
        &secondary,
        invoke_request("get_codes", serde_json::json!({})),
    )
    .expect_err("window outside the capability must be denied");
    assert!(secondary_error.to_string().contains("not allowed"));

    let unwired_error = get_ipc_response(
        &main,
        invoke_request("delete_all_local_data", serde_json::json!({})),
    )
    .expect_err("unregistered sensitive command must not be granted");
    assert!(unwired_error.to_string().contains("not allowed"));
}

#[test]
fn real_tauri_acl_allows_only_the_two_core_event_operations_the_ui_uses() {
    let app = mock_builder()
        .build(app_context())
        .expect("mock Tauri app builds from production context");
    let main = app.get_webview_window("main").unwrap_or_else(|| {
        WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("main mock webview builds")
    });

    let listener_id = get_ipc_response(
        &main,
        invoke_request(
            "plugin:event|listen",
            serde_json::json!({
                "event": "codes-updated",
                "target": { "kind": "Any" },
                "handler": 7
            }),
        ),
    )
    .expect("event listen is allowed")
    .deserialize::<u32>()
    .expect("listener id is returned");
    get_ipc_response(
        &main,
        invoke_request(
            "plugin:event|unlisten",
            serde_json::json!({
                "event": "codes-updated",
                "eventId": listener_id
            }),
        ),
    )
    .expect("event unlisten is allowed");

    let emit_error = get_ipc_response(
        &main,
        invoke_request(
            "plugin:event|emit",
            serde_json::json!({
                "event": "forged-event",
                "payload": null
            }),
        ),
    )
    .expect_err("frontend event emission is outside the declared capability");
    assert!(emit_error.to_string().contains("not allowed"));
}

#[test]
fn build_manifest_generated_schema_and_capability_share_one_exact_inventory() {
    let capability = read_json("capabilities/main.json");
    let generated = read_json("gen/schemas/capabilities.json");
    assert_eq!(generated["main"]["windows"], capability["windows"]);
    assert_eq!(generated["main"]["permissions"], capability["permissions"]);

    let build_source =
        fs::read_to_string(crate_root().join("build.rs")).expect("build manifest exists");
    let commands_block = build_source
        .split_once(".commands(&[")
        .and_then(|(_, rest)| rest.split_once("])"))
        .map(|(block, _)| block)
        .expect("build manifest has one command inventory");
    let build_commands = commands_block
        .lines()
        .filter_map(|line| line.trim().strip_prefix('"'))
        .filter_map(|line| line.strip_suffix("\","))
        .collect::<BTreeSet<_>>();
    let capability_commands = capability["permissions"]
        .as_array()
        .expect("permissions array")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .filter_map(|permission| permission.strip_prefix("allow-"))
        .map(|slug| slug.replace('-', "_"))
        .collect::<BTreeSet<_>>();

    assert_eq!(
        build_commands,
        capability_commands
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
    );
}

#[test]
fn production_authorization_embeds_only_the_public_client_id() {
    let build = fs::read_to_string(crate_root().join("build.rs")).expect("build script exists");
    let google = fs::read_to_string(crate_root().join("src/authorization/google.rs"))
        .expect("Google adapter exists");
    let main = fs::read_to_string(crate_root().join("src/main.rs")).expect("main exists");

    assert!(build.contains("cargo:rustc-env=GOOGLE_CLIENT_ID="));
    assert!(google.contains("option_env!(\"GOOGLE_CLIENT_ID\")"));
    assert!(!build.contains("GOOGLE_CLIENT_SECRET"));
    assert!(!google.contains("GOOGLE_CLIENT_SECRET"));
    assert!(!main.contains("GOOGLE_CLIENT_SECRET"));
    assert!(!crate_root().join("src/gmail.rs").exists());
    assert!(!crate_root().join("src/keychain.rs").exists());
}
