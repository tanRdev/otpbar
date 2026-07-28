use std::{collections::BTreeSet, fs, path::PathBuf};

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn permissions(value: &serde_json::Value) -> BTreeSet<String> {
    value["permissions"]
        .as_array()
        .expect("permissions is an array")
        .iter()
        .map(|entry| entry.as_str().expect("string permission").to_owned())
        .collect()
}

#[test]
fn main_capability_inventory_allows_copy_commands_and_no_clipboard_plugin_commands() {
    let capability = fs::read_to_string(crate_root().join("capabilities/main.json"))
        .expect("main capability exists");
    let value: serde_json::Value =
        serde_json::from_str(&capability).expect("valid capability JSON");
    let permissions = permissions(&value);

    assert_eq!(value["windows"], serde_json::json!(["main"]));
    let expected = [
        "core:event:allow-listen",
        "core:event:allow-unlisten",
        "allow-get-codes",
        "allow-get-auth-status",
        "allow-start-auth",
        "allow-copy-code",
        "allow-copy-code-with-expiry",
        "allow-logout",
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
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    assert_eq!(permissions, expected);
    assert!(
        permissions
            .iter()
            .all(|permission| !permission.starts_with("clipboard-manager:allow-")),
        "the webview must not receive direct clipboard plugin access"
    );
}

#[test]
fn generated_runtime_acl_contains_exact_copy_allow_and_deny_rules() {
    let manifests = fs::read_to_string(crate_root().join("gen/schemas/acl-manifests.json"))
        .expect("generated ACL manifest exists");
    let manifests: serde_json::Value =
        serde_json::from_str(&manifests).expect("valid generated ACL JSON");
    let app_permissions = &manifests["__app-acl__"]["permissions"];

    for command in ["copy_code", "copy_code_with_expiry"] {
        let slug = command.replace('_', "-");
        assert_eq!(
            app_permissions[format!("allow-{slug}")]["commands"],
            serde_json::json!({ "allow": [command], "deny": [] })
        );
        assert_eq!(
            app_permissions[format!("deny-{slug}")]["commands"],
            serde_json::json!({ "allow": [], "deny": [command] })
        );
    }

    assert_eq!(
        manifests["clipboard-manager"]["default_permission"]["permissions"],
        serde_json::json!([])
    );
    assert_eq!(
        manifests["clipboard-manager"]["permissions"]["deny-clear"]["commands"]["deny"],
        serde_json::json!(["clear"])
    );
    assert_eq!(
        manifests["clipboard-manager"]["permissions"]["deny-read-text"]["commands"]["deny"],
        serde_json::json!(["read_text"])
    );
}
