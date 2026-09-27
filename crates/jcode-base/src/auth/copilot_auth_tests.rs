use super::*;
use anyhow::{Result, anyhow};

use tempfile::TempDir;

const COPILOT_FIXTURE_ENV_KEYS: [&str; 9] = [
    "HOME",
    "JCODE_HOME",
    "XDG_CONFIG_HOME",
    "TMPDIR",
    "COPILOT_GITHUB_TOKEN",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "JCODE_COPILOT_ALLOW_GH_AUTH_TOKEN",
    "JCODE_TRUSTED_EXTERNAL_AUTH_SOURCES",
];

struct CopilotFixtureEnv {
    previous: Vec<(&'static str, Option<std::ffi::OsString>)>,
    jcode_home: PathBuf,
}

impl CopilotFixtureEnv {
    fn new(root: &Path) -> Result<Self> {
        let root = root.canonicalize()?;
        let home = root.join("home");
        let tmp = root.join("tmp");
        std::fs::create_dir_all(&home)?;
        std::fs::create_dir_all(&tmp)?;
        let guard = Self {
            previous: COPILOT_FIXTURE_ENV_KEYS
                .into_iter()
                .map(|key| (key, std::env::var_os(key)))
                .collect(),
            jcode_home: root.join("jcode-home"),
        };
        crate::env::set_var("HOME", home);
        crate::env::set_var("TMPDIR", tmp);
        crate::env::set_var("JCODE_HOME", &guard.jcode_home);
        crate::env::set_var(
            "XDG_CONFIG_HOME",
            guard.jcode_home.join("external").join(".config"),
        );
        for key in &COPILOT_FIXTURE_ENV_KEYS[4..] {
            crate::env::remove_var(key);
        }
        crate::config::Config::invalidate_cache();
        crate::auth::AuthStatus::invalidate_cache();
        Ok(guard)
    }
}

impl Drop for CopilotFixtureEnv {
    fn drop(&mut self) {
        for (key, previous) in self.previous.drain(..).rev() {
            match previous {
                Some(value) => crate::env::set_var(key, value),
                None => crate::env::remove_var(key),
            }
        }
        crate::config::Config::invalidate_cache();
        crate::auth::AuthStatus::invalidate_cache();
    }
}

#[test]
fn copilot_api_token_not_expired() {
    let future_ts = chrono::Utc::now().timestamp() + 3600;
    let token = CopilotApiToken {
        token: "test-token".to_string(),
        expires_at: future_ts,
    };
    assert!(!token.is_expired());
}

#[test]
fn copilot_api_token_expired() {
    let past_ts = chrono::Utc::now().timestamp() - 100;
    let token = CopilotApiToken {
        token: "test-token".to_string(),
        expires_at: past_ts,
    };
    assert!(token.is_expired());
}

#[test]
fn copilot_api_token_expiring_within_buffer() {
    let almost_ts = chrono::Utc::now().timestamp() + 30;
    let token = CopilotApiToken {
        token: "test-token".to_string(),
        expires_at: almost_ts,
    };
    assert!(token.is_expired());
}

#[test]
fn load_token_from_hosts_json() -> Result<()> {
    let dir = TempDir::new().map_err(|e| anyhow!(e))?;
    let hosts_path = dir.path().join("hosts.json");
    let data = serde_json::json!({
        "github.com": {
            "oauth_token": "gho_testtoken123",
            "user": "testuser"
        }
    });
    std::fs::write(&hosts_path, serde_json::to_string(&data)?)?;

    let token = load_token_from_json(&hosts_path.to_path_buf())?;
    assert_eq!(token, "gho_testtoken123");
    Ok(())
}

#[test]
fn load_token_from_apps_json() -> Result<()> {
    let dir = TempDir::new().map_err(|e| anyhow!(e))?;
    let apps_path = dir.path().join("apps.json");
    let data = serde_json::json!({
        "github.com": {
            "oauth_token": "ghu_vscodetoken456"
        }
    });
    std::fs::write(&apps_path, serde_json::to_string(&data)?)?;

    let token = load_token_from_json(&apps_path.to_path_buf())?;
    assert_eq!(token, "ghu_vscodetoken456");
    Ok(())
}

#[test]
fn load_token_missing_oauth_token_field() -> Result<()> {
    let dir = TempDir::new().map_err(|e| anyhow!(e))?;
    let path = dir.path().join("hosts.json");
    let data = serde_json::json!({
        "github.com": {
            "user": "testuser"
        }
    });
    std::fs::write(&path, serde_json::to_string(&data)?)?;

    let result = load_token_from_json(&path.to_path_buf());
    assert!(result.is_err());
    Ok(())
}

#[test]
fn load_token_empty_oauth_token() -> Result<()> {
    let dir = TempDir::new().map_err(|e| anyhow!(e))?;
    let path = dir.path().join("hosts.json");
    let data = serde_json::json!({
        "github.com": {
            "oauth_token": "",
            "user": "testuser"
        }
    });
    std::fs::write(&path, serde_json::to_string(&data)?)?;

    let result = load_token_from_json(&path.to_path_buf());
    assert!(result.is_err());
    Ok(())
}

#[test]
fn load_token_nonexistent_file() {
    let path = PathBuf::from("/tmp/nonexistent_auth_test_file.json");
    let result = load_token_from_json(&path);
    assert!(result.is_err());
}

#[test]
fn load_token_invalid_json() -> Result<()> {
    let dir = TempDir::new().map_err(|e| anyhow!(e))?;
    let path = dir.path().join("hosts.json");
    std::fs::write(&path, "not valid json{{{")?;

    let result = load_token_from_json(&path.to_path_buf());
    assert!(result.is_err());
    Ok(())
}

#[test]
fn load_token_from_copilot_config_json() -> Result<()> {
    let dir = TempDir::new().map_err(|e| anyhow!(e))?;
    let path = dir.path().join("config.json");
    std::fs::write(
        &path,
        serde_json::json!({
            "auth": {
                "token": "ghu_config_token"
            }
        })
        .to_string(),
    )?;

    let token = load_token_from_config_json(&path)?;
    assert_eq!(token, "ghu_config_token");
    Ok(())
}

#[test]
fn normalize_candidate_token_rejects_empty_and_unknown_values() {
    assert_eq!(
        normalize_candidate_token("gho_valid"),
        Some("gho_valid".to_string())
    );
    assert_eq!(
        normalize_candidate_token("ghu_valid"),
        Some("ghu_valid".to_string())
    );
    assert_eq!(
        normalize_candidate_token("github_pat_valid"),
        Some("github_pat_valid".to_string())
    );
    assert_eq!(normalize_candidate_token("ghp_classic"), None);
    assert_eq!(normalize_candidate_token("   "), None);
}

#[test]
fn gh_cli_fallback_requires_explicit_opt_in() {
    let key = "JCODE_COPILOT_ALLOW_GH_AUTH_TOKEN";
    let previous = std::env::var_os(key);

    crate::env::remove_var(key);
    assert!(!allow_gh_cli_fallback());

    crate::env::set_var(key, "0");
    assert!(!allow_gh_cli_fallback());

    crate::env::set_var(key, "1");
    assert!(allow_gh_cli_fallback());

    if let Some(previous) = previous {
        crate::env::set_var(key, previous);
    } else {
        crate::env::remove_var(key);
    }
}

#[test]
fn save_and_load_github_token() -> Result<()> {
    let dir = TempDir::new().map_err(|e| anyhow!(e))?;
    let config_dir = dir.path().join("github-copilot");
    std::fs::create_dir_all(&config_dir)?;

    let hosts_path = config_dir.join("hosts.json");

    let mut config: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut entry = HashMap::new();
    entry.insert("user".to_string(), "testuser".to_string());
    entry.insert("oauth_token".to_string(), "gho_saved_token".to_string());
    config.insert("github.com".to_string(), entry);

    let json = serde_json::to_string_pretty(&config)?;
    std::fs::write(&hosts_path, json)?;

    let loaded = load_token_from_json(&hosts_path.to_path_buf())?;
    assert_eq!(loaded, "gho_saved_token");
    Ok(())
}

#[test]
fn save_github_token_creates_config_dir() -> Result<()> {
    let _guard = crate::storage::lock_test_env();
    let dir = TempDir::new().map_err(|e| anyhow!(e))?;
    let previous: Vec<_> = COPILOT_FIXTURE_ENV_KEYS
        .into_iter()
        .map(|key| (key, std::env::var_os(key)))
        .collect();
    {
        let env = CopilotFixtureEnv::new(dir.path())?;
        let config_dir = env
            .jcode_home
            .join("external")
            .join(".config")
            .join("github-copilot");

        // Pin the XDG fallback, then restore the explicit sandbox for the trust
        // write. Both routes must save to exactly the same hosts.json path.
        crate::env::remove_var("JCODE_HOME");
        assert_eq!(legacy_copilot_config_dir(), config_dir);
        crate::env::set_var("JCODE_HOME", &env.jcode_home);
        assert_eq!(legacy_copilot_config_dir(), config_dir);

        let config_path = env.jcode_home.join("config.toml");
        assert_eq!(crate::config::Config::path(), Some(config_path.clone()));
        assert!(
            !config_dir.exists(),
            "token directory must be created by save"
        );
        assert!(!config_path.exists(), "trust config must be created by save");
        save_github_token("gho_newtoken", "testuser")?;

        let hosts_path = config_dir.join("hosts.json");
        assert_eq!(saved_hosts_path(), hosts_path);
        let root = dir.path().canonicalize()?;
        assert!(hosts_path.canonicalize()?.starts_with(&root));
        assert!(config_path.canonicalize()?.starts_with(&root));
        assert_eq!(load_token_from_json(&hosts_path)?, "gho_newtoken");
        let saved: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&hosts_path)?)?;
        assert_eq!(saved["github.com"]["user"], "testuser");

        let cfg = crate::config::Config::load_strict()?;
        assert_eq!(
            cfg.auth.trusted_external_source_paths,
            vec![format!(
                "{}|{}",
                COPILOT_HOSTS_AUTH_SOURCE_ID,
                hosts_path
                    .canonicalize()?
                    .to_string_lossy()
                    .to_ascii_lowercase()
            )]
        );
        assert!(cfg.auth.trusted_external_sources.is_empty());
        assert!(crate::config::Config::external_auth_source_allowed_for_path(
            COPILOT_HOSTS_AUTH_SOURCE_ID,
            &hosts_path
        ));
        assert_eq!(load_github_token()?, "gho_newtoken");
    }
    for (key, value) in previous {
        assert!(std::env::var_os(key) == value, "fixture must restore {key}");
    }
    Ok(())
}

#[test]
fn copilot_fixture_restores_environment_on_unwind() -> Result<()> {
    let _guard = crate::storage::lock_test_env();
    let dir = TempDir::new()?;
    let previous: Vec<_> = COPILOT_FIXTURE_ENV_KEYS
        .into_iter()
        .map(|key| (key, std::env::var_os(key)))
        .collect();
    let previous_config_path = crate::config::Config::path();
    let unwind = std::panic::catch_unwind(|| -> () {
        let _env = CopilotFixtureEnv::new(dir.path()).expect("private fixture environment");
        std::panic::resume_unwind(Box::new(()));
    });
    assert!(unwind.is_err());
    for (key, value) in previous {
        assert!(std::env::var_os(key) == value, "unwind must restore {key}");
    }
    assert_eq!(crate::config::Config::path(), previous_config_path);
    Ok(())
}

#[test]
fn legacy_copilot_config_dir_uses_jcode_home_external_dir() -> Result<()> {
    let _guard = crate::storage::lock_test_env();
    let dir = TempDir::new().map_err(|e| anyhow!(e))?;
    let prev = std::env::var_os("JCODE_HOME");
    crate::env::set_var("JCODE_HOME", dir.path());

    let path = legacy_copilot_config_dir();
    assert_eq!(
        path,
        dir.path()
            .join("external")
            .join(".config")
            .join("github-copilot")
    );

    if let Some(prev) = prev {
        crate::env::set_var("JCODE_HOME", prev);
    } else {
        crate::env::remove_var("JCODE_HOME");
    }
    Ok(())
}

#[test]
fn save_github_token_makes_future_loads_available() -> Result<()> {
    let _guard = crate::storage::lock_test_env();
    let dir = TempDir::new().map_err(|e| anyhow!(e))?;
    let prev_jcode_home = std::env::var_os("JCODE_HOME");
    let prev_xdg_config_home = std::env::var_os("XDG_CONFIG_HOME");

    crate::env::set_var("JCODE_HOME", dir.path());
    crate::env::remove_var("XDG_CONFIG_HOME");

    save_github_token("gho_persisted_token", "testuser")?;

    let hosts_path = ExternalCopilotAuthSource::HostsJson.path();
    assert!(
        crate::config::Config::external_auth_source_allowed_for_path(
            COPILOT_HOSTS_AUTH_SOURCE_ID,
            &hosts_path
        )
    );
    assert_eq!(load_github_token()?, "gho_persisted_token");

    if let Some(prev) = prev_jcode_home {
        crate::env::set_var("JCODE_HOME", prev);
    } else {
        crate::env::remove_var("JCODE_HOME");
    }

    if let Some(prev) = prev_xdg_config_home {
        crate::env::set_var("XDG_CONFIG_HOME", prev);
    } else {
        crate::env::remove_var("XDG_CONFIG_HOME");
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn load_token_from_json_does_not_change_external_permissions() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().map_err(|e| anyhow!(e))?;
    let path = dir.path().join("hosts.json");
    std::fs::write(
        &path,
        r#"{"github.com":{"oauth_token":"gho_test","user":"tester"}}"#,
    )?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;

    let token = load_token_from_json(&path)?;
    assert_eq!(token, "gho_test");

    let dir_mode = std::fs::metadata(dir.path())?.permissions().mode() & 0o777;
    let file_mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o755);
    assert_eq!(file_mode, 0o644);
    Ok(())
}

#[test]
fn choose_default_model_with_opus() {
    let models = vec![
        CopilotModelInfo {
            id: "claude-sonnet-4".to_string(),
            name: String::new(),
            vendor: String::new(),
            version: String::new(),
            model_picker_enabled: false,
            capabilities: Default::default(),
        },
        CopilotModelInfo {
            id: "claude-opus-4.6".to_string(),
            name: String::new(),
            vendor: String::new(),
            version: String::new(),
            model_picker_enabled: false,
            capabilities: Default::default(),
        },
    ];
    assert_eq!(choose_default_model(&models), "claude-opus-4.6");
}

#[test]
fn choose_default_model_without_opus() {
    let models = vec![CopilotModelInfo {
        id: "claude-sonnet-4.6".to_string(),
        name: String::new(),
        vendor: String::new(),
        version: String::new(),
        model_picker_enabled: false,
        capabilities: Default::default(),
    }];
    assert_eq!(choose_default_model(&models), "claude-sonnet-4.6");
}

#[test]
fn choose_default_model_with_sonnet_4_only() {
    let models = vec![CopilotModelInfo {
        id: "claude-sonnet-4".to_string(),
        name: String::new(),
        vendor: String::new(),
        version: String::new(),
        model_picker_enabled: false,
        capabilities: Default::default(),
    }];
    assert_eq!(choose_default_model(&models), "claude-sonnet-4");
}

#[test]
fn choose_default_model_empty_list() {
    let models: Vec<CopilotModelInfo> = vec![];
    assert_eq!(choose_default_model(&models), "claude-sonnet-4");
}

#[test]
fn copilot_account_type_display() {
    assert_eq!(CopilotAccountType::Individual.to_string(), "individual");
    assert_eq!(CopilotAccountType::Business.to_string(), "business");
    assert_eq!(CopilotAccountType::Enterprise.to_string(), "enterprise");
    assert_eq!(CopilotAccountType::Unknown.to_string(), "unknown");
}

#[test]
fn device_code_response_deserialize() -> Result<()> {
    let json = r#"{
            "device_code": "dc_1234",
            "user_code": "ABCD-1234",
            "verification_uri": "https://github.com/login/device",
            "expires_in": 900,
            "interval": 5
        }"#;
    let resp: DeviceCodeResponse = serde_json::from_str(json)?;
    assert_eq!(resp.device_code, "dc_1234");
    assert_eq!(resp.user_code, "ABCD-1234");
    assert_eq!(resp.verification_uri, "https://github.com/login/device");
    assert_eq!(resp.expires_in, 900);
    assert_eq!(resp.interval, 5);
    Ok(())
}

#[test]
fn access_token_response_success() -> Result<()> {
    let json = r#"{
            "access_token": "gho_xxx123",
            "token_type": "bearer",
            "scope": "read:user"
        }"#;
    let resp: AccessTokenResponse = serde_json::from_str(json)?;
    assert_eq!(
        resp.access_token
            .ok_or_else(|| anyhow!("missing access token"))?,
        "gho_xxx123"
    );
    assert!(resp.error.is_none());
    Ok(())
}

#[test]
fn access_token_response_pending() -> Result<()> {
    let json = r#"{
            "error": "authorization_pending",
            "error_description": "The authorization request is still pending."
        }"#;
    let resp: AccessTokenResponse = serde_json::from_str(json)?;
    assert!(resp.access_token.is_none());
    assert_eq!(
        resp.error.ok_or_else(|| anyhow!("missing error"))?,
        "authorization_pending"
    );
    Ok(())
}

#[test]
fn access_token_response_expired() -> Result<()> {
    let json = r#"{
            "error": "expired_token",
            "error_description": "The device code has expired."
        }"#;
    let resp: AccessTokenResponse = serde_json::from_str(json)?;
    assert_eq!(
        resp.error.ok_or_else(|| anyhow!("missing error"))?,
        "expired_token"
    );
    Ok(())
}

#[test]
fn copilot_token_response_roundtrip() -> Result<()> {
    let resp = CopilotTokenResponse {
        token: "bearer_token_xxx".to_string(),
        expires_at: 1700000000,
    };
    let json = serde_json::to_string(&resp)?;
    let parsed: CopilotTokenResponse = serde_json::from_str(&json)?;
    assert_eq!(parsed.token, "bearer_token_xxx");
    assert_eq!(parsed.expires_at, 1700000000);
    Ok(())
}

#[test]
fn copilot_model_info_deserialize() -> Result<()> {
    let json = r#"{
            "id": "claude-sonnet-4",
            "name": "Claude Sonnet 4",
            "vendor": "anthropic",
            "version": "2025-01-01",
            "model_picker_enabled": true,
            "capabilities": {
                "type": "chat",
                "family": "claude-sonnet-4"
            }
        }"#;
    let model: CopilotModelInfo = serde_json::from_str(json)?;
    assert_eq!(model.id, "claude-sonnet-4");
    assert_eq!(model.vendor, "anthropic");
    assert!(model.model_picker_enabled);
    Ok(())
}

#[test]
fn copilot_model_info_minimal() -> Result<()> {
    let json = r#"{"id": "gpt-4o"}"#;
    let model: CopilotModelInfo = serde_json::from_str(json)?;
    assert_eq!(model.id, "gpt-4o");
    assert_eq!(model.name, "");
    assert!(!model.model_picker_enabled);
    Ok(())
}

#[test]
fn load_token_multiple_hosts() -> Result<()> {
    let dir = TempDir::new().map_err(|e| anyhow!(e))?;
    let path = dir.path().join("hosts.json");
    let data = serde_json::json!({
        "api.github.com": {
            "oauth_token": "gho_api",
            "user": "user1"
        },
        "github.com": {
            "oauth_token": "gho_primary",
            "user": "user2"
        },
        "https://github.com/extra/path": {
            "oauth_token": "gho_path",
            "user": "user3"
        }
    });
    std::fs::write(&path, serde_json::to_string(&data)?)?;

    let token = load_token_from_json(&path.to_path_buf())?;
    assert_eq!(token, "gho_primary");
    Ok(())
}

#[test]
fn normalize_github_host_key_accepts_common_forms() {
    assert_eq!(
        normalize_github_host_key("https://github.com/login"),
        Some("github.com".to_string())
    );
    assert_eq!(
        normalize_github_host_key("api.github.com"),
        Some("api.github.com".to_string())
    );
    assert_eq!(
        normalize_github_host_key("sub.github.com/path"),
        Some("sub.github.com".to_string())
    );
}

#[test]
fn normalize_github_host_key_rejects_non_github_hosts() {
    assert_eq!(normalize_github_host_key("gitlab.com"), None);
    assert_eq!(normalize_github_host_key(""), None);
}

/// Regression test for issue #641: GitHub's `apps.json` keys carry a client-id
/// suffix after a colon. Those entries hold valid tokens and must normalize,
/// otherwise the credential is silently dropped and jcode falls through to a
/// possibly stale token from a lower-priority source.
#[test]
fn normalize_github_host_key_accepts_apps_json_client_id_suffix() {
    assert_eq!(
        normalize_github_host_key("github.com:Iv1.b507a08c87ecfe98"),
        Some("github.com".to_string())
    );
    assert_eq!(
        normalize_github_host_key("api.github.com:Iv1.b507a08c87ecfe98"),
        Some("api.github.com".to_string())
    );
    // A colon suffix does not make a non-GitHub host acceptable.
    assert_eq!(normalize_github_host_key("gitlab.com:Iv1.abc"), None);
}

#[test]
fn live_verify_failure_record_blocks_auto_use() -> Result<()> {
    // Lock the test env and isolate JCODE_HOME so the validation record we write
    // does not touch the developer's real auth-validation.json.
    let _guard = crate::storage::lock_test_env();
    let dir = TempDir::new().map_err(|e| anyhow!(e))?;
    let prev_jcode_home = std::env::var_os("JCODE_HOME");
    crate::env::set_var("JCODE_HOME", dir.path());

    // Ensure no env token is present, otherwise the gate short-circuits to
    // "allowed" regardless of the saved record.
    let prev_env: Vec<(&str, Option<std::ffi::OsString>)> =
        ["COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"]
            .into_iter()
            .map(|k| (k, std::env::var_os(k)))
            .collect();
    for (k, _) in &prev_env {
        crate::env::remove_var(k);
    }

    // A banned/ineligible account produces exactly this failure summary shape
    // from `exchange_github_token`; `verify_copilot_credentials_live` persists
    // it verbatim. The auto-use gate must treat it as blocking.
    let record = crate::auth::validation::ProviderValidationRecord {
        checked_at_ms: chrono::Utc::now().timestamp_millis(),
        success: false,
        provider_smoke_ok: Some(false),
        tool_smoke_ok: None,
        summary: "Copilot token exchange failed (HTTP 403): access blocked".to_string(),
    };
    crate::auth::validation::save("copilot", record)?;

    assert!(
        validation_failure_blocks_auto_use(),
        "a recent banned-account exchange failure must block auto-use"
    );

    // A successful exchange record must NOT block auto-use.
    let ok_record = crate::auth::validation::ProviderValidationRecord {
        checked_at_ms: chrono::Utc::now().timestamp_millis(),
        success: true,
        provider_smoke_ok: Some(true),
        tool_smoke_ok: None,
        summary: "copilot token exchange ok".to_string(),
    };
    crate::auth::validation::save("copilot", ok_record)?;
    assert!(
        !validation_failure_blocks_auto_use(),
        "a successful exchange must not block auto-use"
    );

    for (k, prev) in prev_env {
        if let Some(prev) = prev {
            crate::env::set_var(k, prev);
        }
    }
    if let Some(prev) = prev_jcode_home {
        crate::env::set_var("JCODE_HOME", prev);
    } else {
        crate::env::remove_var("JCODE_HOME");
    }
    Ok(())
}

#[test]
fn token_exchange_backoff_is_exponential_and_capped() {
    assert_eq!(super::token_exchange_backoff_ms(1), 500);
    assert_eq!(super::token_exchange_backoff_ms(2), 1_000);
    assert_eq!(super::token_exchange_backoff_ms(3), 2_000);
    assert_eq!(super::token_exchange_backoff_ms(4), 4_000);
    assert_eq!(super::token_exchange_backoff_ms(5), 4_000);
    assert_eq!(super::token_exchange_backoff_ms(100), 4_000);
}

#[test]
fn token_exchange_retries_only_5xx() {
    assert!(super::token_exchange_retryable_status(500));
    assert!(super::token_exchange_retryable_status(502));
    assert!(super::token_exchange_retryable_status(503));
    assert!(super::token_exchange_retryable_status(599));
    assert!(!super::token_exchange_retryable_status(400));
    assert!(!super::token_exchange_retryable_status(401));
    assert!(!super::token_exchange_retryable_status(403));
    assert!(!super::token_exchange_retryable_status(404));
    assert!(!super::token_exchange_retryable_status(429));
    assert!(!super::token_exchange_retryable_status(200));
}
