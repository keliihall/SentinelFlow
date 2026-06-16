//! Layered project configuration.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use sentinelflow_core::constants::{ENV_PREFIX, WORKSPACE_DIR};
use serde::{Deserialize, Serialize};

use crate::CliError;

const MASKED_VALUE: &str = "********";

/// CLI-level configuration overrides.
#[derive(Clone, Debug, Default)]
pub struct ConfigOverrides {
    pub workspace_dir: Option<PathBuf>,
    pub schema_root: Option<PathBuf>,
    pub log_level: Option<String>,
    pub api_endpoint: Option<String>,
    pub auth_token: Option<String>,
}

/// Fully merged CLI configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    /// Configuration format version.
    pub version: u32,
    /// Local `SentinelFlow` state directory.
    pub workspace_dir: PathBuf,
    /// Root used to resolve repository-relative protocol Schema paths.
    pub schema_root: PathBuf,
    /// Configured log verbosity.
    pub log_level: String,
    /// Optional future API endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_endpoint: Option<String>,
    /// Optional authentication token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PartialConfig {
    version: Option<u32>,
    workspace_dir: Option<PathBuf>,
    schema_root: Option<PathBuf>,
    log_level: Option<String>,
    api_endpoint: Option<String>,
    auth_token: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            workspace_dir: PathBuf::from(WORKSPACE_DIR),
            schema_root: PathBuf::from("."),
            log_level: "info".to_owned(),
            api_endpoint: None,
            auth_token: None,
        }
    }
}

impl Config {
    fn apply(&mut self, partial: PartialConfig) {
        if let Some(value) = partial.version {
            self.version = value;
        }
        if let Some(value) = partial.workspace_dir {
            self.workspace_dir = value;
        }
        if let Some(value) = partial.schema_root {
            self.schema_root = value;
        }
        if let Some(value) = partial.log_level {
            self.log_level = value;
        }
        if let Some(value) = partial.api_endpoint {
            self.api_endpoint = Some(value);
        }
        if let Some(value) = partial.auth_token {
            self.auth_token = Some(value);
        }
    }

    fn apply_overrides(&mut self, overrides: ConfigOverrides) {
        self.apply(PartialConfig {
            workspace_dir: overrides.workspace_dir,
            schema_root: overrides.schema_root,
            log_level: overrides.log_level,
            api_endpoint: overrides.api_endpoint,
            auth_token: overrides.auth_token,
            ..PartialConfig::default()
        });
    }

    /// Returns a copy safe to display in terminal output.
    #[must_use]
    pub fn redacted(&self) -> Self {
        let mut redacted = self.clone();
        if redacted.auth_token.is_some() {
            redacted.auth_token = Some(MASKED_VALUE.to_owned());
        }
        redacted
    }
}

/// Selects the workspace used to locate project configuration.
#[must_use]
pub fn bootstrap_workspace(overrides: &ConfigOverrides) -> PathBuf {
    overrides
        .workspace_dir
        .clone()
        .or_else(|| env_value("WORKSPACE_DIR").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(WORKSPACE_DIR))
}

/// Loads configuration in default, project, environment, and CLI order.
///
/// # Errors
///
/// Returns a system error for unreadable or invalid project configuration.
pub fn load(overrides: ConfigOverrides) -> Result<Config, CliError> {
    let config_path = bootstrap_workspace(&overrides).join("config.yaml");
    let mut config = Config::default();

    if config_path.exists() {
        let bytes = fs::read(&config_path).map_err(|error| {
            CliError::system(
                format!("failed to read {}: {error}", config_path.display()),
                Some("$.config".to_owned()),
            )
        })?;
        let project: PartialConfig = serde_yaml::from_slice(&bytes).map_err(|error| {
            CliError::system(
                format!("invalid configuration {}: {error}", config_path.display()),
                Some("$.config".to_owned()),
            )
        })?;
        config.apply(project);
    }

    config.apply(environment_config());
    config.apply_overrides(overrides);
    Ok(config)
}

/// Serializes a new project configuration.
///
/// # Errors
///
/// Returns a system error if YAML serialization fails.
pub fn initial_yaml(workspace_dir: &Path) -> Result<String, CliError> {
    let config = Config {
        workspace_dir: workspace_dir.to_path_buf(),
        ..Config::default()
    };
    serde_yaml::to_string(&config).map_err(|error| {
        CliError::system(
            format!("failed to serialize initial configuration: {error}"),
            Some("$.config".to_owned()),
        )
    })
}

fn environment_config() -> PartialConfig {
    PartialConfig {
        workspace_dir: env_value("WORKSPACE_DIR").map(PathBuf::from),
        schema_root: env_value("SCHEMA_ROOT").map(PathBuf::from),
        log_level: env_value("LOG_LEVEL"),
        api_endpoint: env_value("API_ENDPOINT"),
        auth_token: env_value("AUTH_TOKEN"),
        ..PartialConfig::default()
    }
}

fn env_value(suffix: &str) -> Option<String> {
    env::var(format!("{ENV_PREFIX}{suffix}")).ok()
}
