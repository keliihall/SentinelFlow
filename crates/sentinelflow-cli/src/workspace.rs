//! Local workspace initialization.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::CliError;
use crate::config;

const DIRECTORIES: [&str; 8] = [
    "plugins", "tools", "tasks", "runs", "results", "reports", "audit", "logs",
];

/// Initializes a workspace without replacing an existing configuration.
///
/// # Errors
///
/// Returns a system error if a required directory or initial configuration cannot
/// be created.
pub fn initialize(workspace_dir: &Path) -> Result<(), CliError> {
    fs::create_dir_all(workspace_dir).map_err(|error| {
        CliError::system(
            format!("failed to create {}: {error}", workspace_dir.display()),
            Some("$.workspace".to_owned()),
        )
    })?;

    for directory in DIRECTORIES {
        let path = workspace_dir.join(directory);
        fs::create_dir_all(&path).map_err(|error| {
            CliError::system(
                format!("failed to create {}: {error}", path.display()),
                Some("$.workspace".to_owned()),
            )
        })?;
    }

    let config_path = workspace_dir.join("config.yaml");
    let yaml = config::initial_yaml(workspace_dir)?;
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&config_path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(()),
        Err(error) => {
            return Err(CliError::system(
                format!("failed to create {}: {error}", config_path.display()),
                Some("$.config".to_owned()),
            ));
        }
    };
    file.write_all(yaml.as_bytes()).map_err(|error| {
        CliError::system(
            format!("failed to write {}: {error}", config_path.display()),
            Some("$.config".to_owned()),
        )
    })
}
