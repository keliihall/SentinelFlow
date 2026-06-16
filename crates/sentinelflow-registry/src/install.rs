//! Safe, idempotent plugin installation.

use std::fs;
use std::path::{Path, PathBuf};

use crate::{RegistryError, validate_plugin};

/// Outcome of installing a plugin package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InstallOutcome {
    /// Plugin was copied into the workspace.
    Installed(PathBuf),
    /// The same name and version were already installed.
    AlreadyInstalled(PathBuf),
}

/// Validates and installs a plugin beneath `plugins_root`.
///
/// Existing same-name/same-version packages are preserved and treated as success.
/// Different versions produce a conflict and no files are changed.
///
/// # Errors
///
/// Returns validation, version-conflict, or filesystem errors.
pub fn install_plugin(
    source: impl AsRef<Path>,
    plugins_root: impl AsRef<Path>,
) -> Result<InstallOutcome, RegistryError> {
    let source = source.as_ref();
    let validated = validate_plugin(source)?.into_validated()?;
    let name = validated.manifest.metadata.name.clone();
    let version = validated.manifest.spec.version.clone();
    let plugins_root = plugins_root.as_ref();
    fs::create_dir_all(plugins_root).map_err(|error| RegistryError::io(plugins_root, error))?;
    let destination = plugins_root.join(&name);

    if destination.exists() {
        let existing = validate_plugin(&destination)?.into_validated()?;
        if existing.manifest.spec.version == version {
            return Ok(InstallOutcome::AlreadyInstalled(destination));
        }
        return Err(RegistryError::VersionConflict {
            tool: name,
            existing: existing.manifest.spec.version,
            incoming: version,
        });
    }

    let staging = plugins_root.join(format!(".{name}.install.tmp"));
    if staging.exists() {
        fs::remove_dir_all(&staging).map_err(|error| RegistryError::io(&staging, error))?;
    }
    copy_directory(source, &staging)?;
    if let Err(error) = fs::rename(&staging, &destination) {
        let _ = fs::remove_dir_all(&staging);
        return Err(RegistryError::io(&destination, error));
    }
    Ok(InstallOutcome::Installed(destination))
}

fn copy_directory(source: &Path, destination: &Path) -> Result<(), RegistryError> {
    fs::create_dir(destination).map_err(|error| RegistryError::io(destination, error))?;
    let entries = fs::read_dir(source).map_err(|error| RegistryError::io(source, error))?;
    for entry in entries {
        let entry = entry.map_err(|error| RegistryError::io(source, error))?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry
            .file_type()
            .map_err(|error| RegistryError::io(&source_path, error))?;
        if file_type.is_symlink() {
            return Err(RegistryError::InvalidPlugin {
                path: source.to_path_buf(),
                message: format!(
                    "symbolic links are not installable: {}",
                    source_path.display()
                ),
            });
        }
        if file_type.is_dir() {
            copy_directory(&source_path, &destination_path)?;
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path)
                .map_err(|error| RegistryError::io(&source_path, error))?;
        }
    }
    Ok(())
}
