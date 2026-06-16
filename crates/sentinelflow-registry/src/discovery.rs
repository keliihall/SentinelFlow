//! Plugin directory discovery.

use std::fs;
use std::path::{Path, PathBuf};

use crate::RegistryError;

/// Safe directories discovered under one or more plugin roots.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DiscoveryResult {
    /// Candidate plugin directories.
    pub plugins: Vec<PathBuf>,
    /// Entries ignored due to naming, type, or symlink rules.
    pub ignored: Vec<PathBuf>,
}

/// Discovers immediate plugin directories beneath each root.
///
/// Missing roots are treated as empty. Hidden entries, temporary entries,
/// non-directories, and all symbolic links are ignored.
///
/// # Errors
///
/// Returns an I/O error when an existing root cannot be read.
pub fn discover_plugins<I, P>(roots: I) -> Result<DiscoveryResult, RegistryError>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let mut result = DiscoveryResult::default();

    for root in roots {
        let root = root.as_ref();
        if !root.exists() {
            continue;
        }

        let entries = fs::read_dir(root).map_err(|error| RegistryError::io(root, error))?;
        for entry in entries {
            let entry = entry.map_err(|error| RegistryError::io(root, error))?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let file_type = entry
                .file_type()
                .map_err(|error| RegistryError::io(&path, error))?;

            if is_ignored_name(&name) || file_type.is_symlink() || !file_type.is_dir() {
                result.ignored.push(path);
            } else {
                result.plugins.push(path);
            }
        }
    }

    result.plugins.sort();
    result.plugins.dedup();
    result.ignored.sort();
    result.ignored.dedup();
    Ok(result)
}

fn is_ignored_name(name: &str) -> bool {
    let temporary_extension = Path::new(name).extension().is_some_and(|extension| {
        extension.eq_ignore_ascii_case("tmp")
            || extension.eq_ignore_ascii_case("temp")
            || extension.eq_ignore_ascii_case("swp")
    });
    name.starts_with('.') || name.starts_with("~$") || name.ends_with('~') || temporary_extension
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::discover_plugins;

    #[test]
    fn ignores_hidden_temporary_files_and_non_directories() {
        let temporary = TempDir::new().expect("temporary directory");
        fs::create_dir(temporary.path().join("valid")).expect("valid directory");
        fs::create_dir(temporary.path().join(".hidden")).expect("hidden directory");
        fs::create_dir(temporary.path().join("partial.tmp")).expect("temporary directory");
        fs::write(temporary.path().join("file.txt"), "not a plugin").expect("regular file");

        let result = discover_plugins([temporary.path()]).expect("discovery must succeed");
        assert_eq!(result.plugins, vec![temporary.path().join("valid")]);
        assert_eq!(result.ignored.len(), 3);
    }

    #[cfg(unix)]
    #[test]
    fn ignores_symbolic_links() {
        use std::os::unix::fs::symlink;

        let temporary = TempDir::new().expect("temporary directory");
        let target = temporary.path().join("target");
        fs::create_dir(&target).expect("target directory");
        symlink(&target, temporary.path().join("linked")).expect("symbolic link");

        let result = discover_plugins([temporary.path()]).expect("discovery must succeed");
        assert_eq!(result.plugins, vec![target]);
        assert_eq!(result.ignored, vec![temporary.path().join("linked")]);
    }
}
