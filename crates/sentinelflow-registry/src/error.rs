//! Registry error model.

use std::fmt;
use std::path::PathBuf;

/// Errors that prevent discovery, registration, or installation.
#[derive(Debug)]
pub enum RegistryError {
    /// Filesystem operation failed.
    Io {
        /// Path involved in the operation.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
    /// Plugin failed validation.
    InvalidPlugin {
        /// Plugin root.
        path: PathBuf,
        /// Concise validation summary.
        message: String,
    },
    /// A different version is already registered or installed.
    VersionConflict {
        /// Tool name.
        tool: String,
        /// Existing version.
        existing: String,
        /// Incoming version.
        incoming: String,
    },
    /// Requested tool is not registered.
    NotFound {
        /// Tool name.
        tool: String,
    },
}

impl RegistryError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(formatter, "{}: {source}", path.display())
            }
            Self::InvalidPlugin { path, message } => {
                write!(formatter, "invalid plugin {}: {message}", path.display())
            }
            Self::VersionConflict {
                tool,
                existing,
                incoming,
            } => write!(
                formatter,
                "tool {tool} version conflict: existing {existing}, incoming {incoming}"
            ),
            Self::NotFound { tool } => write!(formatter, "tool is not registered: {tool}"),
        }
    }
}

impl std::error::Error for RegistryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
