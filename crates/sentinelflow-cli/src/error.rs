//! Stable CLI errors and exit codes.

use std::collections::BTreeMap;
use std::fmt;

use sentinelflow_schema::v1alpha1::{
    ErrorDetails, Metadata, ProtocolVersion, StandardError, StandardErrorKind,
};

/// Stable process exit codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExitCode {
    /// Successful completion.
    Success = 0,
    /// Command-line argument error.
    Argument = 2,
    /// Protocol Schema or semantic validation error.
    Schema = 3,
    /// Authorization or policy denial.
    Authorization = 4,
    /// Runtime or not-yet-implemented operation error.
    Runtime = 5,
    /// Filesystem, configuration, or other system error.
    System = 6,
}

/// Error returned by implemented and placeholder CLI commands.
#[derive(Debug)]
pub struct CliError {
    exit_code: ExitCode,
    code: &'static str,
    message: String,
    field: Option<String>,
}

impl CliError {
    /// Creates a command-line argument error.
    #[must_use]
    pub fn argument(message: impl Into<String>) -> Self {
        Self {
            exit_code: ExitCode::Argument,
            code: "InvalidArguments",
            message: message.into(),
            field: Some("$.arguments".to_owned()),
        }
    }

    /// Creates a Schema validation error.
    #[must_use]
    pub fn schema(message: impl Into<String>, field: Option<String>) -> Self {
        Self {
            exit_code: ExitCode::Schema,
            code: "SchemaValidationFailed",
            message: message.into(),
            field,
        }
    }

    /// Creates an authorization or policy error.
    #[must_use]
    pub fn authorization(message: impl Into<String>, field: Option<String>) -> Self {
        Self {
            exit_code: ExitCode::Authorization,
            code: "AuthorizationDenied",
            message: message.into(),
            field,
        }
    }

    /// Creates a controlled runtime error.
    #[must_use]
    pub fn runtime(message: impl Into<String>, field: Option<String>) -> Self {
        Self {
            exit_code: ExitCode::Runtime,
            code: "RuntimeError",
            message: message.into(),
            field,
        }
    }

    /// Creates a system error.
    #[must_use]
    pub fn system(message: impl Into<String>, field: Option<String>) -> Self {
        Self {
            exit_code: ExitCode::System,
            code: "SystemError",
            message: message.into(),
            field,
        }
    }

    /// Creates a not-implemented runtime error.
    #[must_use]
    pub fn not_implemented(command: &str) -> Self {
        Self {
            exit_code: ExitCode::Runtime,
            code: "NotImplemented",
            message: format!("command is not implemented in P1.5: {command}"),
            field: Some("$.command".to_owned()),
        }
    }

    /// Returns the stable numeric process exit code.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        self.exit_code as u8
    }

    /// Encodes this error using the protocol `StandardError` resource.
    #[must_use]
    pub fn to_standard_error_json(&self) -> String {
        serde_json::to_string(&self.to_standard_error()).unwrap_or_else(|_| {
            "{\"apiVersion\":\"sentinelflow.io/v1alpha1\",\"kind\":\"StandardError\",\
             \"metadata\":{\"name\":\"cli-error\"},\"error\":{\"code\":\"SystemError\",\
             \"message\":\"failed to serialize CLI error\"},\"extensions\":{}}"
                .to_owned()
        })
    }

    /// Converts this CLI error to a persistable protocol resource.
    #[must_use]
    pub fn to_standard_error(&self) -> StandardError {
        StandardError {
            api_version: ProtocolVersion::V1Alpha1,
            kind: StandardErrorKind::Value,
            metadata: Metadata {
                name: "cli-error".to_owned(),
                namespace: None,
                uid: None,
                labels: BTreeMap::new(),
                annotations: BTreeMap::new(),
            },
            error: ErrorDetails {
                code: self.code.to_owned(),
                message: self.message.clone(),
                field: self.field.clone(),
                details: BTreeMap::new(),
            },
            extensions: BTreeMap::new(),
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for CliError {}

#[cfg(test)]
mod tests {
    use super::ExitCode;

    #[test]
    fn exit_codes_are_stable() {
        assert_eq!(ExitCode::Success as u8, 0);
        assert_eq!(ExitCode::Argument as u8, 2);
        assert_eq!(ExitCode::Schema as u8, 3);
        assert_eq!(ExitCode::Authorization as u8, 4);
        assert_eq!(ExitCode::Runtime as u8, 5);
        assert_eq!(ExitCode::System as u8, 6);
    }
}
