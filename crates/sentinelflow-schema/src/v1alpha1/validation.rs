//! Structural decoding and semantic validation.

use std::collections::HashSet;
use std::fmt;
use std::path::{Component, Path, PathBuf};

use sentinelflow_core::constants::ENV_PREFIX;
use serde::de::DeserializeOwned;

use super::types::{
    AdapterKind, AuditEvent, Capability, Evidence, Finding, Policy, PolicyEffect, RuntimeMode,
    StandardError, TaskSpec, ToolInput, ToolManifest, ToolOutput,
};

/// Context used by semantic validation.
#[derive(Clone, Debug)]
pub struct ValidationContext {
    schema_root: PathBuf,
}

impl ValidationContext {
    /// Creates a validation context rooted at `schema_root`.
    #[must_use]
    pub fn new(schema_root: impl Into<PathBuf>) -> Self {
        Self {
            schema_root: schema_root.into(),
        }
    }

    /// Returns the root used to resolve repository-relative schema paths.
    #[must_use]
    pub fn schema_root(&self) -> &Path {
        &self.schema_root
    }
}

/// One validation failure with a JSON-compatible field path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationError {
    /// Field path such as `$.spec.authorizationScope`.
    pub path: String,
    /// Human-readable explanation.
    pub message: String,
}

impl ValidationError {
    fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.path, self.message)
    }
}

/// Collection of semantic validation failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationErrors(Vec<ValidationError>);

impl ValidationErrors {
    /// Returns all validation failures.
    #[must_use]
    pub fn errors(&self) -> &[ValidationError] {
        &self.0
    }
}

impl fmt::Display for ValidationErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, error) in self.0.iter().enumerate() {
            if index > 0 {
                formatter.write_str("; ")?;
            }
            write!(formatter, "{error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ValidationErrors {}

/// Structural JSON decoding failure with a field path.
#[derive(Debug)]
pub struct FromJsonError {
    /// Field path reported by `serde`.
    pub path: String,
    /// Human-readable decoding error.
    pub message: String,
}

impl fmt::Display for FromJsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.path, self.message)
    }
}

impl std::error::Error for FromJsonError {}

/// Deserializes JSON while preserving the field path of structural failures.
///
/// # Errors
///
/// Returns a decoding error containing the closest available JSON field path.
pub fn from_json_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, FromJsonError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
        let serde_path = error.path().to_string();
        FromJsonError {
            path: if serde_path.is_empty() {
                "$".to_owned()
            } else {
                format!("$.{serde_path}")
            },
            message: error.inner().to_string(),
        }
    })
}

/// Semantic validation implemented by protocol resources.
pub trait Validate {
    /// Validates cross-field rules that JSON Schema cannot express reliably.
    ///
    /// # Errors
    ///
    /// Returns every detected failure with a field path.
    fn validate(&self, context: &ValidationContext) -> Result<(), ValidationErrors>;
}

fn finish(errors: Vec<ValidationError>) -> Result<(), ValidationErrors> {
    if errors.is_empty() {
        Ok(())
    } else {
        Err(ValidationErrors(errors))
    }
}

fn require_non_empty(errors: &mut Vec<ValidationError>, path: &str, value: &str) {
    if value.trim().is_empty() {
        errors.push(ValidationError::new(path, "must not be empty"));
    }
}

fn validate_metadata(errors: &mut Vec<ValidationError>, name: &str) {
    require_non_empty(errors, "$.metadata.name", name);
}

fn validate_schema_path(
    errors: &mut Vec<ValidationError>,
    context: &ValidationContext,
    path_field: &str,
    value: &str,
) {
    require_non_empty(errors, path_field, value);
    if value.trim().is_empty() {
        return;
    }

    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        errors.push(ValidationError::new(
            path_field,
            "must be a repository-relative path without parent traversal",
        ));
        return;
    }

    let resolved = context.schema_root().join(path);
    if !resolved.is_file() {
        errors.push(ValidationError::new(
            path_field,
            format!("schema path cannot be resolved: {}", resolved.display()),
        ));
    }
}

impl Validate for ToolManifest {
    #[allow(clippy::too_many_lines)]
    fn validate(&self, context: &ValidationContext) -> Result<(), ValidationErrors> {
        let mut errors = Vec::new();
        validate_metadata(&mut errors, &self.metadata.name);
        require_non_empty(&mut errors, "$.spec.displayName", &self.spec.display_name);
        require_non_empty(&mut errors, "$.spec.version", &self.spec.version);
        require_non_empty(&mut errors, "$.spec.parser.name", &self.spec.parser.name);
        let expected_mode = match self.spec.runtime.adapter {
            AdapterKind::Docker => RuntimeMode::Container,
            AdapterKind::Command | AdapterKind::Http | AdapterKind::FileImport => {
                RuntimeMode::Process
            }
        };
        if self.spec.runtime.mode != expected_mode {
            errors.push(ValidationError::new(
                "$.spec.runtime.mode",
                format!(
                    "{:?} adapter requires {:?} mode",
                    self.spec.runtime.adapter, expected_mode
                ),
            ));
        }
        match self.spec.runtime.adapter {
            AdapterKind::Command if self.spec.runtime.entrypoint.is_none() => {
                errors.push(ValidationError::new(
                    "$.spec.runtime.entrypoint",
                    "command adapter requires an entrypoint",
                ));
            }
            AdapterKind::Docker if self.spec.runtime.docker.is_none() => {
                errors.push(ValidationError::new(
                    "$.spec.runtime.docker",
                    "docker adapter requires docker configuration",
                ));
            }
            AdapterKind::Http if self.spec.runtime.http.is_none() => {
                errors.push(ValidationError::new(
                    "$.spec.runtime.http",
                    "http adapter requires http configuration",
                ));
            }
            AdapterKind::FileImport if self.spec.runtime.file_import.is_none() => {
                errors.push(ValidationError::new(
                    "$.spec.runtime.fileImport",
                    "file import adapter requires fileImport configuration",
                ));
            }
            _ => {}
        }
        if let Some(http) = &self.spec.runtime.http {
            for (index, header) in http.headers.iter().enumerate() {
                if header.value.is_some() == header.secret_ref.is_some() {
                    errors.push(ValidationError::new(
                        format!("$.spec.runtime.http.headers[{index}]"),
                        "must declare exactly one of value or secretRef",
                    ));
                }
                if let Some(secret_ref) = &header.secret_ref {
                    if !valid_environment_name(secret_ref) {
                        errors.push(ValidationError::new(
                            format!("$.spec.runtime.http.headers[{index}].secretRef"),
                            "must be a valid environment variable reference",
                        ));
                    }
                }
                let sensitive = matches!(
                    header.name.to_ascii_lowercase().as_str(),
                    "authorization" | "cookie" | "proxy-authorization" | "x-api-key"
                );
                if sensitive && header.value.is_some() {
                    errors.push(ValidationError::new(
                        format!("$.spec.runtime.http.headers[{index}].value"),
                        "sensitive headers must use secretRef and cannot be stored in the Manifest",
                    ));
                }
            }
        }
        if let Some(docker) = &self.spec.runtime.docker {
            for (index, mount) in docker.mounts.iter().enumerate() {
                let path = Path::new(&mount.source);
                if path.is_absolute()
                    || !path.starts_with("examples")
                    || path
                        .components()
                        .any(|component| matches!(component, Component::ParentDir))
                {
                    errors.push(ValidationError::new(
                        format!("$.spec.runtime.docker.mounts[{index}].source"),
                        "must be a plugin-relative path beneath examples/",
                    ));
                }
                if !mount.target.starts_with('/') {
                    errors.push(ValidationError::new(
                        format!("$.spec.runtime.docker.mounts[{index}].target"),
                        "must be an absolute container path",
                    ));
                }
            }
        }
        if self.spec.runtime.timeout_seconds == 0 || self.spec.runtime.timeout_seconds > 3600 {
            errors.push(ValidationError::new(
                "$.spec.runtime.timeoutSeconds",
                "must be between 1 and 3600",
            ));
        }
        if self.spec.runtime.output_limit_bytes == 0
            || self.spec.runtime.output_limit_bytes > 16_777_216
        {
            errors.push(ValidationError::new(
                "$.spec.runtime.outputLimitBytes",
                "must be between 1 and 16777216",
            ));
        }
        if let Some(entrypoint) = &self.spec.runtime.entrypoint {
            let path = Path::new(entrypoint);
            if path.is_absolute()
                || !path.starts_with("runner")
                || path
                    .components()
                    .any(|component| matches!(component, Component::ParentDir | Component::RootDir))
            {
                errors.push(ValidationError::new(
                    "$.spec.runtime.entrypoint",
                    "must be a relative path beneath runner/",
                ));
            }
        }
        for (index, argument) in self.spec.runtime.args.iter().enumerate() {
            if argument.contains('\0') {
                errors.push(ValidationError::new(
                    format!("$.spec.runtime.args[{index}]"),
                    "must not contain a NUL byte",
                ));
            }
        }
        for (index, name) in self.spec.runtime.environment_allowlist.iter().enumerate() {
            if !valid_environment_name(name) || name.starts_with(ENV_PREFIX) {
                errors.push(ValidationError::new(
                    format!("$.spec.runtime.environmentAllowlist[{index}]"),
                    "must be a valid non-reserved environment variable name",
                ));
            }
        }

        if self.spec.capabilities.is_empty() {
            errors.push(ValidationError::new(
                "$.spec.capabilities",
                "must declare at least one capability",
            ));
        }
        for (index, capability) in self.spec.capabilities.iter().enumerate() {
            require_non_empty(
                &mut errors,
                &format!("$.spec.capabilities[{index}].name"),
                &capability.name,
            );
            if capability.risk.requires_approval() && !capability.requires_approval {
                errors.push(ValidationError::new(
                    format!("$.spec.capabilities[{index}].requiresApproval"),
                    "must be true for high or critical risk capabilities",
                ));
            }
        }

        validate_schema_path(
            &mut errors,
            context,
            "$.spec.inputSchema",
            &self.spec.input_schema,
        );
        validate_schema_path(
            &mut errors,
            context,
            "$.spec.outputSchema",
            &self.spec.output_schema,
        );
        finish(errors)
    }
}

fn valid_environment_name(name: &str) -> bool {
    let mut characters = name.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

macro_rules! validate_metadata_only {
    ($($resource:ty),+ $(,)?) => {
        $(
            impl Validate for $resource {
                fn validate(
                    &self,
                    _context: &ValidationContext,
                ) -> Result<(), ValidationErrors> {
                    let mut errors = Vec::new();
                    validate_metadata(&mut errors, &self.metadata.name);
                    finish(errors)
                }
            }
        )+
    };
}

validate_metadata_only!(ToolInput, Evidence, StandardError, AuditEvent);

impl Validate for ToolOutput {
    fn validate(&self, _context: &ValidationContext) -> Result<(), ValidationErrors> {
        let mut errors = Vec::new();
        validate_metadata(&mut errors, &self.metadata.name);
        require_non_empty(&mut errors, "$.spec.schemaRef", &self.spec.schema_ref);
        for (index, finding) in self.spec.findings.iter().enumerate() {
            require_non_empty(
                &mut errors,
                &format!("$.spec.findings[{index}].title"),
                &finding.title,
            );
            require_non_empty(
                &mut errors,
                &format!("$.spec.findings[{index}].summary"),
                &finding.summary,
            );
            for (evidence_index, evidence) in finding.evidence.iter().enumerate() {
                require_non_empty(
                    &mut errors,
                    &format!("$.spec.findings[{index}].evidence[{evidence_index}].evidenceType"),
                    &evidence.evidence_type,
                );
                require_non_empty(
                    &mut errors,
                    &format!("$.spec.findings[{index}].evidence[{evidence_index}].description"),
                    &evidence.description,
                );
            }
        }
        for (index, error) in self.spec.errors.iter().enumerate() {
            require_non_empty(
                &mut errors,
                &format!("$.spec.errors[{index}].code"),
                &error.code,
            );
            require_non_empty(
                &mut errors,
                &format!("$.spec.errors[{index}].message"),
                &error.message,
            );
        }
        finish(errors)
    }
}

impl Validate for Capability {
    fn validate(&self, _context: &ValidationContext) -> Result<(), ValidationErrors> {
        let mut errors = Vec::new();
        validate_metadata(&mut errors, &self.metadata.name);
        require_non_empty(&mut errors, "$.spec.name", &self.spec.name);
        require_non_empty(&mut errors, "$.spec.description", &self.spec.description);
        if self.spec.risk.requires_approval() && !self.spec.requires_approval {
            errors.push(ValidationError::new(
                "$.spec.requiresApproval",
                "must be true for high or critical risk capabilities",
            ));
        }
        finish(errors)
    }
}

impl Validate for Finding {
    fn validate(&self, _context: &ValidationContext) -> Result<(), ValidationErrors> {
        let mut errors = Vec::new();
        validate_metadata(&mut errors, &self.metadata.name);
        require_non_empty(&mut errors, "$.spec.title", &self.spec.title);
        require_non_empty(&mut errors, "$.spec.summary", &self.spec.summary);
        finish(errors)
    }
}

impl Validate for TaskSpec {
    #[allow(clippy::too_many_lines)]
    fn validate(&self, _context: &ValidationContext) -> Result<(), ValidationErrors> {
        let mut errors = Vec::new();
        validate_metadata(&mut errors, &self.metadata.name);
        require_non_empty(
            &mut errors,
            "$.spec.authorizationScope",
            &self.spec.authorization_scope,
        );
        if self.spec.targets.is_empty() {
            errors.push(ValidationError::new(
                "$.spec.targets",
                "must declare at least one target",
            ));
        }
        for (index, target) in self.spec.targets.iter().enumerate() {
            require_non_empty(
                &mut errors,
                &format!("$.spec.targets[{index}].name"),
                &target.name,
            );
        }
        if self.spec.steps.is_empty() {
            errors.push(ValidationError::new(
                "$.spec.steps",
                "must declare at least one step",
            ));
        }
        let mut step_names = HashSet::new();
        let mut output_names = HashSet::new();
        for (index, step) in self.spec.steps.iter().enumerate() {
            require_non_empty(
                &mut errors,
                &format!("$.spec.steps[{index}].name"),
                &step.name,
            );
            require_non_empty(
                &mut errors,
                &format!("$.spec.steps[{index}].toolRef"),
                &step.tool_ref,
            );
            require_non_empty(
                &mut errors,
                &format!("$.spec.steps[{index}].capability"),
                &step.capability,
            );
            if !step_names.insert(step.name.as_str()) {
                errors.push(ValidationError::new(
                    format!("$.spec.steps[{index}].name"),
                    "step names must be unique",
                ));
            }
            if let Some(output_as) = &step.output_as {
                require_non_empty(
                    &mut errors,
                    &format!("$.spec.steps[{index}].outputAs"),
                    output_as,
                );
                if !output_names.insert(output_as.as_str()) {
                    errors.push(ValidationError::new(
                        format!("$.spec.steps[{index}].outputAs"),
                        "output aliases must be unique",
                    ));
                }
            }
            for (mapping_index, mapping) in step.input_from.iter().enumerate() {
                require_non_empty(
                    &mut errors,
                    &format!("$.spec.steps[{index}].inputFrom[{mapping_index}].from"),
                    &mapping.from,
                );
                if !mapping.pointer.starts_with('/') {
                    errors.push(ValidationError::new(
                        format!("$.spec.steps[{index}].inputFrom[{mapping_index}].pointer"),
                        "must be an absolute JSON Pointer",
                    ));
                }
                if mapping.target.contains('.') || mapping.target.contains('/') {
                    errors.push(ValidationError::new(
                        format!("$.spec.steps[{index}].inputFrom[{mapping_index}].target"),
                        "must be a top-level input field name",
                    ));
                }
            }
        }
        for (index, step) in self.spec.steps.iter().enumerate() {
            for dependency in &step.depends_on {
                if dependency == &step.name || !step_names.contains(dependency.as_str()) {
                    errors.push(ValidationError::new(
                        format!("$.spec.steps[{index}].dependsOn"),
                        "dependencies must reference another declared step",
                    ));
                }
            }
        }
        if self.spec.policy.max_concurrency == 0 || self.spec.policy.max_concurrency > 64 {
            errors.push(ValidationError::new(
                "$.spec.policy.maxConcurrency",
                "must be between 1 and 64",
            ));
        }
        if self.spec.policy.rate_limit_per_minute == 0 {
            errors.push(ValidationError::new(
                "$.spec.policy.rateLimitPerMinute",
                "must be greater than zero",
            ));
        }
        for (index, window) in self.spec.policy.time_windows.iter().enumerate() {
            if !valid_hhmm(&window.start) || !valid_hhmm(&window.end) {
                errors.push(ValidationError::new(
                    format!("$.spec.policy.timeWindows[{index}]"),
                    "start and end must use 24-hour HH:MM UTC format",
                ));
            }
        }
        finish(errors)
    }
}

fn valid_hhmm(value: &str) -> bool {
    let Some((hour, minute)) = value.split_once(':') else {
        return false;
    };
    hour.len() == 2
        && minute.len() == 2
        && hour.parse::<u8>().is_ok_and(|hour| hour < 24)
        && minute.parse::<u8>().is_ok_and(|minute| minute < 60)
}

impl Validate for Policy {
    fn validate(&self, _context: &ValidationContext) -> Result<(), ValidationErrors> {
        let mut errors = Vec::new();
        validate_metadata(&mut errors, &self.metadata.name);
        if self.spec.default_effect != PolicyEffect::Deny {
            errors.push(ValidationError::new(
                "$.spec.defaultEffect",
                "must be deny in v1alpha1",
            ));
        }
        for (index, rule) in self.spec.rules.iter().enumerate() {
            require_non_empty(
                &mut errors,
                &format!("$.spec.rules[{index}].name"),
                &rule.name,
            );
            if rule.authorization_scopes.is_empty() {
                errors.push(ValidationError::new(
                    format!("$.spec.rules[{index}].authorizationScopes"),
                    "must declare at least one authorization scope",
                ));
            }
        }
        finish(errors)
    }
}
