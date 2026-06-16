//! Plugin package and Manifest validation.

use std::fs;
use std::path::{Component, Path, PathBuf};

use jsonschema::JSONSchema;
use semver::Version;
use sentinelflow_schema::v1alpha1::{
    RuntimeMode, ToolManifest, Validate, ValidationContext, from_json_slice, schema_documents,
};
use serde::Serialize;
use serde_json::Value;

use crate::RegistryError;

const MANIFEST_FILE: &str = "sentinelflow.tool.yaml";
const REQUIRED_DIRECTORIES: [&str; 3] = ["parser", "schemas", "examples"];
const REQUIRED_FILES: [&str; 2] = [MANIFEST_FILE, "README.md"];

/// One plugin validation stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CheckStage {
    /// Directory shape, YAML parsing, and JSON Schema validation.
    Structure,
    /// Cross-field Manifest semantics.
    Semantic,
    /// Protocol, tool version, and runtime compatibility.
    Compatibility,
    /// Required package dependencies.
    Dependencies,
    /// Symlink and path-containment safety.
    Safety,
}

/// Result of one plugin validation stage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    /// Validation stage.
    pub stage: CheckStage,
    /// Whether the stage passed.
    pub passed: bool,
    /// Field- or path-specific findings.
    pub messages: Vec<String>,
}

impl CheckResult {
    fn new(stage: CheckStage) -> Self {
        Self {
            stage,
            passed: true,
            messages: Vec::new(),
        }
    }

    fn fail(&mut self, message: impl Into<String>) {
        self.passed = false;
        self.messages.push(message.into());
    }

    fn pass(&mut self, message: impl Into<String>) {
        self.messages.push(message.into());
    }
}

/// Full validation report returned even when a plugin is invalid.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginValidationReport {
    /// Plugin root.
    pub plugin_root: PathBuf,
    /// Parsed Manifest when structural decoding succeeded.
    #[serde(skip)]
    pub manifest: Option<ToolManifest>,
    /// Ordered validation stages.
    pub checks: Vec<CheckResult>,
}

impl PluginValidationReport {
    /// Whether every validation stage passed.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.manifest.is_some() && self.checks.iter().all(|check| check.passed)
    }

    /// Converts a successful report into a registrable plugin.
    ///
    /// # Errors
    ///
    /// Returns an invalid-plugin error when any stage failed.
    pub fn into_validated(self) -> Result<ValidatedPlugin, RegistryError> {
        if !self.is_valid() {
            let message = self
                .checks
                .iter()
                .filter(|check| !check.passed)
                .flat_map(|check| check.messages.iter())
                .cloned()
                .collect::<Vec<_>>()
                .join("; ");
            return Err(RegistryError::InvalidPlugin {
                path: self.plugin_root,
                message,
            });
        }

        let Some(manifest) = self.manifest else {
            return Err(RegistryError::InvalidPlugin {
                path: self.plugin_root,
                message: "Manifest was not loaded".to_owned(),
            });
        };
        Ok(ValidatedPlugin {
            root: self.plugin_root,
            manifest,
        })
    }
}

/// A plugin that passed every validation stage.
#[derive(Clone, Debug)]
pub struct ValidatedPlugin {
    /// Plugin root.
    pub root: PathBuf,
    /// Validated Manifest.
    pub manifest: ToolManifest,
}

/// Validates a plugin package without executing any package content.
///
/// # Errors
///
/// Returns an I/O error only when the plugin root metadata cannot be inspected.
/// Package validation failures are represented in the returned report.
pub fn validate_plugin(
    plugin_root: impl AsRef<Path>,
) -> Result<PluginValidationReport, RegistryError> {
    let plugin_root = plugin_root.as_ref().to_path_buf();
    let root_metadata = fs::symlink_metadata(&plugin_root)
        .map_err(|error| RegistryError::io(&plugin_root, error))?;

    let mut structure = CheckResult::new(CheckStage::Structure);
    let mut semantic = CheckResult::new(CheckStage::Semantic);
    let mut compatibility = CheckResult::new(CheckStage::Compatibility);
    let mut dependencies = CheckResult::new(CheckStage::Dependencies);
    let mut safety = CheckResult::new(CheckStage::Safety);

    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        safety.fail(format!(
            "$.pluginRoot: must be a real directory, got {}",
            plugin_root.display()
        ));
        return Ok(PluginValidationReport {
            plugin_root,
            manifest: None,
            checks: vec![structure, semantic, compatibility, dependencies, safety],
        });
    }

    check_required_shape(&plugin_root, &mut structure);
    check_tree_safety(&plugin_root, &mut safety)?;
    let manifest = load_manifest(&plugin_root, &mut structure);

    if let Some(manifest) = &manifest {
        check_semantics(&plugin_root, manifest, &mut semantic);
        check_compatibility(manifest, &mut compatibility);
        check_dependencies(&plugin_root, manifest, &mut dependencies);
        check_tool_name(manifest, &mut safety);
    } else {
        semantic.fail("$.manifest: skipped because structural validation failed");
        compatibility.fail("$.manifest: skipped because structural validation failed");
        dependencies.fail("$.manifest: skipped because structural validation failed");
    }

    if safety.passed {
        safety.pass("no symbolic links or unsafe package paths found");
    }

    Ok(PluginValidationReport {
        plugin_root,
        manifest,
        checks: vec![structure, semantic, compatibility, dependencies, safety],
    })
}

fn check_required_shape(root: &Path, check: &mut CheckResult) {
    for directory in REQUIRED_DIRECTORIES {
        let path = root.join(directory);
        if !path.is_dir() {
            check.fail(format!(
                "$.package.{directory}: required directory is missing"
            ));
        }
    }
    for file in REQUIRED_FILES {
        let path = root.join(file);
        if !path.is_file() {
            check.fail(format!("$.package.{file}: required file is missing"));
        }
    }
    if check.passed {
        check.pass("required plugin directory structure is present");
    }
}

fn load_manifest(root: &Path, check: &mut CheckResult) -> Option<ToolManifest> {
    let path = root.join(MANIFEST_FILE);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            check.fail(format!(
                "$.manifest: failed to read {}: {error}",
                path.display()
            ));
            return None;
        }
    };
    let yaml: serde_yaml::Value = match serde_yaml::from_slice(&bytes) {
        Ok(yaml) => yaml,
        Err(error) => {
            check.fail(format!("$.manifest: invalid YAML: {error}"));
            return None;
        }
    };
    let json_value = match serde_json::to_value(yaml) {
        Ok(value) => value,
        Err(error) => {
            check.fail(format!(
                "$.manifest: YAML cannot be represented as JSON: {error}"
            ));
            return None;
        }
    };

    validate_json_schema(&json_value, check);
    let json_bytes = match serde_json::to_vec(&json_value) {
        Ok(bytes) => bytes,
        Err(error) => {
            check.fail(format!(
                "$.manifest: failed to encode normalized JSON: {error}"
            ));
            return None;
        }
    };
    match from_json_slice(&json_bytes) {
        Ok(manifest) => {
            if check.passed {
                check.pass("Manifest YAML and JSON Schema are valid");
            }
            Some(manifest)
        }
        Err(error) => {
            check.fail(format!("{}: {}", error.path, error.message));
            None
        }
    }
}

fn validate_json_schema(instance: &Value, check: &mut CheckResult) {
    let schema = schema_documents()
        .ok()
        .and_then(|documents| {
            documents
                .into_iter()
                .find(|document| document.filename == "tool-manifest.schema.json")
        })
        .and_then(|document| serde_json::from_str::<Value>(&document.json).ok());
    let Some(schema) = schema else {
        check.fail("$.manifest: internal Tool Manifest JSON Schema is unavailable");
        return;
    };
    let compiled = match JSONSchema::compile(&schema) {
        Ok(compiled) => compiled,
        Err(error) => {
            check.fail(format!(
                "$.manifest: internal Tool Manifest JSON Schema is invalid: {error}"
            ));
            return;
        }
    };
    if let Err(errors) = compiled.validate(instance) {
        for error in errors {
            check.fail(format!("${}: {}", error.instance_path, error));
        }
    }
}

fn check_semantics(root: &Path, manifest: &ToolManifest, check: &mut CheckResult) {
    match manifest.validate(&ValidationContext::new(root)) {
        Ok(()) => check.pass("Manifest semantic validation passed"),
        Err(errors) => {
            for error in errors.errors() {
                check.fail(error.to_string());
            }
        }
    }
}

fn check_compatibility(manifest: &ToolManifest, check: &mut CheckResult) {
    if Version::parse(&manifest.spec.version).is_err() {
        check.fail("$.spec.version: must be a semantic version");
    }
    let compatible = match manifest.spec.runtime.adapter {
        sentinelflow_schema::v1alpha1::AdapterKind::Docker => {
            manifest.spec.runtime.mode == RuntimeMode::Container
        }
        sentinelflow_schema::v1alpha1::AdapterKind::Command
        | sentinelflow_schema::v1alpha1::AdapterKind::Http
        | sentinelflow_schema::v1alpha1::AdapterKind::FileImport => {
            manifest.spec.runtime.mode == RuntimeMode::Process
        }
    };
    if !compatible {
        check.fail("$.spec.runtime.mode: adapter and isolation mode are incompatible");
    }
    if check.passed {
        check.pass("protocol, tool version, and runtime mode are compatible");
    }
}

fn check_dependencies(root: &Path, manifest: &ToolManifest, check: &mut CheckResult) {
    for directory in ["parser"] {
        if !root.join(directory).is_dir() {
            check.fail(format!(
                "$.package.{directory}: dependency directory is missing"
            ));
        }
    }
    if manifest.spec.runtime.adapter == sentinelflow_schema::v1alpha1::AdapterKind::Command
        && !root.join("runner").is_dir()
    {
        check.fail("$.package.runner: dependency directory is missing");
    }
    for (field, path) in [
        ("inputSchema", &manifest.spec.input_schema),
        ("outputSchema", &manifest.spec.output_schema),
    ] {
        if !safe_regular_file(root, Path::new(path)) {
            check.fail(format!(
                "$.spec.{field}: dependency does not resolve to a safe regular file"
            ));
        }
    }
    if check.passed {
        check.pass("adapter, parser, and input/output Schema dependencies are present");
    }
}

fn check_tree_safety(root: &Path, check: &mut CheckResult) -> Result<(), RegistryError> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries =
            fs::read_dir(&directory).map_err(|error| RegistryError::io(&directory, error))?;
        for entry in entries {
            let entry = entry.map_err(|error| RegistryError::io(&directory, error))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|error| RegistryError::io(&path, error))?;
            if file_type.is_symlink() {
                check.fail(format!(
                    "$.package: symbolic links are not allowed: {}",
                    path.display()
                ));
            } else if file_type.is_dir() {
                pending.push(path);
            }
        }
    }
    Ok(())
}

fn check_tool_name(manifest: &ToolManifest, check: &mut CheckResult) {
    let name = &manifest.metadata.name;
    let mut components = Path::new(name).components();
    let is_single_normal_component =
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();
    let temporary_extension = Path::new(name).extension().is_some_and(|extension| {
        extension.eq_ignore_ascii_case("tmp") || extension.eq_ignore_ascii_case("temp")
    });
    if !is_single_normal_component
        || name.starts_with('.')
        || name.starts_with("~$")
        || name.ends_with('~')
        || temporary_extension
    {
        check.fail("$.metadata.name: must be a visible, non-temporary single directory name");
    }
}

fn safe_regular_file(root: &Path, relative: &Path) -> bool {
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return false;
    }
    let path = root.join(relative);
    path.is_file()
        && fs::symlink_metadata(path)
            .map(|metadata| !metadata.file_type().is_symlink())
            .unwrap_or(false)
}
