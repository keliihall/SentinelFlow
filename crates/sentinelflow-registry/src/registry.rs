//! In-memory Tool Registry.

use std::collections::BTreeMap;
use std::path::PathBuf;

use sentinelflow_schema::v1alpha1::ToolManifest;

use crate::{RegistryError, ValidatedPlugin};

/// A registered tool and its local state.
#[derive(Clone, Debug)]
pub struct RegisteredTool {
    /// Validated Manifest.
    pub manifest: ToolManifest,
    /// Plugin package root.
    pub plugin_root: PathBuf,
    /// Whether the tool is enabled for future policy-controlled use.
    pub enabled: bool,
}

/// Result of registering a validated plugin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegisterOutcome {
    /// New registration created.
    Registered,
    /// The exact name and version were already registered.
    AlreadyRegistered,
}

/// Queryable registry of validated tool declarations.
#[derive(Clone, Debug, Default)]
pub struct ToolRegistry {
    tools: BTreeMap<String, RegisteredTool>,
}

impl ToolRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one validated plugin.
    ///
    /// # Errors
    ///
    /// Returns a version conflict when the same tool name is already registered
    /// with a different version.
    pub fn register(&mut self, plugin: ValidatedPlugin) -> Result<RegisterOutcome, RegistryError> {
        let name = plugin.manifest.metadata.name.clone();
        if let Some(existing) = self.tools.get(&name) {
            if existing.manifest.spec.version == plugin.manifest.spec.version {
                return Ok(RegisterOutcome::AlreadyRegistered);
            }
            return Err(RegistryError::VersionConflict {
                tool: name,
                existing: existing.manifest.spec.version.clone(),
                incoming: plugin.manifest.spec.version,
            });
        }

        self.tools.insert(
            name,
            RegisteredTool {
                manifest: plugin.manifest,
                plugin_root: plugin.root,
                enabled: true,
            },
        );
        Ok(RegisterOutcome::Registered)
    }

    /// Returns a registered tool by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&RegisteredTool> {
        self.tools.get(name)
    }

    /// Returns all tools in stable name order.
    pub fn list(&self) -> impl Iterator<Item = (&str, &RegisteredTool)> {
        self.tools.iter().map(|(name, tool)| (name.as_str(), tool))
    }

    /// Changes a tool's enabled state.
    ///
    /// # Errors
    ///
    /// Returns not-found when the tool is not registered.
    pub fn set_enabled(&mut self, name: &str, enabled: bool) -> Result<(), RegistryError> {
        let tool = self
            .tools
            .get_mut(name)
            .ok_or_else(|| RegistryError::NotFound {
                tool: name.to_owned(),
            })?;
        tool.enabled = enabled;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use sentinelflow_schema::v1alpha1::{
        AdapterKind, Metadata, ParserMode, ParserSpec, ProtocolVersion, RuntimeMode, RuntimeSpec,
        ToolManifest, ToolManifestKind, ToolManifestSpec,
    };

    use super::{RegisterOutcome, ToolRegistry};
    use crate::ValidatedPlugin;

    fn plugin(version: &str) -> ValidatedPlugin {
        ValidatedPlugin {
            root: PathBuf::from("example"),
            manifest: ToolManifest {
                api_version: ProtocolVersion::V1Alpha1,
                kind: ToolManifestKind::Value,
                metadata: Metadata {
                    name: "example".to_owned(),
                    namespace: None,
                    uid: None,
                    labels: BTreeMap::default(),
                    annotations: BTreeMap::default(),
                },
                spec: ToolManifestSpec {
                    display_name: "Example".to_owned(),
                    version: version.to_owned(),
                    capabilities: Vec::new(),
                    runtime: RuntimeSpec {
                        adapter: AdapterKind::Command,
                        mode: RuntimeMode::Process,
                        entrypoint: None,
                        args: Vec::new(),
                        environment_allowlist: Vec::new(),
                        timeout_seconds: 30,
                        output_limit_bytes: 1_048_576,
                        docker: None,
                        http: None,
                        file_import: None,
                    },
                    parser: ParserSpec {
                        mode: ParserMode::Builtin,
                        name: "example-echo-v1".to_owned(),
                    },
                    input_schema: "schemas/input.json".to_owned(),
                    output_schema: "schemas/output.json".to_owned(),
                },
                extensions: BTreeMap::default(),
            },
        }
    }

    #[test]
    fn registration_is_idempotent_and_detects_version_conflicts() {
        let mut registry = ToolRegistry::new();
        assert_eq!(
            registry.register(plugin("1.0.0")).expect("register"),
            RegisterOutcome::Registered
        );
        assert_eq!(
            registry.register(plugin("1.0.0")).expect("idempotent"),
            RegisterOutcome::AlreadyRegistered
        );
        assert!(registry.register(plugin("2.0.0")).is_err());
    }

    #[test]
    fn enabled_state_can_be_changed() {
        let mut registry = ToolRegistry::new();
        registry.register(plugin("1.0.0")).expect("register");
        registry.set_enabled("example", false).expect("disable");
        assert!(!registry.get("example").expect("registered").enabled);
    }
}
