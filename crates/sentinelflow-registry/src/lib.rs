//! Safe plugin discovery, validation, installation, and registration.

mod discovery;
mod error;
mod install;
mod registry;
mod validation;

pub use discovery::{DiscoveryResult, discover_plugins};
pub use error::RegistryError;
pub use install::{InstallOutcome, install_plugin};
pub use registry::{RegisterOutcome, RegisteredTool, ToolRegistry};
pub use validation::{
    CheckResult, CheckStage, PluginValidationReport, ValidatedPlugin, validate_plugin,
};
