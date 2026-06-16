//! The `sentinelflow.io/v1alpha1` protocol.

mod schema;
mod types;
mod validation;

pub use schema::{SchemaDocument, schema_documents, write_schema_documents};
pub use types::{
    API_VERSION, AdapterKind, AuditEvent, AuditEventKind, AuditEventSpec, AuditOutcome, Capability,
    CapabilityKind, CapabilitySpec, DockerAdapterSpec, DockerMountSpec, DockerNetworkPolicy,
    ErrorDetails, Evidence, EvidenceKind, EvidenceSpec, FailurePolicy, FileImportAdapterSpec,
    FileImportFormat, Finding, FindingKind, FindingSeverity, FindingSpec, HttpAdapterSpec,
    HttpHeaderSpec, HttpMethod, HttpPaginationSpec, HttpPollingSpec, Metadata,
    OutputRetentionPolicy, ParserMode, ParserSpec, Policy, PolicyEffect, PolicyKind, PolicyRule,
    PolicySpec, PolicyTimeWindow, ProtocolVersion, RiskLevel, RuntimeMode, RuntimeSpec,
    StandardError, StandardErrorKind, TaskExecutionPolicy, TaskInputMapping, TaskSpec,
    TaskSpecData, TaskSpecKind, TaskStepSpec, TaskTargetSpec, ToolInput, ToolInputKind,
    ToolInputSpec, ToolManifest, ToolManifestKind, ToolManifestSpec, ToolOutput, ToolOutputKind,
    ToolOutputSpec,
};
pub use validation::{
    FromJsonError, Validate, ValidationContext, ValidationError, ValidationErrors, from_json_slice,
};
