//! Resource types for protocol version `v1alpha1`.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Canonical API version for all resources in this module.
pub const API_VERSION: &str = "sentinelflow.io/v1alpha1";

/// Supported protocol version.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub enum ProtocolVersion {
    /// The initial alpha protocol.
    #[serde(rename = "sentinelflow.io/v1alpha1")]
    V1Alpha1,
}

impl ProtocolVersion {
    /// Returns the wire-format API version.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        API_VERSION
    }
}

/// Common metadata attached to every protocol resource.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Metadata {
    /// Resource name within its namespace.
    #[schemars(length(min = 1))]
    pub name: String,
    /// Optional logical namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Optional stable identifier assigned by a store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    /// Queryable labels.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Non-queryable annotations.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

/// Risk classification for a declared capability.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RiskLevel {
    /// Read-only or otherwise low-impact validation.
    Low,
    /// Validation with bounded side effects.
    Medium,
    /// Validation requiring explicit approval.
    High,
    /// Exceptional validation requiring explicit approval.
    Critical,
}

impl RiskLevel {
    /// Whether this risk class requires explicit approval.
    #[must_use]
    pub const fn requires_approval(self) -> bool {
        matches!(self, Self::High | Self::Critical)
    }
}

/// A capability declaration embedded in a tool manifest or exposed as a resource.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilitySpec {
    /// Stable capability identifier.
    #[schemars(length(min = 1))]
    pub name: String,
    /// Human-readable description.
    #[schemars(length(min = 1))]
    pub description: String,
    /// Declared risk classification.
    pub risk: RiskLevel,
    /// Whether authorization must include an explicit approval.
    pub requires_approval: bool,
}

/// Isolation mode declared by a tool manifest.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RuntimeMode {
    /// Tool is isolated in a separately managed operating-system process.
    Process,
    /// Tool is isolated in a container runtime introduced by a later phase.
    Container,
}

/// Adapter selected by a tool Manifest.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AdapterKind {
    /// Execute a local process with a fixed argument array.
    #[default]
    Command,
    /// Execute an OCI image through the Docker CLI.
    Docker,
    /// Invoke a bounded HTTP endpoint.
    Http,
    /// Import caller-supplied structured file content.
    FileImport,
}

/// Docker network policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DockerNetworkPolicy {
    /// Disable container networking.
    None,
    /// Use the default bridge network when explicitly authorized.
    Bridge,
}

/// One controlled container mount.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DockerMountSpec {
    /// Plugin-relative source beneath `examples/`.
    pub source: String,
    /// Absolute container destination.
    pub target: String,
    /// Whether the mount is read-only.
    #[serde(default = "default_true")]
    pub read_only: bool,
}

/// Docker Adapter configuration.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DockerAdapterSpec {
    /// Immutable image reference, preferably pinned by digest.
    #[schemars(length(min = 1))]
    pub image: String,
    /// Fixed container command arguments.
    #[serde(default)]
    pub command: Vec<String>,
    /// Controlled plugin fixture mounts.
    #[serde(default)]
    pub mounts: Vec<DockerMountSpec>,
    /// Container network policy.
    pub network: DockerNetworkPolicy,
    /// CPU quota in millicpus.
    #[schemars(range(min = 100, max = 4000))]
    pub cpu_millis: u32,
    /// Memory limit in MiB.
    #[schemars(range(min = 16, max = 4096))]
    pub memory_mib: u64,
}

/// Supported HTTP methods.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    /// Read a resource.
    Get,
    /// Submit structured input.
    Post,
}

/// HTTP header value source.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HttpHeaderSpec {
    /// Header name.
    pub name: String,
    /// Non-sensitive literal value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Environment-backed secret reference, without the secret value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<String>,
}

/// HTTP pagination mode.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HttpPaginationSpec {
    /// JSON response field containing the next relative URL.
    pub next_field: String,
    /// Maximum number of pages.
    #[schemars(range(min = 1, max = 20))]
    pub max_pages: u32,
}

/// HTTP asynchronous polling configuration.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HttpPollingSpec {
    /// JSON field containing the status value.
    pub status_field: String,
    /// Terminal success value.
    pub success_value: String,
    /// Relative or same-origin URL field used for polling.
    pub location_field: String,
    /// Poll interval in milliseconds.
    #[schemars(range(min = 10, max = 60_000))]
    pub interval_ms: u64,
    /// Maximum polling attempts.
    #[schemars(range(min = 1, max = 100))]
    pub max_attempts: u32,
}

/// HTTP Adapter configuration.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HttpAdapterSpec {
    /// Endpoint URL. P3 permits HTTPS and loopback HTTP fixtures.
    pub url: String,
    /// Request method.
    pub method: HttpMethod,
    /// Controlled request headers.
    #[serde(default)]
    pub headers: Vec<HttpHeaderSpec>,
    /// Retry count after the first attempt.
    #[serde(default)]
    #[schemars(range(max = 5))]
    pub retries: u32,
    /// Optional bounded pagination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pagination: Option<HttpPaginationSpec>,
    /// Optional bounded asynchronous polling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub polling: Option<HttpPollingSpec>,
}

/// Supported structured import formats.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FileImportFormat {
    /// One JSON value.
    Json,
    /// One JSON value per line.
    Jsonl,
    /// CSV with a header row.
    Csv,
}

/// File Import Adapter configuration.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileImportAdapterSpec {
    /// Accepted formats.
    #[schemars(length(min = 1))]
    pub formats: Vec<FileImportFormat>,
    /// Maximum caller-supplied content size.
    #[schemars(range(min = 1, max = 16_777_216))]
    pub max_bytes: usize,
    /// Maximum imported records.
    #[schemars(range(min = 1, max = 100_000))]
    pub max_records: usize,
}

/// Declarative runtime requirements. This type does not execute tools.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeSpec {
    /// Adapter implementation selected for this tool.
    #[serde(default)]
    pub adapter: AdapterKind,
    /// Required isolation mode.
    pub mode: RuntimeMode,
    /// Plugin-relative executable entry point for the Command Adapter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<String>,
    /// Fixed argument array passed directly to the executable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Host environment variable names that may be inherited.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environment_allowlist: Vec<String>,
    /// Maximum execution time declared by the plugin.
    #[serde(default = "default_timeout_seconds")]
    #[schemars(range(min = 1, max = 3600))]
    pub timeout_seconds: u64,
    /// Combined stdout and stderr byte limit.
    #[serde(default = "default_output_limit_bytes")]
    #[schemars(range(min = 1, max = 16_777_216))]
    pub output_limit_bytes: usize,
    /// Docker-specific configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docker: Option<DockerAdapterSpec>,
    /// HTTP-specific configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpAdapterSpec>,
    /// File Import-specific configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_import: Option<FileImportAdapterSpec>,
}

const fn default_true() -> bool {
    true
}

/// Parser implementation class selected by a tool manifest.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ParserMode {
    /// A parser compiled into the trusted `SentinelFlow` runtime.
    Builtin,
}

/// Declarative parser selection. Parsers never execute inside the tool process.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParserSpec {
    /// Trusted parser implementation class.
    pub mode: ParserMode,
    /// Stable parser identifier understood by the runtime.
    #[schemars(length(min = 1))]
    pub name: String,
}

const fn default_timeout_seconds() -> u64 {
    30
}

const fn default_output_limit_bytes() -> usize {
    1_048_576
}

/// Tool manifest payload.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolManifestSpec {
    /// Human-readable tool name.
    #[schemars(length(min = 1))]
    pub display_name: String,
    /// Tool integration version.
    #[schemars(length(min = 1))]
    pub version: String,
    /// Capabilities declared by the integration.
    #[schemars(length(min = 1))]
    pub capabilities: Vec<CapabilitySpec>,
    /// Required runtime isolation declaration.
    pub runtime: RuntimeSpec,
    /// Parser used to convert validated runner output into protocol resources.
    pub parser: ParserSpec,
    /// Repository-relative path to the accepted input JSON Schema.
    #[schemars(length(min = 1))]
    pub input_schema: String,
    /// Repository-relative path to the produced output JSON Schema.
    #[schemars(length(min = 1))]
    pub output_schema: String,
}

/// Input payload supplied to a tool adapter.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolInputSpec {
    /// Schema identifier or repository-relative schema path.
    #[schemars(length(min = 1))]
    pub schema_ref: String,
    /// Schema-constrained input values.
    pub values: Value,
}

/// Output payload returned from parsing and normalization.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolOutputSpec {
    /// Schema identifier or repository-relative schema path.
    #[schemars(length(min = 1))]
    pub schema_ref: String,
    /// Normalized findings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<FindingSpec>,
    /// Standard errors produced while parsing or normalizing output.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<ErrorDetails>,
    /// Additional schema-constrained output values.
    pub values: Value,
}

/// Finding severity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FindingSeverity {
    /// Informational observation.
    Info,
    /// Low-severity finding.
    Low,
    /// Medium-severity finding.
    Medium,
    /// High-severity finding.
    High,
    /// Critical-severity finding.
    Critical,
}

/// A normalized finding.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingSpec {
    /// Short finding title.
    #[schemars(length(min = 1))]
    pub title: String,
    /// Finding severity.
    pub severity: FindingSeverity,
    /// Human-readable summary.
    #[schemars(length(min = 1))]
    pub summary: String,
    /// Supporting evidence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<EvidenceSpec>,
    /// Stable hash scoped to the producing tool.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fingerprint: String,
    /// Stable content hash used by the baseline cross-tool strategy.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cross_tool_fingerprint: String,
    /// Existing finding identifier selected by persistence deduplication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duplicate_of: Option<String>,
}

/// Evidence attached to a finding.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceSpec {
    /// Evidence format or category.
    #[schemars(length(min = 1))]
    pub evidence_type: String,
    /// Human-readable evidence description.
    #[schemars(length(min = 1))]
    pub description: String,
    /// Structured, non-sensitive evidence content.
    pub data: Value,
}

/// Standard error payload.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ErrorDetails {
    /// Stable machine-readable error code.
    #[schemars(length(min = 1))]
    pub code: String,
    /// Human-readable message.
    #[schemars(length(min = 1))]
    pub message: String,
    /// Optional JSON path locating the invalid field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Additional structured details.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, Value>,
}

/// Audit event outcome.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AuditOutcome {
    /// The action was allowed.
    Allowed,
    /// The action was denied by policy or validation.
    Denied,
    /// The action failed after being accepted.
    Failed,
    /// The action completed successfully.
    Succeeded,
}

/// Audit event payload.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditEventSpec {
    /// Stable action identifier.
    #[schemars(length(min = 1))]
    pub action: String,
    /// Result of the audited action.
    pub outcome: AuditOutcome,
    /// Actor identifier, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// RFC 3339 timestamp supplied by the audit producer.
    #[schemars(length(min = 1))]
    pub timestamp: String,
    /// Optional related resource reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_ref: Option<String>,
    /// Logical task identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    /// Individual run identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// Step identifier within the task.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_id: Option<String>,
    /// Registered tool identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_id: Option<String>,
    /// Actor responsible for the action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    /// Cross-component correlation identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

/// One explicitly authorized task target and its tool input.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskTargetSpec {
    /// Stable target name used by policy.
    #[schemars(length(min = 1))]
    pub name: String,
    /// Exact structured input supplied to the selected tool.
    pub input: Value,
}

/// How a failed step affects the remaining DAG.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FailurePolicy {
    /// Stop scheduling new work after the first failure.
    #[default]
    Stop,
    /// Continue scheduling nodes whose own dependencies succeeded.
    Continue,
    /// Mark every transitive dependent as skipped.
    SkipDependents,
}

/// Maps a prior normalized output value into a downstream step input.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskInputMapping {
    /// Dependency step name or its `outputAs` alias.
    #[schemars(length(min = 1))]
    pub from: String,
    /// JSON Pointer evaluated against the prior normalized `ToolOutput`.
    #[schemars(length(min = 1))]
    pub pointer: String,
    /// Field inserted into the downstream structured input.
    ///
    /// Plain names keep the legacy top-level replacement behavior. Values
    /// starting with `/` are treated as JSON Pointers and create intermediate
    /// objects as needed.
    #[schemars(length(min = 1))]
    pub target: String,
}

/// One task execution step.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskStepSpec {
    /// Step name within the task.
    #[schemars(length(min = 1))]
    pub name: String,
    /// Manifest resource name selected for the step.
    #[schemars(length(min = 1))]
    pub tool_ref: String,
    /// Capability requested from the Manifest.
    #[schemars(length(min = 1))]
    pub capability: String,
    /// Step names that must complete successfully before this step is ready.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
    /// Values mapped from prior normalized outputs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub input_from: Vec<TaskInputMapping>,
    /// Optional structured input for this step.
    ///
    /// When omitted, the target-level input remains the source of truth for
    /// backward compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<serde_json::Value>,
    /// Optional stable alias for this step's normalized output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_as: Option<String>,
    /// Failure propagation behavior.
    #[serde(default)]
    pub failure_policy: FailurePolicy,
}

/// UTC wall-clock execution window.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyTimeWindow {
    /// Inclusive `HH:MM` start in UTC.
    pub start: String,
    /// Exclusive `HH:MM` end in UTC. Values earlier than start cross midnight.
    pub end: String,
}

/// Output retention constraints.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutputRetentionPolicy {
    /// Number of days normalized output may be retained.
    #[schemars(range(min = 0, max = 3650))]
    pub days: u32,
    /// Whether normalized evidence may be retained.
    #[serde(default = "default_true")]
    pub retain_evidence: bool,
}

/// Task-local execution policy.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskExecutionPolicy {
    /// Target names explicitly authorized for this task.
    #[schemars(length(min = 1))]
    pub allowed_targets: Vec<String>,
    /// Domain, URL, IP, or CIDR patterns allowed by the task.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_patterns: Vec<String>,
    /// Explicit approval for high or critical risk tools.
    #[serde(default)]
    pub approve_high_risk: bool,
    /// Persisted approval request used for high or critical risk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_ref: Option<String>,
    /// Optional timeout lower than or equal to the Manifest ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1, max = 3600))]
    pub timeout_seconds: Option<u64>,
    /// Maximum concurrently running DAG nodes.
    #[serde(default = "default_task_concurrency")]
    #[schemars(range(min = 1, max = 64))]
    pub max_concurrency: usize,
    /// Maximum node starts per minute.
    #[serde(default = "default_rate_limit")]
    #[schemars(range(min = 1, max = 10000))]
    pub rate_limit_per_minute: u32,
    /// Optional UTC execution windows.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub time_windows: Vec<PolicyTimeWindow>,
    /// Output retention constraints.
    #[serde(default = "default_retention")]
    pub output_retention: OutputRetentionPolicy,
}

const fn default_task_concurrency() -> usize {
    1
}

const fn default_rate_limit() -> u32 {
    60
}

const fn default_retention() -> OutputRetentionPolicy {
    OutputRetentionPolicy {
        days: 30,
        retain_evidence: true,
    }
}

/// DAG task request payload.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskSpecData {
    /// Explicit authorization boundary for this task.
    #[schemars(length(min = 1))]
    pub authorization_scope: String,
    /// One or more explicitly named targets.
    #[schemars(length(min = 1))]
    pub targets: Vec<TaskTargetSpec>,
    /// DAG execution steps.
    #[schemars(length(min = 1))]
    pub steps: Vec<TaskStepSpec>,
    /// Task-local policy constraints.
    pub policy: TaskExecutionPolicy,
}

/// Draft policy effect.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PolicyEffect {
    /// Deny matching requests.
    Deny,
    /// Allow matching requests when every declared condition is satisfied.
    Allow,
}

/// Draft policy rule.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyRule {
    /// Stable rule name.
    #[schemars(length(min = 1))]
    pub name: String,
    /// Rule effect.
    pub effect: PolicyEffect,
    /// Authorization scopes matched by this rule.
    #[schemars(length(min = 1))]
    pub authorization_scopes: Vec<String>,
    /// Capability names matched by this rule.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    /// Whether explicit approval is required when this rule allows a request.
    pub requires_approval: bool,
}

/// Draft policy payload.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicySpec {
    /// Effect used when no rule matches. It must remain deny in `v1alpha1`.
    pub default_effect: PolicyEffect,
    /// Ordered draft policy rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<PolicyRule>,
}

macro_rules! define_resource {
    (
        $(#[$resource_meta:meta])*
        $resource:ident,
        $kind:ident,
        $kind_wire:literal,
        $spec:ty,
        $field:ident
    ) => {
        $(#[$resource_meta])*
        #[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $resource {
            /// Protocol API version.
            pub api_version: ProtocolVersion,
            /// Protocol resource kind.
            pub kind: $kind,
            /// Common resource metadata.
            pub metadata: Metadata,
            /// Resource-specific payload.
            pub $field: $spec,
            /// Forward-compatible extension values.
            #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
            pub extensions: BTreeMap<String, Value>,
        }

        #[doc = concat!("Kind discriminator for [`", stringify!($resource), "`].")]
        #[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
        pub enum $kind {
            #[doc = concat!("The `", $kind_wire, "` resource kind.")]
            #[serde(rename = $kind_wire)]
            Value,
        }
    };
}

define_resource!(
    /// A manifest describing an external tool integration.
    ToolManifest,
    ToolManifestKind,
    "ToolManifest",
    ToolManifestSpec,
    spec
);
define_resource!(
    /// A standalone capability declaration.
    Capability,
    CapabilityKind,
    "Capability",
    CapabilitySpec,
    spec
);
define_resource!(
    /// A standalone tool input resource.
    ToolInput,
    ToolInputKind,
    "ToolInput",
    ToolInputSpec,
    spec
);
define_resource!(
    /// A standalone normalized tool output resource.
    ToolOutput,
    ToolOutputKind,
    "ToolOutput",
    ToolOutputSpec,
    spec
);
define_resource!(
    /// A standalone normalized finding resource.
    Finding,
    FindingKind,
    "Finding",
    FindingSpec,
    spec
);
define_resource!(
    /// A standalone evidence resource.
    Evidence,
    EvidenceKind,
    "Evidence",
    EvidenceSpec,
    spec
);
define_resource!(
    /// A standard protocol error resource.
    StandardError,
    StandardErrorKind,
    "StandardError",
    ErrorDetails,
    error
);
define_resource!(
    /// An auditable protocol event.
    AuditEvent,
    AuditEventKind,
    "AuditEvent",
    AuditEventSpec,
    spec
);
define_resource!(
    /// A policy-controlled DAG task specification.
    TaskSpec,
    TaskSpecKind,
    "TaskSpec",
    TaskSpecData,
    spec
);
define_resource!(
    /// A draft policy resource.
    Policy,
    PolicyKind,
    "Policy",
    PolicySpec,
    spec
);
