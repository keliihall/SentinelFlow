//! Controlled execution contracts for `SentinelFlow`.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use jsonschema::JSONSchema;
use schemars::schema_for;
use sentinelflow_policy::{ExecutionPolicyRequest, authorize};
use sentinelflow_schema::v1alpha1::{
    ErrorDetails, FindingSeverity, FindingSpec, Metadata, ProtocolVersion, RiskLevel,
    StandardError, StandardErrorKind, ToolManifest, ToolOutput, ToolOutputKind, ToolOutputSpec,
    Validate, ValidationContext,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Correlation identifiers attached to every execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionIdentifiers {
    /// Logical task identifier.
    pub task_id: String,
    /// Individual run identifier.
    pub run_id: String,
    /// Step identifier within the task.
    pub step_id: String,
    /// Registered tool identifier.
    pub tool_id: String,
    /// Cross-component correlation identifier.
    pub correlation_id: String,
}

impl ExecutionIdentifiers {
    /// Generates identifiers for one tool execution.
    #[must_use]
    pub fn generate(tool_id: impl Into<String>) -> Self {
        Self {
            task_id: format!("task-{}", Uuid::new_v4()),
            run_id: format!("run-{}", Uuid::new_v4()),
            step_id: format!("step-{}", Uuid::new_v4()),
            tool_id: tool_id.into(),
            correlation_id: format!("corr-{}", Uuid::new_v4()),
        }
    }
}

/// Request passed to a controlled adapter.
#[derive(Clone, Debug)]
pub struct ExecutionRequest {
    /// Required correlation identifiers.
    pub identifiers: ExecutionIdentifiers,
    /// Validated plugin root.
    pub plugin_root: PathBuf,
    /// Validated Manifest.
    pub manifest: ToolManifest,
    /// Capability selected for execution.
    pub capability: String,
    /// Caller-provided structured input.
    pub input: Value,
    /// Explicit authorization scope.
    pub authorization_scope: Option<String>,
    /// Explicit approval for high or critical capabilities.
    pub approved: bool,
    /// Requested execution timeout.
    pub timeout: Duration,
}

/// Terminal execution status.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ExecutionStatus {
    /// Process completed and normalized output passed Schema validation.
    Succeeded,
    /// Process exceeded the timeout.
    TimedOut,
    /// User or caller cancelled the run.
    Cancelled,
    /// Process exited unsuccessfully.
    Failed,
    /// Combined output exceeded the configured limit.
    OutputLimitExceeded,
}

/// Result returned after collection and output validation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionResult {
    /// Correlation identifiers copied from the request.
    pub identifiers: ExecutionIdentifiers,
    /// Terminal status.
    pub status: ExecutionStatus,
    /// Validated and normalized JSON output. Raw stdout is never retained here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<Value>,
    /// Child exit code when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Wall-clock execution duration.
    pub duration_ms: u128,
}

/// Opaque adapter error category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeErrorKind {
    /// Policy denied the request.
    PolicyDenied,
    /// Input did not satisfy its Schema.
    InputInvalid,
    /// Plugin or entrypoint path was invalid.
    InvalidPath,
    /// Runner was missing or unusable.
    RunnerUnavailable,
    /// Process could not be started or managed.
    Process,
    /// Process exited unsuccessfully.
    ExitFailure,
    /// Timeout elapsed.
    Timeout,
    /// User cancelled the run.
    Cancelled,
    /// Output exceeded the configured limit.
    OutputLimit,
    /// Output was not valid JSON or failed its Schema.
    OutputInvalid,
    /// Internal system operation failed.
    System,
}

/// Error returned by an adapter or runtime boundary.
#[derive(Debug)]
pub struct RuntimeError {
    /// Stable category.
    pub kind: RuntimeErrorKind,
    /// JSON-compatible field path when available.
    pub field: Option<String>,
    /// Non-sensitive explanation.
    pub message: String,
}

impl RuntimeError {
    /// Creates a runtime error.
    #[must_use]
    pub fn new(kind: RuntimeErrorKind, field: Option<String>, message: impl Into<String>) -> Self {
        Self {
            kind,
            field,
            message: message.into(),
        }
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(field) = &self.field {
            write!(formatter, "{field}: {}", self.message)
        } else {
            formatter.write_str(&self.message)
        }
    }
}

impl std::error::Error for RuntimeError {}

/// Runtime environment values that adapters may expose to a runner.
#[derive(Clone, Debug, Default)]
pub struct RuntimeEnvironment {
    /// Explicit values, filtered by the Manifest allowlist during preparation.
    pub values: BTreeMap<String, String>,
}

/// Shared cancellation handle for a run.
#[derive(Clone, Debug)]
pub struct ExecutionCancellation {
    token: CancellationToken,
}

impl ExecutionCancellation {
    /// Creates a fresh cancellation handle.
    #[must_use]
    pub fn new() -> Self {
        Self {
            token: CancellationToken::new(),
        }
    }

    /// Requests cancellation.
    pub fn cancel(&self) {
        self.token.cancel();
    }

    /// Returns whether cancellation was requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }

    /// Waits until cancellation is requested.
    pub async fn cancelled(&self) {
        self.token.cancelled().await;
    }
}

impl Default for ExecutionCancellation {
    fn default() -> Self {
        Self::new()
    }
}

/// Features an Adapter can provide to the runtime.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)]
pub struct AdapterCapabilities {
    /// Whether active work can be cancelled.
    pub cancellation: bool,
    /// Whether logs can be emitted while work is running.
    pub streaming_logs: bool,
    /// Whether CPU or memory limits can be enforced.
    pub resource_limits: bool,
    /// Whether the Adapter supports submit-and-poll jobs.
    pub asynchronous_tasks: bool,
}

/// Common lifecycle implemented by every execution adapter.
#[async_trait]
pub trait Adapter: Send + Sync {
    /// Adapter-specific prepared state.
    type Prepared: Send;
    /// Adapter-specific running state.
    type Running: Send;

    /// Returns the Adapter's static feature capabilities.
    fn capabilities(&self) -> AdapterCapabilities;

    /// Validates policy, input, paths, and execution configuration.
    async fn prepare(&self, request: ExecutionRequest) -> Result<Self::Prepared, RuntimeError>;

    /// Starts the prepared operation.
    async fn execute(&self, prepared: Self::Prepared) -> Result<Self::Running, RuntimeError>;

    /// Collects, validates, and normalizes the terminal result.
    async fn collect(&self, running: Self::Running) -> Result<ExecutionResult, RuntimeError>;

    /// Requests cancellation of a running operation.
    async fn cancel(&self, run_id: &str) -> Result<(), RuntimeError>;
}

/// Finds the requested capability risk in a Manifest.
#[must_use]
pub fn capability_risk(manifest: &ToolManifest, capability: &str) -> Option<RiskLevel> {
    manifest
        .spec
        .capabilities
        .iter()
        .find(|candidate| candidate.name == capability)
        .map(|candidate| candidate.risk)
}

/// Applies the shared default-deny policy used by every Adapter.
///
/// # Errors
///
/// Returns a policy runtime error when execution is not explicitly authorized.
pub fn authorize_execution(request: &ExecutionRequest) -> Result<(), RuntimeError> {
    let risk = capability_risk(&request.manifest, &request.capability).ok_or_else(|| {
        RuntimeError::new(
            RuntimeErrorKind::PolicyDenied,
            Some("$.capability".to_owned()),
            "requested capability is not declared by the Manifest",
        )
    })?;
    let example_label = request
        .manifest
        .metadata
        .labels
        .get("sentinelflow.io/example")
        .is_some_and(|value| value == "true");
    let official_label = request
        .manifest
        .metadata
        .labels
        .get("sentinelflow.io/official")
        .is_some_and(|value| value == "true");
    let known_example = matches!(
        request.manifest.metadata.name.as_str(),
        "example-echo"
            | "example-dns-resolve"
            | "example-file-import"
            | "example-docker-adapter"
            | "example-http-adapter"
            | "example-structured-import"
            | "example-finding-consumer"
            | "example-failure"
            | "example-slow"
            | "example-high-risk"
            | "example-invalid-parser"
            | "example-restricted-high-risk"
    );
    let known_official = matches!(
        request.manifest.metadata.name.as_str(),
        "subdomain-discovery"
            | "subdomain-discovery-plus"
            | "dns-resolve-plus"
            | "crtsh-subdomain-plus"
            | "ip-enrichment-plus"
            | "port-probe-plus"
            | "http-probe-plus"
            | "web-fingerprint-plus"
            | "tls-certificate-check-plus"
            | "fofa-import-plus"
            | "shodan-import-plus"
            | "censys-import-plus"
            | "nessus-import-plus"
            | "openvas-import-plus"
            | "nuclei-adapter-plus"
            | "zap-baseline-plus"
            | "cloud-asset-import-plus"
            | "cmdb-sync-plus"
            | "markdown-report-plus"
            | "service-detect-plus"
    );
    let sdk_scaffold = request.plugin_root.join(".sentinelflow-scaffold").is_file();
    let example_plugin =
        (example_label && (known_example || sdk_scaffold)) || (official_label && known_official);
    authorize(&ExecutionPolicyRequest {
        example_plugin,
        authorization_scope: request.authorization_scope.as_deref(),
        risk,
        approved: request.approved,
        requested_timeout: request.timeout,
        maximum_timeout: Duration::from_secs(request.manifest.spec.runtime.timeout_seconds),
    })
    .map(|_| ())
    .map_err(|error| {
        RuntimeError::new(
            RuntimeErrorKind::PolicyDenied,
            Some(error.field.to_owned()),
            error.message,
        )
    })
}

/// Reference to raw adapter output. The value is borrowed and is never persisted by
/// the parser contract.
#[derive(Clone, Copy, Debug)]
pub struct RawOutputReference<'a> {
    /// Run that produced the output.
    pub run_id: &'a str,
    /// Validated adapter output held in memory.
    pub value: &'a Value,
}

/// Execution context supplied to a parser.
#[derive(Clone, Debug)]
pub struct ParserContext<'a> {
    /// Correlation identifiers for the execution.
    pub identifiers: &'a ExecutionIdentifiers,
    /// Actor that requested the execution.
    pub actor_id: &'a str,
}

/// Input passed to a trusted parser.
#[derive(Clone, Debug)]
pub struct ParserInput<'a> {
    /// Borrowed raw output reference.
    pub raw: RawOutputReference<'a>,
    /// Execution context.
    pub context: ParserContext<'a>,
}

/// Trusted parser calling convention.
pub trait Parser: Send + Sync {
    /// Converts raw output into a JSON parser envelope.
    ///
    /// The normalizer must decode and validate the returned envelope before it is
    /// accepted as protocol output.
    ///
    /// # Errors
    ///
    /// Returns a standard error when raw output cannot be parsed safely.
    fn parse(&self, input: &ParserInput<'_>) -> Result<Value, ErrorDetails>;
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ParserEnvelope {
    #[serde(default)]
    findings: Vec<FindingSpec>,
    #[serde(default)]
    errors: Vec<ErrorDetails>,
    values: Value,
}

/// Normalization failure represented by a standard protocol error.
#[derive(Debug)]
pub struct NormalizationError {
    /// Standard error safe to persist and report.
    pub error: StandardError,
}

impl fmt::Display for NormalizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.error.error.message)
    }
}

impl std::error::Error for NormalizationError {}

/// Selects a trusted built-in parser by manifest identifier.
///
/// # Errors
///
/// Returns a standard normalization error for unknown parser identifiers.
pub fn builtin_parser(name: &str) -> Result<Box<dyn Parser>, NormalizationError> {
    match name {
        "example-echo-v1" => Ok(Box::new(ExampleEchoParser)),
        "example-dns-resolve-v1" => Ok(Box::new(DnsResolveParser)),
        "example-file-import-v1" => Ok(Box::new(FileImportParser)),
        "subdomain-discovery-plus-v1" => Ok(Box::new(SubdomainDiscoveryPlusParser)),
        "dns-resolve-plus-v1" => Ok(Box::new(DnsResolvePlusParser)),
        "crtsh-subdomain-plus-v1" => Ok(Box::new(CrtshSubdomainPlusParser)),
        "ip-enrichment-plus-v1" => Ok(Box::new(IpEnrichmentPlusParser)),
        "port-probe-plus-v1" => Ok(Box::new(PortProbePlusParser)),
        "http-probe-plus-v1" => Ok(Box::new(HttpProbePlusParser)),
        "web-fingerprint-plus-v1" => Ok(Box::new(WebFingerprintPlusParser)),
        "tls-certificate-check-plus-v1" => Ok(Box::new(TlsCertificateCheckPlusParser)),
        "fofa-import-plus-v1" => Ok(Box::new(FofaImportPlusParser)),
        "shodan-import-plus-v1" => Ok(Box::new(ShodanImportPlusParser)),
        "censys-import-plus-v1" => Ok(Box::new(CensysImportPlusParser)),
        "nessus-import-plus-v1" => Ok(Box::new(NessusImportPlusParser)),
        "openvas-import-plus-v1" => Ok(Box::new(OpenvasImportPlusParser)),
        "nuclei-adapter-plus-v1" => Ok(Box::new(NucleiAdapterPlusParser)),
        "zap-baseline-plus-v1" => Ok(Box::new(ZapBaselinePlusParser)),
        "cloud-asset-import-plus-v1" => Ok(Box::new(CloudAssetImportPlusParser)),
        "cmdb-sync-plus-v1" => Ok(Box::new(CmdbSyncPlusParser)),
        "markdown-report-plus-v1" => Ok(Box::new(MarkdownReportPlusParser)),
        "service-detect-plus-v1" => Ok(Box::new(ServiceDetectPlusParser)),
        "fixture-invalid-output-v1" => Ok(Box::new(InvalidOutputFixtureParser)),
        _ => Err(normalization_error(
            "ParserUnavailable",
            format!("trusted parser is not available: {name}"),
            Some("$.manifest.spec.parser.name".to_owned()),
        )),
    }
}

/// Converts parser output to a `ToolOutput` and validates the protocol resource.
///
/// # Errors
///
/// Returns a standard error when the parser fails, returns an invalid envelope, or
/// the resulting resource fails semantic validation.
pub fn normalize(
    parser: &dyn Parser,
    input: &ParserInput<'_>,
    schema_ref: &str,
) -> Result<ToolOutput, NormalizationError> {
    let parsed = parser.parse(input).map_err(|details| NormalizationError {
        error: standard_error(details, input.context.identifiers),
    })?;
    let mut envelope: ParserEnvelope = serde_json::from_value(parsed).map_err(|error| {
        normalization_error(
            "ParserOutputInvalid",
            format!("parser output does not match the normalization contract: {error}"),
            Some("$.parserOutput".to_owned()),
        )
    })?;
    assign_fingerprints_and_deduplicate(
        &mut envelope.findings,
        &input.context.identifiers.tool_id,
    )?;
    let output = ToolOutput {
        api_version: ProtocolVersion::V1Alpha1,
        kind: ToolOutputKind::Value,
        metadata: Metadata {
            name: format!("result-{}", input.context.identifiers.run_id),
            namespace: None,
            uid: Some(input.context.identifiers.run_id.clone()),
            labels: BTreeMap::from([
                (
                    "sentinelflow.io/tool-id".to_owned(),
                    input.context.identifiers.tool_id.clone(),
                ),
                (
                    "sentinelflow.io/task-id".to_owned(),
                    input.context.identifiers.task_id.clone(),
                ),
            ]),
            annotations: BTreeMap::from([(
                "sentinelflow.io/actor-id".to_owned(),
                input.context.actor_id.to_owned(),
            )]),
        },
        spec: ToolOutputSpec {
            schema_ref: schema_ref.to_owned(),
            findings: envelope.findings,
            errors: envelope.errors,
            values: envelope.values,
        },
        extensions: BTreeMap::new(),
    };
    validate_tool_output_schema(&output)?;
    output
        .validate(&ValidationContext::new("."))
        .map_err(|errors| {
            normalization_error(
                "NormalizedOutputInvalid",
                errors.to_string(),
                errors.errors().first().map(|error| error.path.clone()),
            )
        })?;
    Ok(output)
}

fn assign_fingerprints_and_deduplicate(
    findings: &mut Vec<FindingSpec>,
    tool_id: &str,
) -> Result<(), NormalizationError> {
    let mut seen = HashSet::new();
    for finding in findings.iter_mut() {
        let content = serde_json::to_vec(&serde_json::json!({
            "title": finding.title,
            "severity": finding.severity,
            "summary": finding.summary,
            "evidence": finding.evidence,
        }))
        .map_err(|error| {
            normalization_error(
                "FingerprintFailed",
                format!("failed to encode finding fingerprint input: {error}"),
                Some("$.findings".to_owned()),
            )
        })?;
        finding.cross_tool_fingerprint = sha256_hex(&content);
        let mut scoped = tool_id.as_bytes().to_vec();
        scoped.push(0);
        scoped.extend_from_slice(&content);
        finding.fingerprint = sha256_hex(&scoped);
        finding.duplicate_of = None;
    }
    findings.retain(|finding| seen.insert(finding.fingerprint.clone()));
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().fold(
        String::with_capacity(digest.len() * 2),
        |mut output, byte| {
            let _ = write!(output, "{byte:02x}");
            output
        },
    )
}

fn validate_tool_output_schema(output: &ToolOutput) -> Result<(), NormalizationError> {
    let schema = serde_json::to_value(schema_for!(ToolOutput)).map_err(|error| {
        normalization_error(
            "SchemaCompilationFailed",
            format!("failed to encode ToolOutput Schema: {error}"),
            Some("$.schema".to_owned()),
        )
    })?;
    let compiled = JSONSchema::compile(&schema).map_err(|error| {
        normalization_error(
            "SchemaCompilationFailed",
            format!("failed to compile ToolOutput Schema: {error}"),
            Some("$.schema".to_owned()),
        )
    })?;
    let value = serde_json::to_value(output).map_err(|error| {
        normalization_error(
            "NormalizedOutputInvalid",
            format!("failed to encode normalized ToolOutput: {error}"),
            Some("$.output".to_owned()),
        )
    })?;
    if let Err(mut errors) = compiled.validate(&value) {
        if let Some(error) = errors.next() {
            return Err(normalization_error(
                "NormalizedOutputInvalid",
                format!("normalized ToolOutput failed Schema validation: {error}"),
                Some(format!("$.output{}", error.instance_path)),
            ));
        }
    }
    Ok(())
}

struct ExampleEchoParser;

impl Parser for ExampleEchoParser {
    fn parse(&self, input: &ParserInput<'_>) -> Result<Value, ErrorDetails> {
        let message = input
            .raw
            .value
            .get("message")
            .and_then(Value::as_str)
            .ok_or_else(|| ErrorDetails {
                code: "ParserInputInvalid".to_owned(),
                message: "example echo output must contain a string message".to_owned(),
                field: Some("$.raw.message".to_owned()),
                details: BTreeMap::new(),
            })?;
        Ok(serde_json::json!({
            "values": input.raw.value,
            "findings": [{
                "title": "Example echo completed",
                "severity": FindingSeverity::Info,
                "summary": "The safe example plugin returned a synthetic message.",
                "evidence": [{
                    "evidenceType": "synthetic-message",
                    "description": "Structured output emitted by the local example runner.",
                    "data": {"message": message}
                }]
            }],
            "errors": []
        }))
    }
}

struct InvalidOutputFixtureParser;

impl Parser for InvalidOutputFixtureParser {
    fn parse(&self, _input: &ParserInput<'_>) -> Result<Value, ErrorDetails> {
        Ok(serde_json::json!({"findings": "invalid fixture envelope"}))
    }
}

struct DnsResolveParser;

impl Parser for DnsResolveParser {
    fn parse(&self, input: &ParserInput<'_>) -> Result<Value, ErrorDetails> {
        let hostname = required_string(input.raw.value, "hostname")?;
        let addresses = input
            .raw
            .value
            .get("addresses")
            .and_then(Value::as_array)
            .ok_or_else(|| parser_field_error("$.raw.addresses", "addresses must be an array"))?;
        Ok(serde_json::json!({
            "values": input.raw.value,
            "findings": [{
                "title": "Fixture DNS resolution completed",
                "severity": FindingSeverity::Info,
                "summary": format!("Resolved {hostname} using the local mock table."),
                "evidence": [{
                    "evidenceType": "mock-dns-records",
                    "description": "Synthetic documentation-range addresses from the example fixture.",
                    "data": {"hostname": hostname, "addresses": addresses}
                }]
            }],
            "errors": []
        }))
    }
}

struct FileImportParser;

impl Parser for FileImportParser {
    fn parse(&self, input: &ParserInput<'_>) -> Result<Value, ErrorDetails> {
        let source = required_string(input.raw.value, "source")?;
        let records = input
            .raw
            .value
            .get("records")
            .and_then(Value::as_array)
            .ok_or_else(|| parser_field_error("$.raw.records", "records must be an array"))?;
        Ok(serde_json::json!({
            "values": input.raw.value,
            "findings": if records.is_empty() { Vec::<Value>::new() } else { vec![serde_json::json!({
                "title": "Structured records imported",
                "severity": FindingSeverity::Info,
                "summary": format!("Imported {} structured records from {source}.", records.len()),
                "evidence": [{
                    "evidenceType": "structured-record-count",
                    "description": "Count of structured records supplied by the runner.",
                    "data": {"source": source, "count": records.len()}
                }]
            })] },
            "errors": []
        }))
    }
}

struct SubdomainDiscoveryPlusParser;

struct CrtshSubdomainPlusParser;

struct IpEnrichmentPlusParser;

impl Parser for SubdomainDiscoveryPlusParser {
    #[allow(clippy::too_many_lines)]
    fn parse(&self, input: &ParserInput<'_>) -> Result<Value, ErrorDetails> {
        let raw_findings = input
            .raw
            .value
            .get("findings")
            .and_then(Value::as_array)
            .ok_or_else(|| parser_field_error("$.raw.findings", "findings must be an array"))?;
        let mut findings = Vec::with_capacity(raw_findings.len());
        for (index, raw_finding) in raw_findings.iter().enumerate() {
            if raw_finding.get("type").and_then(Value::as_str) == Some("subdomain_candidate") {
                continue;
            }
            if raw_finding.get("type").and_then(Value::as_str) != Some("subdomain_finding") {
                return Err(parser_field_error(
                    format!("$.raw.findings[{index}].type"),
                    "finding type must be subdomain_finding",
                ));
            }
            let domain = required_string(raw_finding, "domain")?;
            let subdomain = required_string(raw_finding, "subdomain")?;
            let sources = string_array(raw_finding, "sources", index)?;
            let resolved = raw_finding
                .get("resolved")
                .and_then(Value::as_bool)
                .ok_or_else(|| {
                    parser_field_error(
                        format!("$.raw.findings[{index}].resolved"),
                        "resolved must be a boolean",
                    )
                })?;
            let record_type = raw_finding
                .get("record_type")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let addresses = raw_finding
                .get("addresses")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let records = raw_finding
                .get("records")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let confidence = raw_finding
                .get("confidence")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let source_details = raw_finding
                .get("source_details")
                .cloned()
                .unwrap_or_else(|| serde_json::json!([]));
            let confirmed = raw_finding
                .get("confirmed")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let status = raw_finding
                .get("status")
                .cloned()
                .unwrap_or_else(|| Value::String("confirmed".to_owned()));
            let synthetic_fixture = raw_finding
                .get("synthetic_fixture")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let real_scan = raw_finding
                .get("real_scan")
                .and_then(Value::as_bool)
                .unwrap_or(!synthetic_fixture);
            let authorization_scope = input
                .raw
                .value
                .get("run_context")
                .and_then(|context| context.get("authorization_scope"))
                .cloned()
                .unwrap_or(Value::Null);
            let mode = input.raw.value.get("mode").cloned().unwrap_or(Value::Null);
            let summary = raw_finding
                .get("evidence")
                .and_then(|evidence| evidence.get("summary"))
                .and_then(Value::as_str)
                .map_or_else(
                    || format!("Discovered subdomain {subdomain} for {domain}."),
                    ToOwned::to_owned,
                );
            findings.push(serde_json::json!({
                "title": "Discovered subdomain",
                "severity": FindingSeverity::Info,
                "summary": summary,
                "evidence": [{
                    "evidenceType": "subdomain-discovery",
                    "description": "Structured subdomain discovery evidence.",
                    "data": {
                        "findingType": "asset.subdomain",
                        "target": {"type": "domain", "value": domain},
                        "confidence": confidence,
                        "x-sentinelflow-subdomain.domain": domain,
                        "x-sentinelflow-subdomain.subdomain": subdomain,
                        "x-sentinelflow-subdomain.sources": sources,
                        "x-sentinelflow-subdomain.resolved": resolved,
                        "x-sentinelflow-subdomain.confirmed": confirmed,
                        "x-sentinelflow-subdomain.status": status,
                        "x-sentinelflow-subdomain.recordType": record_type,
                        "x-sentinelflow-subdomain.addresses": addresses,
                        "x-sentinelflow-subdomain.records": records,
                        "x-sentinelflow-subdomain.source_details": source_details,
                        "x-sentinelflow-run.mode": mode,
                        "x-sentinelflow-run.authorization_scope": authorization_scope,
                        "x-sentinelflow-fixture.synthetic": synthetic_fixture,
                        "x-sentinelflow-fixture.source": if synthetic_fixture { Value::String("local_fixture".to_owned()) } else { Value::Null },
                        "x-sentinelflow-fixture.real_scan": real_scan,
                        "raw": raw_finding.get("raw").cloned().unwrap_or(Value::Null)
                    }
                }]
            }));
        }
        Ok(serde_json::json!({
            "values": input.raw.value,
            "findings": findings,
            "errors": parser_errors(input.raw.value)
        }))
    }
}

impl Parser for CrtshSubdomainPlusParser {
    #[allow(clippy::too_many_lines)]
    fn parse(&self, input: &ParserInput<'_>) -> Result<Value, ErrorDetails> {
        let raw_findings = input
            .raw
            .value
            .get("findings")
            .and_then(Value::as_array)
            .ok_or_else(|| parser_field_error("$.raw.findings", "findings must be an array"))?;
        let raw_certificates = input
            .raw
            .value
            .get("certificates")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                parser_field_error("$.raw.certificates", "certificates must be an array")
            })?;
        let mut findings = Vec::with_capacity(raw_findings.len() + raw_certificates.len());
        for (index, raw_finding) in raw_findings.iter().enumerate() {
            if raw_finding.get("type").and_then(Value::as_str) != Some("subdomain_finding") {
                return Err(parser_field_error(
                    format!("$.raw.findings[{index}].type"),
                    "finding type must be subdomain_finding",
                ));
            }
            let domain = required_result_string(raw_finding, "domain", index)?;
            let subdomain = required_result_string(raw_finding, "subdomain", index)?;
            let sources = string_array(raw_finding, "sources", index)?;
            let confidence = raw_finding
                .get("confidence")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let summary = raw_finding
                .get("evidence")
                .and_then(|evidence| evidence.get("summary"))
                .and_then(Value::as_str)
                .map_or_else(
                    || format!("crt.sh certificate transparency observed {subdomain}."),
                    ToOwned::to_owned,
                );
            findings.push(serde_json::json!({
                "title": "Subdomain observed in certificate transparency",
                "severity": FindingSeverity::Info,
                "summary": summary,
                "evidence": [{
                    "evidenceType": "certificate-transparency-subdomain",
                    "description": "Structured crt.sh certificate transparency subdomain evidence.",
                    "data": {
                        "findingType": "asset.subdomain",
                        "target": {"type": "domain", "value": subdomain},
                        "confidence": confidence,
                        "x-sentinelflow-subdomain.domain": domain,
                        "x-sentinelflow-subdomain.subdomain": subdomain,
                        "x-sentinelflow-subdomain.sources": sources,
                        "x-sentinelflow-subdomain.source_count": raw_finding.get("source_count").cloned().unwrap_or_else(|| serde_json::json!(sources.len())),
                        "x-sentinelflow-subdomain.source_details": raw_finding.get("source_details").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-subdomain.first_seen": raw_finding.get("first_seen").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-subdomain.last_seen": raw_finding.get("last_seen").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-subdomain.wildcard_cleaned": raw_finding.get("wildcard_cleaned").cloned().unwrap_or(Value::Bool(false)),
                        "x-sentinelflow-subdomain.resolved": raw_finding.get("resolved").cloned().unwrap_or(Value::Bool(false)),
                        "x-sentinelflow-subdomain.confirmed": raw_finding.get("confirmed").cloned().unwrap_or(Value::Bool(false)),
                    }
                }]
            }));
        }
        for (index, raw_certificate) in raw_certificates.iter().enumerate() {
            if raw_certificate.get("type").and_then(Value::as_str) != Some("certificate_asset") {
                return Err(parser_field_error(
                    format!("$.raw.certificates[{index}].type"),
                    "certificate type must be certificate_asset",
                ));
            }
            let domain = required_result_string(raw_certificate, "domain", index)?;
            let confidence = raw_certificate
                .get("confidence")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let common_name = raw_certificate
                .get("common_name")
                .and_then(Value::as_str)
                .unwrap_or(domain);
            let summary = raw_certificate
                .get("evidence")
                .and_then(|evidence| evidence.get("summary"))
                .and_then(Value::as_str)
                .map_or_else(
                    || format!("crt.sh certificate entry observed SAN assets for {domain}."),
                    ToOwned::to_owned,
                );
            findings.push(serde_json::json!({
                "title": "Certificate transparency asset observed",
                "severity": FindingSeverity::Info,
                "summary": summary,
                "evidence": [{
                    "evidenceType": "certificate-transparency-certificate",
                    "description": "Structured crt.sh certificate and SAN asset evidence.",
                    "data": {
                        "findingType": "asset.tls_certificate",
                        "target": {"type": "domain", "value": domain},
                        "confidence": confidence,
                        "x-sentinelflow-tls-certificate.host": domain,
                        "x-sentinelflow-tls-certificate.subject": common_name,
                        "x-sentinelflow-tls-certificate.issuer": raw_certificate.get("issuer_name").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-tls-certificate.san": raw_certificate.get("san_names").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-tls-certificate.not_before": raw_certificate.get("not_before").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-tls-certificate.not_after": raw_certificate.get("not_after").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-tls-certificate.status": if raw_certificate.get("expired").and_then(Value::as_bool).unwrap_or(false) { "expired" } else { "observed" },
                        "x-sentinelflow-tls-certificate.ct_entry_id": raw_certificate.get("entry_id").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-tls-certificate.logged_at": raw_certificate.get("logged_at").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-tls-certificate.san_assets": raw_certificate.get("san_names").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-tls-certificate.sources": raw_certificate.get("sources").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-tls-certificate.source_count": raw_certificate.get("source_count").cloned().unwrap_or_else(|| serde_json::json!(0)),
                        "x-sentinelflow-tls-certificate.source_details": raw_certificate.get("source_details").cloned().unwrap_or_else(|| serde_json::json!([])),
                    }
                }]
            }));
        }
        Ok(serde_json::json!({
            "values": input.raw.value,
            "findings": findings,
            "errors": parser_errors(input.raw.value)
        }))
    }
}

impl Parser for IpEnrichmentPlusParser {
    #[allow(clippy::too_many_lines)]
    fn parse(&self, input: &ParserInput<'_>) -> Result<Value, ErrorDetails> {
        let raw_results = input
            .raw
            .value
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| parser_field_error("$.raw.results", "results must be an array"))?;
        let mut findings = Vec::with_capacity(raw_results.len());
        for (index, raw_result) in raw_results.iter().enumerate() {
            if raw_result.get("type").and_then(Value::as_str) != Some("ip_enrichment_result") {
                return Err(parser_field_error(
                    format!("$.raw.results[{index}].type"),
                    "result type must be ip_enrichment_result",
                ));
            }
            let ip = required_result_string(raw_result, "ip", index)?;
            let classification = required_result_string(raw_result, "classification", index)?;
            let is_public = raw_result
                .get("is_public")
                .and_then(Value::as_bool)
                .ok_or_else(|| {
                    parser_field_error(
                        format!("$.raw.results[{index}].is_public"),
                        "is_public must be a boolean",
                    )
                })?;
            let ip_version = raw_result
                .get("ip_version")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    parser_field_error(
                        format!("$.raw.results[{index}].ip_version"),
                        "ip_version must be an unsigned integer",
                    )
                })?;
            let confidence = raw_result
                .get("confidence")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let summary = raw_result
                .get("evidence")
                .and_then(|evidence| evidence.get("summary"))
                .and_then(Value::as_str)
                .map_or_else(
                    || format!("IP enrichment classified {ip} as {classification}."),
                    ToOwned::to_owned,
                );
            findings.push(serde_json::json!({
                "title": "IP enrichment observed",
                "severity": FindingSeverity::Info,
                "summary": summary,
                "evidence": [{
                    "evidenceType": "ip-enrichment",
                    "description": "Structured IP enrichment and address classification evidence.",
                    "data": {
                        "findingType": "asset.ip_enrichment",
                        "target": {"type": "ip", "value": ip},
                        "confidence": confidence,
                        "x-sentinelflow-ip.ip": ip,
                        "x-sentinelflow-ip.ip_version": ip_version,
                        "x-sentinelflow-ip.classification": classification,
                        "x-sentinelflow-ip.is_public": is_public,
                        "x-sentinelflow-ip.asn": raw_result.get("asn").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-ip.organization": raw_result.get("organization").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-ip.isp": raw_result.get("isp").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-ip.geo": raw_result.get("geo").cloned().unwrap_or_else(|| serde_json::json!({})),
                        "x-sentinelflow-ip.cloud": raw_result.get("cloud").cloned().unwrap_or_else(|| serde_json::json!({})),
                        "x-sentinelflow-ip.cdn_waf": raw_result.get("cdn_waf").cloned().unwrap_or_else(|| serde_json::json!({})),
                        "x-sentinelflow-ip.observed_at": raw_result.get("observed_at").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-ip.sources": raw_result.get("sources").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-ip.source_count": raw_result.get("source_count").cloned().unwrap_or_else(|| serde_json::json!(0)),
                        "x-sentinelflow-ip.source_details": raw_result.get("source_details").cloned().unwrap_or_else(|| serde_json::json!([])),
                    }
                }]
            }));
        }
        Ok(serde_json::json!({
            "values": input.raw.value,
            "findings": findings,
            "errors": parser_errors(input.raw.value)
        }))
    }
}

struct DnsResolvePlusParser;

impl Parser for DnsResolvePlusParser {
    fn parse(&self, input: &ParserInput<'_>) -> Result<Value, ErrorDetails> {
        let raw_results = input
            .raw
            .value
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| parser_field_error("$.raw.results", "results must be an array"))?;
        let mut findings = Vec::with_capacity(raw_results.len());
        for (index, raw_result) in raw_results.iter().enumerate() {
            if raw_result.get("type").and_then(Value::as_str) != Some("dns_result") {
                return Err(parser_field_error(
                    format!("$.raw.results[{index}].type"),
                    "result type must be dns_result",
                ));
            }
            if raw_result
                .get("resolved")
                .and_then(Value::as_bool)
                .is_some_and(|resolved| !resolved)
            {
                continue;
            }
            let domain = required_result_string(raw_result, "domain", index)?;
            let record_type = required_result_string(raw_result, "record_type", index)?;
            if matches!(record_type, "A" | "AAAA")
                && raw_result
                    .get("valid_for_port_probe")
                    .and_then(Value::as_bool)
                    .is_some_and(|valid| !valid)
            {
                continue;
            }
            let value = raw_result.get("value").cloned().unwrap_or(Value::Null);
            let confidence = raw_result
                .get("confidence")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let summary = raw_result
                .get("evidence")
                .and_then(|evidence| evidence.get("summary"))
                .and_then(Value::as_str)
                .map_or_else(
                    || format!("DNS {record_type} record for {domain} observed."),
                    ToOwned::to_owned,
                );
            findings.push(serde_json::json!({
                "title": "DNS resolution observed",
                "severity": FindingSeverity::Info,
                "summary": summary,
                "evidence": [{
                    "evidenceType": "dns-resolution",
                    "description": "Structured DNS resolution evidence.",
                    "data": {
                        "findingType": "asset.dns_resolve",
                        "target": {"type": "domain", "value": domain},
                        "confidence": confidence,
                        "x-sentinelflow-dns.domain": domain,
                        "x-sentinelflow-dns.record_type": record_type,
                        "x-sentinelflow-dns.value": value,
                        "x-sentinelflow-dns.sources": raw_result.get("sources").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-dns.source_details": raw_result.get("source_details").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-dns.source_count": raw_result.get("source_count").cloned().unwrap_or_else(|| serde_json::json!(0)),
                        "x-sentinelflow-dns.source_agreement": raw_result.get("source_agreement").cloned().unwrap_or_else(|| serde_json::json!("unknown")),
                        "x-sentinelflow-dns.conflict": raw_result.get("conflict").cloned().unwrap_or(Value::Bool(false)),
                        "x-sentinelflow-dns.conflict_reason": raw_result.get("conflict_reason").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-dns.observed_at": raw_result.get("observed_at").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-dns.stale": raw_result.get("stale").cloned().unwrap_or(Value::Bool(false)),
                        "x-sentinelflow-dns.resolved": raw_result.get("resolved").cloned().unwrap_or(Value::Bool(true)),
                        "x-sentinelflow-dns.status": raw_result.get("status").cloned().unwrap_or_else(|| Value::String("resolved".to_owned())),
                        "x-sentinelflow-dns.address_class": raw_result.get("address_class").cloned().unwrap_or_else(|| Value::String("not_applicable".to_owned())),
                        "x-sentinelflow-dns.public_routable": raw_result.get("public_routable").cloned().unwrap_or(Value::Bool(false)),
                        "x-sentinelflow-dns.valid_for_port_probe": raw_result.get("valid_for_port_probe").cloned().unwrap_or(Value::Bool(false)),
                        "x-sentinelflow-dns.confidence_strategy": raw_result.get("confidence_strategy").cloned().unwrap_or(Value::Null),
                    }
                }]
            }));
        }
        Ok(serde_json::json!({
            "values": input.raw.value,
            "findings": findings,
            "errors": parser_errors(input.raw.value)
        }))
    }
}

struct ServiceDetectPlusParser;

struct PortProbePlusParser;

struct HttpProbePlusParser;

struct WebFingerprintPlusParser;

struct TlsCertificateCheckPlusParser;

struct FofaImportPlusParser;

struct ShodanImportPlusParser;

struct CensysImportPlusParser;

struct NessusImportPlusParser;

struct OpenvasImportPlusParser;

struct NucleiAdapterPlusParser;

struct ZapBaselinePlusParser;

struct CloudAssetImportPlusParser;

struct CmdbSyncPlusParser;

struct MarkdownReportPlusParser;

impl Parser for PortProbePlusParser {
    #[allow(clippy::too_many_lines)]
    fn parse(&self, input: &ParserInput<'_>) -> Result<Value, ErrorDetails> {
        let raw_results = input
            .raw
            .value
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| parser_field_error("$.raw.results", "results must be an array"))?;
        let mut findings = Vec::with_capacity(raw_results.len());
        for (index, raw_result) in raw_results.iter().enumerate() {
            if raw_result.get("type").and_then(Value::as_str) != Some("port_result") {
                return Err(parser_field_error(
                    format!("$.raw.results[{index}].type"),
                    "result type must be port_result",
                ));
            }
            let address = required_result_string(raw_result, "address", index)?;
            let protocol = required_result_string(raw_result, "protocol", index)?;
            let state = required_result_string(raw_result, "state", index)?;
            let port = raw_result
                .get("port")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    parser_field_error(
                        format!("$.raw.results[{index}].port"),
                        "port must be an unsigned integer",
                    )
                })?;
            let confidence = raw_result
                .get("confidence")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let summary = raw_result
                .get("evidence")
                .and_then(|evidence| evidence.get("summary"))
                .and_then(Value::as_str)
                .map_or_else(
                    || format!("Port {port}/{protocol} on {address} observed as {state}."),
                    ToOwned::to_owned,
                );
            findings.push(serde_json::json!({
                "title": "Open port observed",
                "severity": FindingSeverity::Info,
                "summary": summary,
                "evidence": [{
                    "evidenceType": "port-probe",
                    "description": "Structured port exposure evidence.",
                    "data": {
                        "findingType": "asset.port_probe",
                        "target": {"type": "service", "value": format!("{address}:{port}")},
                        "confidence": confidence,
                        "x-sentinelflow-port.address": address,
                        "x-sentinelflow-port.port": port,
                        "x-sentinelflow-port.protocol": protocol,
                        "x-sentinelflow-port.state": state,
                        "x-sentinelflow-port.service": raw_result.get("service").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-port.hostnames": raw_result.get("hostnames").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-port.sources": raw_result.get("sources").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-port.source_details": raw_result.get("source_details").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-port.source_count": raw_result.get("source_count").cloned().unwrap_or_else(|| serde_json::json!(0)),
                        "x-sentinelflow-port.source_agreement": raw_result.get("source_agreement").cloned().unwrap_or_else(|| serde_json::json!("unknown")),
                        "x-sentinelflow-port.passive_only": raw_result.get("passive_only").cloned().unwrap_or(Value::Bool(false)),
                        "x-sentinelflow-port.active_verified": raw_result.get("active_verified").cloned().unwrap_or(Value::Bool(false)),
                        "x-sentinelflow-port.conflict": raw_result.get("conflict").cloned().unwrap_or(Value::Bool(false)),
                        "x-sentinelflow-port.conflict_reason": raw_result.get("conflict_reason").cloned().unwrap_or(Value::Null),
                    }
                }]
            }));
        }
        Ok(serde_json::json!({
            "values": input.raw.value,
            "findings": findings,
            "errors": parser_errors(input.raw.value)
        }))
    }
}

impl Parser for HttpProbePlusParser {
    #[allow(clippy::too_many_lines)]
    fn parse(&self, input: &ParserInput<'_>) -> Result<Value, ErrorDetails> {
        let raw_results = input
            .raw
            .value
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| parser_field_error("$.raw.results", "results must be an array"))?;
        let mut findings = Vec::with_capacity(raw_results.len());
        for (index, raw_result) in raw_results.iter().enumerate() {
            if raw_result.get("type").and_then(Value::as_str) != Some("http_result") {
                return Err(parser_field_error(
                    format!("$.raw.results[{index}].type"),
                    "result type must be http_result",
                ));
            }
            let url = required_result_string(raw_result, "url", index)?;
            let status_code = raw_result
                .get("status_code")
                .cloned()
                .unwrap_or(Value::Null);
            let confidence = raw_result
                .get("confidence")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let summary = raw_result
                .get("evidence")
                .and_then(|evidence| evidence.get("summary"))
                .and_then(Value::as_str)
                .map_or_else(
                    || format!("HTTP endpoint {url} observed."),
                    ToOwned::to_owned,
                );
            findings.push(serde_json::json!({
                "title": "HTTP endpoint observed",
                "severity": FindingSeverity::Info,
                "summary": summary,
                "evidence": [{
                    "evidenceType": "http-probe",
                    "description": "Structured HTTP endpoint evidence.",
                    "data": {
                        "findingType": "asset.http_probe",
                        "target": {"type": "url", "value": url},
                        "confidence": confidence,
                        "x-sentinelflow-http.url": url,
                        "x-sentinelflow-http.status_code": status_code,
                        "x-sentinelflow-http.title": raw_result.get("title").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-http.server": raw_result.get("server").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-http.content_type": raw_result.get("content_type").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-http.content_length": raw_result.get("content_length").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-http.redirect_chain": raw_result.get("redirect_chain").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-http.tls_enabled": raw_result.get("tls_enabled").cloned().unwrap_or(Value::Bool(false)),
                        "x-sentinelflow-http.sources": raw_result.get("sources").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-http.source_details": raw_result.get("source_details").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-http.source_count": raw_result.get("source_count").cloned().unwrap_or_else(|| serde_json::json!(0)),
                        "x-sentinelflow-http.source_agreement": raw_result.get("source_agreement").cloned().unwrap_or_else(|| serde_json::json!("unknown")),
                        "x-sentinelflow-http.passive_only": raw_result.get("passive_only").cloned().unwrap_or(Value::Bool(false)),
                        "x-sentinelflow-http.active_verified": raw_result.get("active_verified").cloned().unwrap_or(Value::Bool(false)),
                        "x-sentinelflow-http.conflict": raw_result.get("conflict").cloned().unwrap_or(Value::Bool(false)),
                        "x-sentinelflow-http.conflict_reason": raw_result.get("conflict_reason").cloned().unwrap_or(Value::Null),
                    }
                }]
            }));
        }
        Ok(serde_json::json!({
            "values": input.raw.value,
            "findings": findings,
            "errors": parser_errors(input.raw.value)
        }))
    }
}

impl Parser for WebFingerprintPlusParser {
    #[allow(clippy::too_many_lines)]
    fn parse(&self, input: &ParserInput<'_>) -> Result<Value, ErrorDetails> {
        let raw_results = input
            .raw
            .value
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| parser_field_error("$.raw.results", "results must be an array"))?;
        let mut findings = Vec::with_capacity(raw_results.len());
        for (index, raw_result) in raw_results.iter().enumerate() {
            if raw_result.get("type").and_then(Value::as_str) != Some("web_fingerprint_result") {
                return Err(parser_field_error(
                    format!("$.raw.results[{index}].type"),
                    "result type must be web_fingerprint_result",
                ));
            }
            let url = required_result_string(raw_result, "url", index)?;
            let technology = required_result_string(raw_result, "technology", index)?;
            let category = required_result_string(raw_result, "category", index)?;
            let confidence = raw_result
                .get("confidence")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let summary = raw_result
                .get("evidence")
                .and_then(|evidence| evidence.get("summary"))
                .and_then(Value::as_str)
                .map_or_else(
                    || format!("{technology} fingerprint observed on {url}."),
                    ToOwned::to_owned,
                );
            findings.push(serde_json::json!({
                "title": "Web technology fingerprint observed",
                "severity": FindingSeverity::Info,
                "summary": summary,
                "evidence": [{
                    "evidenceType": "web-fingerprint",
                    "description": "Structured passive Web fingerprint evidence.",
                    "data": {
                        "findingType": "asset.web_fingerprint",
                        "target": {"type": "url", "value": url},
                        "confidence": confidence,
                        "x-sentinelflow-web-fingerprint.url": url,
                        "x-sentinelflow-web-fingerprint.technology": technology,
                        "x-sentinelflow-web-fingerprint.category": category,
                        "x-sentinelflow-web-fingerprint.version": raw_result.get("version").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-web-fingerprint.sources": raw_result.get("sources").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-web-fingerprint.source_count": raw_result.get("source_count").cloned().unwrap_or_else(|| serde_json::json!(0)),
                        "x-sentinelflow-web-fingerprint.source_details": raw_result.get("source_details").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-web-fingerprint.signals": raw_result.get("signals").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-web-fingerprint.signal_count": raw_result.get("signal_count").cloned().unwrap_or_else(|| serde_json::json!(0)),
                    }
                }]
            }));
        }
        Ok(serde_json::json!({
            "values": input.raw.value,
            "findings": findings,
            "errors": parser_errors(input.raw.value)
        }))
    }
}

impl Parser for TlsCertificateCheckPlusParser {
    #[allow(clippy::too_many_lines)]
    fn parse(&self, input: &ParserInput<'_>) -> Result<Value, ErrorDetails> {
        let raw_results = input
            .raw
            .value
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| parser_field_error("$.raw.results", "results must be an array"))?;
        let mut findings = Vec::with_capacity(raw_results.len());
        for (index, raw_result) in raw_results.iter().enumerate() {
            if raw_result.get("type").and_then(Value::as_str) != Some("tls_certificate_result") {
                return Err(parser_field_error(
                    format!("$.raw.results[{index}].type"),
                    "result type must be tls_certificate_result",
                ));
            }
            let host = required_result_string(raw_result, "host", index)?;
            let subject = required_result_string(raw_result, "subject", index)?;
            let issuer = required_result_string(raw_result, "issuer", index)?;
            let status = required_result_string(raw_result, "status", index)?;
            let port = raw_result
                .get("port")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    parser_field_error(
                        format!("$.raw.results[{index}].port"),
                        "port must be an unsigned integer",
                    )
                })?;
            let confidence = raw_result
                .get("confidence")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let summary = raw_result
                .get("evidence")
                .and_then(|evidence| evidence.get("summary"))
                .and_then(Value::as_str)
                .map_or_else(
                    || format!("TLS certificate for {host}:{port} is {status}."),
                    ToOwned::to_owned,
                );
            findings.push(serde_json::json!({
                "title": "TLS certificate observed",
                "severity": FindingSeverity::Info,
                "summary": summary,
                "evidence": [{
                    "evidenceType": "tls-certificate",
                    "description": "Structured TLS certificate evidence.",
                    "data": {
                        "findingType": "asset.tls_certificate",
                        "target": {"type": "service", "value": format!("{host}:{port}")},
                        "confidence": confidence,
                        "x-sentinelflow-tls-certificate.host": host,
                        "x-sentinelflow-tls-certificate.port": port,
                        "x-sentinelflow-tls-certificate.subject": subject,
                        "x-sentinelflow-tls-certificate.issuer": issuer,
                        "x-sentinelflow-tls-certificate.san": raw_result.get("san").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-tls-certificate.not_before": raw_result.get("not_before").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-tls-certificate.not_after": raw_result.get("not_after").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-tls-certificate.days_until_expiry": raw_result.get("days_until_expiry").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-tls-certificate.status": status,
                        "x-sentinelflow-tls-certificate.signature_algorithm": raw_result.get("signature_algorithm").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-tls-certificate.tls_version": raw_result.get("tls_version").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-tls-certificate.chain_summary": raw_result.get("chain_summary").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-tls-certificate.san_assets": raw_result.get("san_assets").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-tls-certificate.sources": raw_result.get("sources").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-tls-certificate.source_count": raw_result.get("source_count").cloned().unwrap_or_else(|| serde_json::json!(0)),
                        "x-sentinelflow-tls-certificate.source_details": raw_result.get("source_details").cloned().unwrap_or_else(|| serde_json::json!([])),
                    }
                }]
            }));
        }
        Ok(serde_json::json!({
            "values": input.raw.value,
            "findings": findings,
            "errors": parser_errors(input.raw.value)
        }))
    }
}

impl Parser for FofaImportPlusParser {
    #[allow(clippy::too_many_lines)]
    fn parse(&self, input: &ParserInput<'_>) -> Result<Value, ErrorDetails> {
        let raw_results = input
            .raw
            .value
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| parser_field_error("$.raw.results", "results must be an array"))?;
        let mut findings = Vec::with_capacity(raw_results.len());
        for (index, raw_result) in raw_results.iter().enumerate() {
            if raw_result.get("type").and_then(Value::as_str) != Some("exposure_intel_result") {
                return Err(parser_field_error(
                    format!("$.raw.results[{index}].type"),
                    "result type must be exposure_intel_result",
                ));
            }
            let host = required_result_string(raw_result, "host", index)?;
            let ip = required_result_string(raw_result, "ip", index)?;
            let protocol = required_result_string(raw_result, "protocol", index)?;
            let port = raw_result
                .get("port")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    parser_field_error(
                        format!("$.raw.results[{index}].port"),
                        "port must be an unsigned integer",
                    )
                })?;
            let confidence = raw_result
                .get("confidence")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let summary = raw_result
                .get("evidence")
                .and_then(|evidence| evidence.get("summary"))
                .and_then(Value::as_str)
                .map_or_else(
                    || format!("FOFA exposure intelligence observed {host}:{port}/{protocol}."),
                    ToOwned::to_owned,
                );
            findings.push(serde_json::json!({
                "title": "Exposure intelligence imported",
                "severity": FindingSeverity::Info,
                "summary": summary,
                "evidence": [{
                    "evidenceType": "exposure-intel",
                    "description": "Structured external exposure intelligence evidence.",
                    "data": {
                        "findingType": "asset.exposure_intel",
                        "target": {"type": "service", "value": format!("{host}:{port}")},
                        "confidence": confidence,
                        "x-sentinelflow-exposure-intel.provider": "fofa",
                        "x-sentinelflow-exposure-intel.host": host,
                        "x-sentinelflow-exposure-intel.ip": ip,
                        "x-sentinelflow-exposure-intel.port": port,
                        "x-sentinelflow-exposure-intel.protocol": protocol,
                        "x-sentinelflow-exposure-intel.service": raw_result.get("service").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-exposure-intel.title": raw_result.get("title").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-exposure-intel.headers": raw_result.get("headers").cloned().unwrap_or_else(|| serde_json::json!({})),
                        "x-sentinelflow-exposure-intel.certificate": raw_result.get("certificate").cloned().unwrap_or_else(|| serde_json::json!({})),
                        "x-sentinelflow-exposure-intel.observed_at": raw_result.get("observed_at").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-exposure-intel.sources": raw_result.get("sources").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-exposure-intel.source_count": raw_result.get("source_count").cloned().unwrap_or_else(|| serde_json::json!(0)),
                        "x-sentinelflow-exposure-intel.source_details": raw_result.get("source_details").cloned().unwrap_or_else(|| serde_json::json!([])),
                    }
                }]
            }));
        }
        Ok(serde_json::json!({
            "values": input.raw.value,
            "findings": findings,
            "errors": parser_errors(input.raw.value)
        }))
    }
}

impl Parser for ShodanImportPlusParser {
    #[allow(clippy::too_many_lines)]
    fn parse(&self, input: &ParserInput<'_>) -> Result<Value, ErrorDetails> {
        let raw_results = input
            .raw
            .value
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| parser_field_error("$.raw.results", "results must be an array"))?;
        let mut findings = Vec::with_capacity(raw_results.len());
        for (index, raw_result) in raw_results.iter().enumerate() {
            if raw_result.get("type").and_then(Value::as_str) != Some("exposure_intel_result") {
                return Err(parser_field_error(
                    format!("$.raw.results[{index}].type"),
                    "result type must be exposure_intel_result",
                ));
            }
            let host = required_result_string(raw_result, "host", index)?;
            let ip = required_result_string(raw_result, "ip", index)?;
            let protocol = required_result_string(raw_result, "protocol", index)?;
            let port = raw_result
                .get("port")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    parser_field_error(
                        format!("$.raw.results[{index}].port"),
                        "port must be an unsigned integer",
                    )
                })?;
            let confidence = raw_result
                .get("confidence")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let summary = raw_result
                .get("evidence")
                .and_then(|evidence| evidence.get("summary"))
                .and_then(Value::as_str)
                .map_or_else(
                    || format!("Shodan host intelligence observed {host}:{port}/{protocol}."),
                    ToOwned::to_owned,
                );
            findings.push(serde_json::json!({
                "title": "Exposure intelligence imported",
                "severity": FindingSeverity::Info,
                "summary": summary,
                "evidence": [{
                    "evidenceType": "exposure-intel",
                    "description": "Structured external host intelligence evidence.",
                    "data": {
                        "findingType": "asset.exposure_intel",
                        "target": {"type": "service", "value": format!("{host}:{port}")},
                        "confidence": confidence,
                        "x-sentinelflow-exposure-intel.provider": "shodan",
                        "x-sentinelflow-exposure-intel.host": host,
                        "x-sentinelflow-exposure-intel.ip": ip,
                        "x-sentinelflow-exposure-intel.port": port,
                        "x-sentinelflow-exposure-intel.protocol": protocol,
                        "x-sentinelflow-exposure-intel.service": raw_result.get("service").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-exposure-intel.title": raw_result.get("title").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-exposure-intel.banner": raw_result.get("banner").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-exposure-intel.certificate": raw_result.get("certificate").cloned().unwrap_or_else(|| serde_json::json!({})),
                        "x-sentinelflow-exposure-intel.first_seen": raw_result.get("first_seen").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-exposure-intel.last_seen": raw_result.get("last_seen").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-exposure-intel.observed_at": raw_result.get("observed_at").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-exposure-intel.sources": raw_result.get("sources").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-exposure-intel.source_count": raw_result.get("source_count").cloned().unwrap_or_else(|| serde_json::json!(0)),
                        "x-sentinelflow-exposure-intel.source_details": raw_result.get("source_details").cloned().unwrap_or_else(|| serde_json::json!([])),
                    }
                }]
            }));
        }
        Ok(serde_json::json!({
            "values": input.raw.value,
            "findings": findings,
            "errors": parser_errors(input.raw.value)
        }))
    }
}

impl Parser for CensysImportPlusParser {
    #[allow(clippy::too_many_lines)]
    fn parse(&self, input: &ParserInput<'_>) -> Result<Value, ErrorDetails> {
        let raw_results = input
            .raw
            .value
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| parser_field_error("$.raw.results", "results must be an array"))?;
        let mut findings = Vec::with_capacity(raw_results.len());
        for (index, raw_result) in raw_results.iter().enumerate() {
            if raw_result.get("type").and_then(Value::as_str) != Some("exposure_intel_result") {
                return Err(parser_field_error(
                    format!("$.raw.results[{index}].type"),
                    "result type must be exposure_intel_result",
                ));
            }
            let host = required_result_string(raw_result, "host", index)?;
            let ip = required_result_string(raw_result, "ip", index)?;
            let protocol = required_result_string(raw_result, "protocol", index)?;
            let port = raw_result
                .get("port")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    parser_field_error(
                        format!("$.raw.results[{index}].port"),
                        "port must be an unsigned integer",
                    )
                })?;
            let confidence = raw_result
                .get("confidence")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let summary = raw_result
                .get("evidence")
                .and_then(|evidence| evidence.get("summary"))
                .and_then(Value::as_str)
                .map_or_else(
                    || format!("Censys exposure intelligence observed {host}:{port}/{protocol}."),
                    ToOwned::to_owned,
                );
            findings.push(serde_json::json!({
                "title": "Exposure intelligence imported",
                "severity": FindingSeverity::Info,
                "summary": summary,
                "evidence": [{
                    "evidenceType": "exposure-intel",
                    "description": "Structured Censys host, service, and certificate intelligence evidence.",
                    "data": {
                        "findingType": "asset.exposure_intel",
                        "target": {"type": "service", "value": format!("{host}:{port}")},
                        "confidence": confidence,
                        "x-sentinelflow-exposure-intel.provider": "censys",
                        "x-sentinelflow-exposure-intel.host": host,
                        "x-sentinelflow-exposure-intel.ip": ip,
                        "x-sentinelflow-exposure-intel.port": port,
                        "x-sentinelflow-exposure-intel.protocol": protocol,
                        "x-sentinelflow-exposure-intel.service": raw_result.get("service").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-exposure-intel.names": raw_result.get("names").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-exposure-intel.certificate": raw_result.get("certificate").cloned().unwrap_or_else(|| serde_json::json!({})),
                        "x-sentinelflow-exposure-intel.service_fingerprint": raw_result.get("service_fingerprint").cloned().unwrap_or_else(|| serde_json::json!({})),
                        "x-sentinelflow-exposure-intel.first_observed_at": raw_result.get("first_observed_at").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-exposure-intel.last_observed_at": raw_result.get("last_observed_at").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-exposure-intel.observed_at": raw_result.get("observed_at").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-exposure-intel.sources": raw_result.get("sources").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-exposure-intel.source_count": raw_result.get("source_count").cloned().unwrap_or_else(|| serde_json::json!(0)),
                        "x-sentinelflow-exposure-intel.source_details": raw_result.get("source_details").cloned().unwrap_or_else(|| serde_json::json!([])),
                    }
                }]
            }));
        }
        Ok(serde_json::json!({
            "values": input.raw.value,
            "findings": findings,
            "errors": parser_errors(input.raw.value)
        }))
    }
}

impl Parser for NessusImportPlusParser {
    #[allow(clippy::too_many_lines)]
    fn parse(&self, input: &ParserInput<'_>) -> Result<Value, ErrorDetails> {
        let raw_results = input
            .raw
            .value
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| parser_field_error("$.raw.results", "results must be an array"))?;
        let mut findings = Vec::with_capacity(raw_results.len());
        for (index, raw_result) in raw_results.iter().enumerate() {
            if raw_result.get("type").and_then(Value::as_str) != Some("vulnerability_import_result")
            {
                return Err(parser_field_error(
                    format!("$.raw.results[{index}].type"),
                    "result type must be vulnerability_import_result",
                ));
            }
            let host = required_result_string(raw_result, "host", index)?;
            let plugin_id = required_result_string(raw_result, "plugin_id", index)?;
            let plugin_name = required_result_string(raw_result, "plugin_name", index)?;
            let severity_label = required_result_string(raw_result, "severity_label", index)?;
            let severity = finding_severity_from_label(severity_label);
            let confidence = raw_result
                .get("confidence")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let summary = raw_result
                .get("evidence")
                .and_then(|evidence| evidence.get("summary"))
                .and_then(Value::as_str)
                .map_or_else(
                    || format!("Nessus imported {severity_label} finding {plugin_name} on {host}."),
                    ToOwned::to_owned,
                );
            let port = raw_result.get("port").cloned().unwrap_or(Value::Null);
            findings.push(serde_json::json!({
                "title": plugin_name,
                "severity": severity,
                "summary": summary,
                "evidence": [{
                    "evidenceType": "nessus-vulnerability-import",
                    "description": "Structured Nessus vulnerability import evidence.",
                    "data": {
                        "findingType": "risk.vuln_import",
                        "target": {"type": "host", "value": host},
                        "confidence": confidence,
                        "x-sentinelflow-vuln-import.source": "nessus",
                        "x-sentinelflow-vuln-import.host": host,
                        "x-sentinelflow-vuln-import.host_ip": raw_result.get("host_ip").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-vuln-import.port": port,
                        "x-sentinelflow-vuln-import.protocol": raw_result.get("protocol").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-vuln-import.service": raw_result.get("service").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-vuln-import.plugin_id": plugin_id,
                        "x-sentinelflow-vuln-import.plugin_name": plugin_name,
                        "x-sentinelflow-vuln-import.plugin_family": raw_result.get("plugin_family").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-vuln-import.severity": raw_result.get("severity").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-vuln-import.severity_label": severity_label,
                        "x-sentinelflow-vuln-import.cve": raw_result.get("cve").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-vuln-import.cwe": raw_result.get("cwe").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-vuln-import.cvss_base_score": raw_result.get("cvss_base_score").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-vuln-import.synopsis": raw_result.get("synopsis").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-vuln-import.description": raw_result.get("description").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-vuln-import.solution": raw_result.get("solution").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-vuln-import.plugin_output": raw_result.get("plugin_output").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-vuln-import.sources": raw_result.get("sources").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-vuln-import.source_count": raw_result.get("source_count").cloned().unwrap_or_else(|| serde_json::json!(0)),
                        "x-sentinelflow-vuln-import.source_details": raw_result.get("source_details").cloned().unwrap_or_else(|| serde_json::json!([])),
                    }
                }]
            }));
        }
        Ok(serde_json::json!({
            "values": input.raw.value,
            "findings": findings,
            "errors": parser_errors(input.raw.value)
        }))
    }
}

impl Parser for OpenvasImportPlusParser {
    #[allow(clippy::too_many_lines)]
    fn parse(&self, input: &ParserInput<'_>) -> Result<Value, ErrorDetails> {
        let raw_results = input
            .raw
            .value
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| parser_field_error("$.raw.results", "results must be an array"))?;
        let mut findings = Vec::with_capacity(raw_results.len());
        for (index, raw_result) in raw_results.iter().enumerate() {
            if raw_result.get("type").and_then(Value::as_str) != Some("vulnerability_import_result")
            {
                return Err(parser_field_error(
                    format!("$.raw.results[{index}].type"),
                    "result type must be vulnerability_import_result",
                ));
            }
            let host = required_result_string(raw_result, "host", index)?;
            let nvt_oid = required_result_string(raw_result, "nvt_oid", index)?;
            let plugin_name = required_result_string(raw_result, "plugin_name", index)?;
            let severity_label = required_result_string(raw_result, "severity_label", index)?;
            let severity = finding_severity_from_label(severity_label);
            let confidence = raw_result
                .get("confidence")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let summary = raw_result
                .get("evidence")
                .and_then(|evidence| evidence.get("summary"))
                .and_then(Value::as_str)
                .map_or_else(
                    || {
                        format!(
                            "OpenVAS imported {severity_label} finding {plugin_name} on {host}."
                        )
                    },
                    ToOwned::to_owned,
                );
            let port = raw_result.get("port").cloned().unwrap_or(Value::Null);
            findings.push(serde_json::json!({
                "title": plugin_name,
                "severity": severity,
                "summary": summary,
                "evidence": [{
                    "evidenceType": "openvas-vulnerability-import",
                    "description": "Structured OpenVAS vulnerability import evidence.",
                    "data": {
                        "findingType": "risk.vuln_import",
                        "target": {"type": "host", "value": host},
                        "confidence": confidence,
                        "x-sentinelflow-vuln-import.source": "openvas",
                        "x-sentinelflow-vuln-import.host": host,
                        "x-sentinelflow-vuln-import.port": port,
                        "x-sentinelflow-vuln-import.protocol": raw_result.get("protocol").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-vuln-import.nvt_oid": nvt_oid,
                        "x-sentinelflow-vuln-import.plugin_name": plugin_name,
                        "x-sentinelflow-vuln-import.family": raw_result.get("family").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-vuln-import.threat": raw_result.get("threat").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-vuln-import.qod": raw_result.get("qod").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-vuln-import.severity": raw_result.get("severity").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-vuln-import.severity_label": severity_label,
                        "x-sentinelflow-vuln-import.cve": raw_result.get("cve").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-vuln-import.cvss_base_score": raw_result.get("cvss_base_score").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-vuln-import.description": raw_result.get("description").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-vuln-import.solution": raw_result.get("solution").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-vuln-import.solution_type": raw_result.get("solution_type").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-vuln-import.result_id": raw_result.get("result_id").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-vuln-import.evidence_text": raw_result.get("evidence_text").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-vuln-import.sources": raw_result.get("sources").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-vuln-import.source_count": raw_result.get("source_count").cloned().unwrap_or_else(|| serde_json::json!(0)),
                        "x-sentinelflow-vuln-import.source_details": raw_result.get("source_details").cloned().unwrap_or_else(|| serde_json::json!([])),
                    }
                }]
            }));
        }
        Ok(serde_json::json!({
            "values": input.raw.value,
            "findings": findings,
            "errors": parser_errors(input.raw.value)
        }))
    }
}

impl Parser for NucleiAdapterPlusParser {
    #[allow(clippy::too_many_lines)]
    fn parse(&self, input: &ParserInput<'_>) -> Result<Value, ErrorDetails> {
        let raw_results = input
            .raw
            .value
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| parser_field_error("$.raw.results", "results must be an array"))?;
        let mut findings = Vec::with_capacity(raw_results.len());
        for (index, raw_result) in raw_results.iter().enumerate() {
            if raw_result.get("type").and_then(Value::as_str) != Some("nuclei_result") {
                return Err(parser_field_error(
                    format!("$.raw.results[{index}].type"),
                    "result type must be nuclei_result",
                ));
            }
            let matched_at = required_result_string(raw_result, "matched_at", index)?;
            let template_id = required_result_string(raw_result, "template_id", index)?;
            let template_name = required_result_string(raw_result, "template_name", index)?;
            let template_severity = required_result_string(raw_result, "template_severity", index)?;
            let severity = finding_severity_from_label(template_severity);
            let confidence = raw_result
                .get("confidence")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let summary = raw_result
                .get("evidence")
                .and_then(|evidence| evidence.get("summary"))
                .and_then(Value::as_str)
                .map_or_else(
                    || {
                        format!(
                            "Nuclei imported {template_severity} template result {template_id} on {matched_at}."
                        )
                    },
                    ToOwned::to_owned,
                );
            findings.push(serde_json::json!({
                "title": template_name,
                "severity": severity,
                "summary": summary,
                "evidence": [{
                    "evidenceType": "nuclei-template-result",
                    "description": "Structured Nuclei template result evidence.",
                    "data": {
                        "findingType": "risk.web_scan",
                        "target": {"type": "url", "value": matched_at},
                        "confidence": confidence,
                        "x-sentinelflow-nuclei.matched_at": matched_at,
                        "x-sentinelflow-nuclei.host": raw_result.get("host").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-nuclei.ip": raw_result.get("ip").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-nuclei.scheme": raw_result.get("scheme").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-nuclei.port": raw_result.get("port").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-nuclei.template_id": template_id,
                        "x-sentinelflow-nuclei.template_path": raw_result.get("template_path").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-nuclei.template_name": template_name,
                        "x-sentinelflow-nuclei.template_severity": template_severity,
                        "x-sentinelflow-nuclei.tags": raw_result.get("tags").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-nuclei.description": raw_result.get("description").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-nuclei.matcher_name": raw_result.get("matcher_name").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-nuclei.extractor_name": raw_result.get("extractor_name").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-nuclei.type_name": raw_result.get("type_name").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-nuclei.cve": raw_result.get("cve").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-nuclei.cwe": raw_result.get("cwe").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-nuclei.cvss_score": raw_result.get("cvss_score").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-nuclei.references": raw_result.get("references").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-nuclei.extracted_results": raw_result.get("extracted_results").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-nuclei.request": raw_result.get("request").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-nuclei.curl_command": raw_result.get("curl_command").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-nuclei.observed_at": raw_result.get("observed_at").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-nuclei.sources": raw_result.get("sources").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-nuclei.source_count": raw_result.get("source_count").cloned().unwrap_or_else(|| serde_json::json!(0)),
                        "x-sentinelflow-nuclei.source_details": raw_result.get("source_details").cloned().unwrap_or_else(|| serde_json::json!([])),
                    }
                }]
            }));
        }
        Ok(serde_json::json!({
            "values": input.raw.value,
            "findings": findings,
            "errors": parser_errors(input.raw.value)
        }))
    }
}

impl Parser for ZapBaselinePlusParser {
    #[allow(clippy::too_many_lines)]
    fn parse(&self, input: &ParserInput<'_>) -> Result<Value, ErrorDetails> {
        let raw_results = input
            .raw
            .value
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| parser_field_error("$.raw.results", "results must be an array"))?;
        let mut findings = Vec::with_capacity(raw_results.len());
        for (index, raw_result) in raw_results.iter().enumerate() {
            if raw_result.get("type").and_then(Value::as_str) != Some("zap_alert_result") {
                return Err(parser_field_error(
                    format!("$.raw.results[{index}].type"),
                    "result type must be zap_alert_result",
                ));
            }
            let url = required_result_string(raw_result, "url", index)?;
            let alert_id = required_result_string(raw_result, "alert_id", index)?;
            let alert_name = required_result_string(raw_result, "alert_name", index)?;
            let risk = required_result_string(raw_result, "risk", index)?;
            let confidence_label = required_result_string(raw_result, "confidence_label", index)?;
            let severity = finding_severity_from_label(risk);
            let confidence = raw_result
                .get("confidence")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let summary = raw_result
                .get("evidence")
                .and_then(|evidence| evidence.get("summary"))
                .and_then(Value::as_str)
                .map_or_else(
                    || format!("ZAP imported {risk} passive alert {alert_id} on {url}."),
                    ToOwned::to_owned,
                );
            findings.push(serde_json::json!({
                "title": alert_name,
                "severity": severity,
                "summary": summary,
                "evidence": [{
                    "evidenceType": "zap-baseline-alert",
                    "description": "Structured OWASP ZAP passive baseline alert evidence.",
                    "data": {
                        "findingType": "risk.web_scan",
                        "target": {"type": "url", "value": url},
                        "confidence": confidence,
                        "x-sentinelflow-zap.url": url,
                        "x-sentinelflow-zap.site": raw_result.get("site").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-zap.host": raw_result.get("host").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-zap.port": raw_result.get("port").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-zap.ssl": raw_result.get("ssl").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-zap.alert_id": alert_id,
                        "x-sentinelflow-zap.alert_ref": raw_result.get("alert_ref").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-zap.alert_name": alert_name,
                        "x-sentinelflow-zap.risk": risk,
                        "x-sentinelflow-zap.risk_description": raw_result.get("risk_description").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-zap.confidence_label": confidence_label,
                        "x-sentinelflow-zap.method": raw_result.get("method").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-zap.parameter": raw_result.get("parameter").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-zap.attack": raw_result.get("attack").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-zap.evidence_text": raw_result.get("evidence_text").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-zap.description": raw_result.get("description").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-zap.other_info": raw_result.get("other_info").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-zap.solution": raw_result.get("solution").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-zap.reference": raw_result.get("reference").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-zap.cwe_id": raw_result.get("cwe_id").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-zap.wasc_id": raw_result.get("wasc_id").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-zap.source_id": raw_result.get("source_id").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-zap.sources": raw_result.get("sources").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-zap.source_count": raw_result.get("source_count").cloned().unwrap_or_else(|| serde_json::json!(0)),
                        "x-sentinelflow-zap.source_details": raw_result.get("source_details").cloned().unwrap_or_else(|| serde_json::json!([])),
                    }
                }]
            }));
        }
        Ok(serde_json::json!({
            "values": input.raw.value,
            "findings": findings,
            "errors": parser_errors(input.raw.value)
        }))
    }
}

impl Parser for CloudAssetImportPlusParser {
    #[allow(clippy::too_many_lines)]
    fn parse(&self, input: &ParserInput<'_>) -> Result<Value, ErrorDetails> {
        let raw_results = input
            .raw
            .value
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| parser_field_error("$.raw.results", "results must be an array"))?;
        let mut findings = Vec::with_capacity(raw_results.len());
        for (index, raw_result) in raw_results.iter().enumerate() {
            if raw_result.get("type").and_then(Value::as_str) != Some("cloud_asset_result") {
                return Err(parser_field_error(
                    format!("$.raw.results[{index}].type"),
                    "result type must be cloud_asset_result",
                ));
            }
            let provider = required_result_string(raw_result, "provider", index)?;
            let resource_type = required_result_string(raw_result, "resource_type", index)?;
            let resource_id = required_result_string(raw_result, "resource_id", index)?;
            let name = required_result_string(raw_result, "name", index)?;
            let scope_id = required_result_string(raw_result, "scope_id", index)?;
            let region = required_result_string(raw_result, "region", index)?;
            let risk = required_result_string(raw_result, "risk", index)?;
            let severity = finding_severity_from_label(risk);
            let confidence = raw_result
                .get("confidence")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let target_value = raw_result
                .get("public_ips")
                .and_then(Value::as_array)
                .and_then(|values| values.first())
                .and_then(Value::as_str)
                .or_else(|| {
                    raw_result
                        .get("dns_names")
                        .and_then(Value::as_array)
                        .and_then(|values| values.first())
                        .and_then(Value::as_str)
                })
                .unwrap_or(resource_id);
            let summary = raw_result
                .get("evidence")
                .and_then(|evidence| evidence.get("summary"))
                .and_then(Value::as_str)
                .map_or_else(
                    || {
                        format!(
                            "{provider} {resource_type} asset {name} imported from offline inventory."
                        )
                    },
                    ToOwned::to_owned,
                );
            findings.push(serde_json::json!({
                "title": format!("{provider} {resource_type}: {name}"),
                "severity": severity,
                "summary": summary,
                "evidence": [{
                    "evidenceType": "cloud-asset-inventory",
                    "description": "Structured offline multi-cloud inventory evidence.",
                    "data": {
                        "findingType": "asset.cloud",
                        "target": {"type": "cloud_resource", "value": target_value},
                        "confidence": confidence,
                        "x-sentinelflow-cloud.provider": provider,
                        "x-sentinelflow-cloud.resource_type": resource_type,
                        "x-sentinelflow-cloud.resource_id": resource_id,
                        "x-sentinelflow-cloud.name": name,
                        "x-sentinelflow-cloud.scope_id": scope_id,
                        "x-sentinelflow-cloud.region": region,
                        "x-sentinelflow-cloud.status": raw_result.get("status").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-cloud.public_ips": raw_result.get("public_ips").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-cloud.private_ips": raw_result.get("private_ips").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-cloud.dns_names": raw_result.get("dns_names").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-cloud.internet_exposed": raw_result.get("internet_exposed").cloned().unwrap_or(Value::Bool(false)),
                        "x-sentinelflow-cloud.exposure_reasons": raw_result.get("exposure_reasons").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-cloud.risk": risk,
                        "x-sentinelflow-cloud.tags": raw_result.get("tags").cloned().unwrap_or_else(|| serde_json::json!({})),
                        "x-sentinelflow-cloud.security_rules": raw_result.get("security_rules").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-cloud.sources": raw_result.get("sources").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-cloud.source_count": raw_result.get("source_count").cloned().unwrap_or_else(|| serde_json::json!(0)),
                        "x-sentinelflow-cloud.source_details": raw_result.get("source_details").cloned().unwrap_or_else(|| serde_json::json!([])),
                    }
                }]
            }));
        }
        Ok(serde_json::json!({
            "values": input.raw.value,
            "findings": findings,
            "errors": parser_errors(input.raw.value)
        }))
    }
}

impl Parser for CmdbSyncPlusParser {
    #[allow(clippy::too_many_lines)]
    fn parse(&self, input: &ParserInput<'_>) -> Result<Value, ErrorDetails> {
        let raw_results = input
            .raw
            .value
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| parser_field_error("$.raw.results", "results must be an array"))?;
        let mut findings = Vec::with_capacity(raw_results.len());
        for (index, raw_result) in raw_results.iter().enumerate() {
            if raw_result.get("type").and_then(Value::as_str) != Some("cmdb_asset_result") {
                return Err(parser_field_error(
                    format!("$.raw.results[{index}].type"),
                    "result type must be cmdb_asset_result",
                ));
            }
            let external_id = required_result_string(raw_result, "external_id", index)?;
            let asset_type = required_result_string(raw_result, "asset_type", index)?;
            let name = required_result_string(raw_result, "name", index)?;
            let criticality = required_result_string(raw_result, "criticality", index)?;
            let status = required_result_string(raw_result, "status", index)?;
            let confidence = raw_result
                .get("confidence")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let target_value = raw_result
                .get("addresses")
                .and_then(Value::as_array)
                .and_then(|values| values.first())
                .and_then(Value::as_str)
                .unwrap_or(external_id);
            let summary = raw_result
                .get("evidence")
                .and_then(|evidence| evidence.get("summary"))
                .and_then(Value::as_str)
                .map_or_else(
                    || format!("CMDB asset {name} ({external_id}) imported."),
                    ToOwned::to_owned,
                );
            findings.push(serde_json::json!({
                "title": format!("CMDB {asset_type}: {name}"),
                "severity": FindingSeverity::Info,
                "summary": summary,
                "evidence": [{
                    "evidenceType": "cmdb-asset-record",
                    "description": "Structured CMDB ownership and business mapping evidence.",
                    "data": {
                        "findingType": "asset.cmdb",
                        "target": {"type": "cmdb_asset", "value": target_value},
                        "confidence": confidence,
                        "x-sentinelflow-cmdb.external_id": external_id,
                        "x-sentinelflow-cmdb.asset_type": asset_type,
                        "x-sentinelflow-cmdb.name": name,
                        "x-sentinelflow-cmdb.addresses": raw_result.get("addresses").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-cmdb.department": raw_result.get("department").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-cmdb.business_system": raw_result.get("business_system").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-cmdb.owner": raw_result.get("owner").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-cmdb.criticality": criticality,
                        "x-sentinelflow-cmdb.status": status,
                        "x-sentinelflow-cmdb.updated_at": raw_result.get("updated_at").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-cmdb.sources": raw_result.get("sources").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-cmdb.source_count": raw_result.get("source_count").cloned().unwrap_or_else(|| serde_json::json!(0)),
                        "x-sentinelflow-cmdb.source_details": raw_result.get("source_details").cloned().unwrap_or_else(|| serde_json::json!([])),
                    }
                }]
            }));
        }
        Ok(serde_json::json!({
            "values": input.raw.value,
            "findings": findings,
            "errors": parser_errors(input.raw.value)
        }))
    }
}

impl Parser for MarkdownReportPlusParser {
    fn parse(&self, input: &ParserInput<'_>) -> Result<Value, ErrorDetails> {
        let report = input
            .raw
            .value
            .get("report")
            .and_then(Value::as_object)
            .ok_or_else(|| parser_field_error("$.raw.report", "report must be an object"))?;
        if report.get("type").and_then(Value::as_str) != Some("markdown_report") {
            return Err(parser_field_error(
                "$.raw.report.type",
                "report type must be markdown_report",
            ));
        }
        let title = report
            .get("title")
            .and_then(Value::as_str)
            .ok_or_else(|| parser_field_error("$.raw.report.title", "title must be a string"))?;
        let markdown = report
            .get("markdown")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                parser_field_error("$.raw.report.markdown", "markdown must be a string")
            })?;
        let bytes = report.get("bytes").and_then(Value::as_u64).ok_or_else(|| {
            parser_field_error("$.raw.report.bytes", "bytes must be an unsigned integer")
        })?;
        let target = input
            .raw
            .value
            .get("target")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({"type": "report", "value": "unknown"}));
        let summary = input
            .raw
            .value
            .get("summary")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        let redaction_count = report
            .get("redaction_count")
            .cloned()
            .unwrap_or_else(|| serde_json::json!(0));
        let truncated = report
            .get("truncated")
            .cloned()
            .unwrap_or(Value::Bool(false));
        Ok(serde_json::json!({
            "values": input.raw.value,
            "findings": [{
                "title": "Markdown report generated",
                "severity": FindingSeverity::Info,
                "summary": format!("Markdown report '{title}' generated with {bytes} bytes."),
                "evidence": [{
                    "evidenceType": "markdown-report",
                    "description": "Bounded Markdown report artifact generated from normalized SentinelFlow data.",
                    "data": {
                        "findingType": "report.markdown",
                        "target": target,
                        "confidence": 1.0,
                        "x-sentinelflow-report.title": title,
                        "x-sentinelflow-report.bytes": bytes,
                        "x-sentinelflow-report.sections": report.get("sections").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-report.truncated": truncated,
                        "x-sentinelflow-report.redaction_count": redaction_count,
                        "x-sentinelflow-report.summary": summary,
                        "x-sentinelflow-report.markdown": markdown
                    }
                }]
            }],
            "errors": parser_errors(input.raw.value)
        }))
    }
}

impl Parser for ServiceDetectPlusParser {
    fn parse(&self, input: &ParserInput<'_>) -> Result<Value, ErrorDetails> {
        let raw_results = input
            .raw
            .value
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| parser_field_error("$.raw.results", "results must be an array"))?;
        let mut findings = Vec::with_capacity(raw_results.len());
        for (index, raw_result) in raw_results.iter().enumerate() {
            if raw_result.get("type").and_then(Value::as_str) != Some("service_result") {
                return Err(parser_field_error(
                    format!("$.raw.results[{index}].type"),
                    "result type must be service_result",
                ));
            }
            let address = required_result_string(raw_result, "address", index)?;
            let service = required_result_string(raw_result, "service", index)?;
            let port = raw_result
                .get("port")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    parser_field_error(
                        format!("$.raw.results[{index}].port"),
                        "port must be an unsigned integer",
                    )
                })?;
            let confidence = raw_result
                .get("confidence")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let summary = raw_result
                .get("evidence")
                .and_then(|evidence| evidence.get("summary"))
                .and_then(Value::as_str)
                .map_or_else(
                    || format!("Service on {address}:{port} identified as {service}."),
                    ToOwned::to_owned,
                );
            findings.push(serde_json::json!({
                "title": "Service observed",
                "severity": FindingSeverity::Info,
                "summary": summary,
                "evidence": [{
                    "evidenceType": "service-detection",
                    "description": "Structured service detection evidence.",
                    "data": {
                        "findingType": "asset.service_detect",
                        "target": {"type": "service", "value": format!("{address}:{port}")},
                        "confidence": confidence,
                        "x-sentinelflow-service.address": address,
                        "x-sentinelflow-service.port": port,
                        "x-sentinelflow-service.protocol": raw_result.get("protocol").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-service.service": service,
                        "x-sentinelflow-service.transport": raw_result.get("transport").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-service.product": raw_result.get("product").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-service.version": raw_result.get("version").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-service.hostnames": raw_result.get("hostnames").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-service.http": raw_result.get("http").cloned().unwrap_or_else(|| serde_json::json!({})),
                        "x-sentinelflow-service.tls": raw_result.get("tls").cloned().unwrap_or_else(|| serde_json::json!({})),
                        "x-sentinelflow-service.sources": raw_result.get("sources").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-service.source_details": raw_result.get("source_details").cloned().unwrap_or_else(|| serde_json::json!([])),
                        "x-sentinelflow-service.source_count": raw_result.get("source_count").cloned().unwrap_or_else(|| serde_json::json!(0)),
                        "x-sentinelflow-service.source_agreement": raw_result.get("source_agreement").cloned().unwrap_or_else(|| serde_json::json!("unknown")),
                        "x-sentinelflow-service.conflict": raw_result.get("conflict").cloned().unwrap_or(Value::Bool(false)),
                        "x-sentinelflow-service.conflict_reason": raw_result.get("conflict_reason").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-service.detection_depth": raw_result.get("detection_depth").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-service.risk_level": raw_result.get("risk_level").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-service.observed_at": raw_result.get("observed_at").cloned().unwrap_or(Value::Null),
                        "x-sentinelflow-service.stale": raw_result.get("stale").cloned().unwrap_or(Value::Bool(false)),
                        "x-sentinelflow-service.confidence_strategy": raw_result.get("confidence_strategy").cloned().unwrap_or(Value::Null),
                    }
                }]
            }));
        }
        Ok(serde_json::json!({
            "values": input.raw.value,
            "findings": findings,
            "errors": parser_errors(input.raw.value)
        }))
    }
}

fn required_result_string<'a>(
    value: &'a Value,
    field: &str,
    index: usize,
) -> Result<&'a str, ErrorDetails> {
    value.get(field).and_then(Value::as_str).ok_or_else(|| {
        parser_field_error(
            format!("$.raw.results[{index}].{field}"),
            "field must be a string",
        )
    })
}

fn string_array(value: &Value, field: &str, index: usize) -> Result<Vec<String>, ErrorDetails> {
    let array = value.get(field).and_then(Value::as_array).ok_or_else(|| {
        parser_field_error(
            format!("$.raw.findings[{index}].{field}"),
            "field must be an array",
        )
    })?;
    let mut items = Vec::with_capacity(array.len());
    for (item_index, item) in array.iter().enumerate() {
        let Some(text) = item.as_str() else {
            return Err(parser_field_error(
                format!("$.raw.findings[{index}].{field}[{item_index}]"),
                "array item must be a string",
            ));
        };
        items.push(text.to_owned());
    }
    Ok(items)
}

fn parser_errors(raw: &Value) -> Vec<Value> {
    raw.get("errors")
        .and_then(Value::as_array)
        .map(|errors| {
            errors
                .iter()
                .filter_map(|error| {
                    let object = error.as_object()?;
                    let code = object
                        .get("code")
                        .and_then(Value::as_str)
                        .unwrap_or("ParserInputError");
                    let message = object
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("parser input error");
                    let details = object
                        .get("details")
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!({}));
                    let mut normalized = serde_json::json!({
                        "code": code,
                        "message": message,
                        "details": details
                    });
                    if let Some(field) = object.get("field").and_then(Value::as_str) {
                        normalized["field"] = Value::String(field.to_owned());
                    }
                    Some(normalized)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn finding_severity_from_label(label: &str) -> FindingSeverity {
    match label {
        "critical" => FindingSeverity::Critical,
        "high" => FindingSeverity::High,
        "medium" => FindingSeverity::Medium,
        "low" => FindingSeverity::Low,
        _ => FindingSeverity::Info,
    }
}

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, ErrorDetails> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| parser_field_error(format!("$.raw.{field}"), "field must be a string"))
}

fn parser_field_error(field: impl Into<String>, message: impl Into<String>) -> ErrorDetails {
    ErrorDetails {
        code: "ParserInputInvalid".to_owned(),
        message: message.into(),
        field: Some(field.into()),
        details: BTreeMap::new(),
    }
}

fn normalization_error(
    code: &str,
    message: impl Into<String>,
    field: Option<String>,
) -> NormalizationError {
    NormalizationError {
        error: standard_error(
            ErrorDetails {
                code: code.to_owned(),
                message: message.into(),
                field,
                details: BTreeMap::new(),
            },
            &ExecutionIdentifiers {
                task_id: "unknown".to_owned(),
                run_id: "unknown".to_owned(),
                step_id: "unknown".to_owned(),
                tool_id: "unknown".to_owned(),
                correlation_id: "unknown".to_owned(),
            },
        ),
    }
}

fn standard_error(details: ErrorDetails, identifiers: &ExecutionIdentifiers) -> StandardError {
    StandardError {
        api_version: ProtocolVersion::V1Alpha1,
        kind: StandardErrorKind::Value,
        metadata: Metadata {
            name: format!("error-{}", identifiers.run_id),
            namespace: None,
            uid: None,
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
        },
        error: details,
        extensions: BTreeMap::new(),
    }
}

#[cfg(test)]
mod parser_tests {
    use super::*;

    struct InvalidParser;

    impl Parser for InvalidParser {
        fn parse(&self, _input: &ParserInput<'_>) -> Result<Value, ErrorDetails> {
            Ok(serde_json::json!({"findings": "not-an-array"}))
        }
    }

    #[test]
    fn invalid_parser_output_becomes_a_standard_error() {
        let identifiers = ExecutionIdentifiers::generate("example-echo");
        let raw = serde_json::json!({"message": "fixture"});
        let input = ParserInput {
            raw: RawOutputReference {
                run_id: &identifiers.run_id,
                value: &raw,
            },
            context: ParserContext {
                identifiers: &identifiers,
                actor_id: "test",
            },
        };
        let error = normalize(&InvalidParser, &input, "schema")
            .expect_err("invalid parser output must fail");
        assert_eq!(error.error.error.code, "ParserOutputInvalid");
    }

    #[test]
    fn finding_fingerprints_are_stable_and_tool_scoped() {
        let first_identifiers = ExecutionIdentifiers::generate("example-echo");
        let second_identifiers = ExecutionIdentifiers::generate("example-echo");
        let other_identifiers = ExecutionIdentifiers::generate("example-dns-resolve");
        let raw = serde_json::json!({"message": "fixture"});
        let normalized = |identifiers: &ExecutionIdentifiers| {
            normalize(
                &ExampleEchoParser,
                &ParserInput {
                    raw: RawOutputReference {
                        run_id: &identifiers.run_id,
                        value: &raw,
                    },
                    context: ParserContext {
                        identifiers,
                        actor_id: "test",
                    },
                },
                "schema",
            )
            .unwrap()
            .spec
            .findings
            .remove(0)
        };
        let first = normalized(&first_identifiers);
        let second = normalized(&second_identifiers);
        let other = normalized(&other_identifiers);
        assert_eq!(first.fingerprint, second.fingerprint);
        assert_eq!(first.cross_tool_fingerprint, other.cross_tool_fingerprint);
        assert_ne!(first.fingerprint, other.fingerprint);
    }

    #[test]
    fn subdomain_discovery_plus_parser_emits_asset_findings_and_errors() {
        let identifiers = ExecutionIdentifiers::generate("subdomain-discovery-plus");
        let raw = serde_json::json!({
            "source": "subdomain-discovery-plus",
            "domain": "example.com",
            "mode": "hybrid",
            "findings": [{
                "type": "subdomain_finding",
                "domain": "example.com",
                "subdomain": "www.example.com",
                "source": "merged",
                "sources": ["passive_fixture", "active_dictionary"],
                "resolved": true,
                "record_type": "A",
                "addresses": ["93.184.216.34"],
                "records": [{"record_type": "A", "value": "93.184.216.34"}],
                "confidence": 0.9,
                "evidence": {
                    "summary": "www.example.com discovered by fixture and DNS.",
                    "items": []
                },
                "raw": {"retained": true}
            }],
            "errors": [{
                "code": "PolicyDenied",
                "message": "active denied",
                "field": "$.policy.allow_active_verify",
                "details": {"activeEnabled": true}
            }]
        });
        let output = normalize(
            &SubdomainDiscoveryPlusParser,
            &ParserInput {
                raw: RawOutputReference {
                    run_id: &identifiers.run_id,
                    value: &raw,
                },
                context: ParserContext {
                    identifiers: &identifiers,
                    actor_id: "test",
                },
            },
            "schema",
        )
        .expect("subdomain parser output must normalize");

        assert_eq!(output.spec.findings.len(), 1);
        assert_eq!(output.spec.errors.len(), 1);
        let evidence = &output.spec.findings[0].evidence[0].data;
        assert_eq!(evidence["findingType"], "asset.subdomain");
        assert_eq!(
            evidence["x-sentinelflow-subdomain.subdomain"],
            "www.example.com"
        );
        assert_eq!(output.spec.errors[0].code, "PolicyDenied");
    }

    #[test]
    fn crtsh_subdomain_plus_parser_emits_subdomain_and_certificate_findings() {
        let identifiers = ExecutionIdentifiers::generate("crtsh-subdomain-plus");
        let raw = serde_json::json!({
            "source": "crtsh-subdomain-plus",
            "domain": "example.com",
            "mode": "fixture",
            "findings": [{
                "type": "subdomain_finding",
                "domain": "example.com",
                "subdomain": "www.example.com",
                "source": "passive_crtsh",
                "sources": ["passive_crtsh_fixture"],
                "confirmed": false,
                "resolved": false,
                "record_type": "unknown",
                "addresses": [],
                "first_seen": "2026-01-02T00:00:00Z",
                "last_seen": "2026-01-02T00:00:00Z",
                "wildcard_cleaned": true,
                "source_count": 1,
                "source_details": [{"source": "passive_crtsh_fixture", "entry_id": "111111"}],
                "confidence": 0.74,
                "evidence": {"summary": "crt.sh observed www.example.com.", "items": []},
                "raw": {"entries": ["111111"]}
            }],
            "certificates": [{
                "type": "certificate_asset",
                "domain": "example.com",
                "entry_id": "111111",
                "issuer_name": "CN=Example CA",
                "common_name": "www.example.com",
                "san_names": ["www.example.com", "api.example.com"],
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-12-31T23:59:59Z",
                "logged_at": "2026-01-02T00:00:00Z",
                "expired": false,
                "sources": ["passive_crtsh_fixture"],
                "source_count": 1,
                "source_details": [{"source": "passive_crtsh_fixture", "entry_id": "111111"}],
                "confidence": 0.84,
                "evidence": {"summary": "crt.sh certificate entry contains SAN assets.", "items": []}
            }],
            "source_status": [],
            "summary": {"finding_count": 1, "certificate_count": 1},
            "errors": [],
            "safety": {"active_target_connections": 0}
        });
        let output = normalize(
            &CrtshSubdomainPlusParser,
            &ParserInput {
                raw: RawOutputReference {
                    run_id: &identifiers.run_id,
                    value: &raw,
                },
                context: ParserContext {
                    identifiers: &identifiers,
                    actor_id: "test",
                },
            },
            "schema",
        )
        .expect("crtsh parser output must normalize");

        assert_eq!(output.spec.findings.len(), 2);
        let subdomain = &output.spec.findings[0].evidence[0].data;
        assert_eq!(subdomain["findingType"], "asset.subdomain");
        assert_eq!(
            subdomain["x-sentinelflow-subdomain.subdomain"],
            "www.example.com"
        );
        let certificate = &output.spec.findings[1].evidence[0].data;
        assert_eq!(certificate["findingType"], "asset.tls_certificate");
        assert_eq!(
            certificate["x-sentinelflow-tls-certificate.ct_entry_id"],
            "111111"
        );
    }

    #[test]
    fn ip_enrichment_plus_parser_emits_asset_findings() {
        let identifiers = ExecutionIdentifiers::generate("ip-enrichment-plus");
        let raw = serde_json::json!({
            "source": "ip-enrichment-plus",
            "target": {"type": "ip", "value": "93.184.216.34"},
            "mode": "fixture",
            "results": [{
                "type": "ip_enrichment_result",
                "ip": "93.184.216.34",
                "ip_version": 4,
                "classification": "public",
                "is_public": true,
                "asn": 15133,
                "organization": "Edgecast Inc.",
                "isp": "Edgecast Networks",
                "geo": {"country": "US"},
                "cloud": {"provider": null, "confidence": 0.0},
                "cdn_waf": {"cdn": true, "waf": false, "provider": "Edgecast", "signals": ["asn_org"], "confidence": 0.74},
                "observed_at": "2026-06-01T00:00:00Z",
                "sources": ["fixture", "local_classifier"],
                "source_count": 2,
                "source_details": [],
                "confidence": 0.85,
                "evidence": {"summary": "IP enrichment classified 93.184.216.34 as public.", "items": []}
            }],
            "source_status": [],
            "summary": {"result_count": 1},
            "errors": [],
            "safety": {"active_target_connections": 0}
        });
        let output = normalize(
            &IpEnrichmentPlusParser,
            &ParserInput {
                raw: RawOutputReference {
                    run_id: &identifiers.run_id,
                    value: &raw,
                },
                context: ParserContext {
                    identifiers: &identifiers,
                    actor_id: "test",
                },
            },
            "schema",
        )
        .expect("ip enrichment parser output must normalize");

        assert_eq!(output.spec.findings.len(), 1);
        let evidence = &output.spec.findings[0].evidence[0].data;
        assert_eq!(evidence["findingType"], "asset.ip_enrichment");
        assert_eq!(evidence["x-sentinelflow-ip.asn"], 15133);
        assert_eq!(
            evidence["x-sentinelflow-ip.cdn_waf"]["provider"],
            "Edgecast"
        );
    }

    #[test]
    fn dns_resolve_plus_parser_emits_asset_findings_and_source_details() {
        let identifiers = ExecutionIdentifiers::generate("dns-resolve-plus");
        let raw = serde_json::json!({
            "source": "dns-resolve-plus",
            "target": {"type": "domain", "value": "example.com"},
            "mode": "passive_intel",
            "record_types": ["A"],
            "observations": [],
            "results": [{
                "type": "dns_result",
                "domain": "www.example.com",
                "record_type": "A",
                "value": "93.184.216.34",
                "ttl": 300,
                "resolved": true,
                "sources": ["fixture"],
                "source_details": [{"source": "fixture", "source_type": "fixture", "observed_at": "2026-06-01T00:00:00Z", "source_updated_at": null, "confidence": 0.7, "stale": false, "evidence": {"summary": "fixture", "items": []}}],
                "source_count": 1,
                "source_agreement": "passive_only",
                "conflict": false,
                "conflict_reason": null,
                "observed_at": "2026-06-01T00:00:00Z",
                "stale": false,
                "confidence": 0.7,
                "confidence_strategy": "weighted_sources",
                "risk_level": "low",
                "evidence": {"summary": "A record observed.", "items": []}
            }],
            "source_status": [],
            "summary": {
                "domain_count": 1,
                "record_types": ["A"],
                "observation_count": 1,
                "result_count": 1,
                "passive_sources": ["fixture"],
                "active_enabled": false,
                "estimated_api_queries": 0,
                "estimated_dns_queries": 0,
                "requires_active_verify": false,
                "requires_high_risk": false,
                "requires_approval": false,
                "source_status_count": 0,
                "error_count": 0
            },
            "errors": [],
            "safety": {
                "target_type_domain_only": true,
                "authorization_scope_required": true,
                "active_policy_allowed": false,
                "high_risk_policy_allowed": false,
                "active_dns_queries": 0,
                "external_api_queries": 0,
                "shell_commands": 0,
                "exploit_attempts": 0
            }
        });
        let output = normalize(
            &DnsResolvePlusParser,
            &ParserInput {
                raw: RawOutputReference {
                    run_id: &identifiers.run_id,
                    value: &raw,
                },
                context: ParserContext {
                    identifiers: &identifiers,
                    actor_id: "test",
                },
            },
            "schema",
        )
        .expect("dns parser output must normalize");

        assert_eq!(output.spec.findings.len(), 1);
        let evidence = &output.spec.findings[0].evidence[0].data;
        assert_eq!(evidence["findingType"], "asset.dns_resolve");
        assert_eq!(
            evidence["x-sentinelflow-dns.source_agreement"],
            "passive_only"
        );
        assert!(evidence["x-sentinelflow-dns.source_details"].is_array());
    }

    #[test]
    fn service_detect_plus_parser_emits_asset_findings_and_risk_context() {
        let identifiers = ExecutionIdentifiers::generate("service-detect-plus");
        let raw = serde_json::json!({
            "source": "service-detect-plus",
            "target": {"type": "service", "value": "93.184.216.34:443"},
            "mode": "passive_intel",
            "detection_depth": "passive",
            "observations": [],
            "results": [{
                "type": "service_result",
                "address": "93.184.216.34",
                "port": 443,
                "protocol": "tcp",
                "service": "https",
                "transport": "tls",
                "product": "example-http-service",
                "version": null,
                "hostnames": ["www.example.com"],
                "banner_summary": null,
                "http": {"status": 200},
                "tls": {"san_count": 2},
                "sources": ["fixture"],
                "source_details": [{"source": "fixture", "source_type": "fixture", "detection_depth": "fixture", "observed_at": "2026-06-01T00:00:00Z", "source_updated_at": null, "confidence": 0.7, "stale": false, "evidence": {"summary": "fixture", "items": []}}],
                "source_count": 1,
                "source_agreement": "passive_only",
                "conflict": false,
                "conflict_reason": null,
                "detection_depth": "fixture",
                "risk_level": "low",
                "observed_at": "2026-06-01T00:00:00Z",
                "stale": false,
                "confidence": 0.7,
                "confidence_strategy": "weighted_sources",
                "evidence": {"summary": "Service observed.", "items": []}
            }],
            "source_status": [],
            "summary": {
                "service_count": 1,
                "observation_count": 1,
                "result_count": 1,
                "passive_sources": ["fixture"],
                "active_enabled": false,
                "detection_depth": "passive",
                "estimated_api_queries": 0,
                "estimated_service_probes": 0,
                "requires_active_verify": false,
                "requires_high_risk": false,
                "requires_approval": false,
                "source_status_count": 0,
                "error_count": 0
            },
            "errors": [],
            "safety": {
                "target_type_service_only": true,
                "authorization_scope_required": true,
                "active_policy_allowed": false,
                "high_risk_policy_allowed": false,
                "active_service_probes": 0,
                "external_api_queries": 0,
                "shell_commands": 0,
                "exploit_attempts": 0,
                "bruteforce_attempts": 0,
                "dos_attempts": 0
            }
        });
        let output = normalize(
            &ServiceDetectPlusParser,
            &ParserInput {
                raw: RawOutputReference {
                    run_id: &identifiers.run_id,
                    value: &raw,
                },
                context: ParserContext {
                    identifiers: &identifiers,
                    actor_id: "test",
                },
            },
            "schema",
        )
        .expect("service parser output must normalize");

        assert_eq!(output.spec.findings.len(), 1);
        let evidence = &output.spec.findings[0].evidence[0].data;
        assert_eq!(evidence["findingType"], "asset.service_detect");
        assert_eq!(evidence["x-sentinelflow-service.risk_level"], "low");
        assert!(evidence["x-sentinelflow-service.source_details"].is_array());
    }

    #[test]
    fn http_probe_plus_parser_emits_asset_findings() {
        let identifiers = ExecutionIdentifiers::generate("http-probe-plus");
        let raw = serde_json::json!({
            "source": "http-probe-plus",
            "target": {"type": "domain", "value": "example.com"},
            "mode": "fixture",
            "results": [{
                "type": "http_result",
                "url": "https://www.example.com/",
                "status_code": 200,
                "title": "Example Domain",
                "server": "example-http",
                "content_type": "text/html",
                "content_length": 1256,
                "redirect_chain": [],
                "tls_enabled": true,
                "sources": ["fixture"],
                "source_details": [{"source": "fixture", "source_type": "fixture", "evidence": {}}],
                "source_count": 1,
                "source_agreement": "passive_only",
                "passive_only": true,
                "active_verified": false,
                "conflict": false,
                "conflict_reason": null,
                "confidence": 0.7,
                "evidence": {"summary": "HTTP endpoint observed.", "items": []}
            }],
            "source_status": [],
            "summary": {"endpoint_count": 1, "result_count": 1},
            "errors": [],
            "safety": {"active_http_probes": 0}
        });
        let output = normalize(
            &HttpProbePlusParser,
            &ParserInput {
                raw: RawOutputReference {
                    run_id: &identifiers.run_id,
                    value: &raw,
                },
                context: ParserContext {
                    identifiers: &identifiers,
                    actor_id: "test",
                },
            },
            "schema",
        )
        .expect("http parser output must normalize");

        assert_eq!(output.spec.findings.len(), 1);
        let evidence = &output.spec.findings[0].evidence[0].data;
        assert_eq!(evidence["findingType"], "asset.http_probe");
        assert_eq!(evidence["x-sentinelflow-http.status_code"], 200);
        assert!(evidence["x-sentinelflow-http.source_details"].is_array());
    }

    #[test]
    fn web_fingerprint_plus_parser_emits_asset_findings() {
        let identifiers = ExecutionIdentifiers::generate("web-fingerprint-plus");
        let raw = serde_json::json!({
            "source": "web-fingerprint-plus",
            "target": {"type": "domain", "value": "example.com"},
            "mode": "fixture",
            "results": [{
                "type": "web_fingerprint_result",
                "url": "https://www.example.com/",
                "technology": "WordPress",
                "category": "cms",
                "version": "6.4",
                "confidence": 0.86,
                "sources": ["fixture"],
                "source_count": 1,
                "source_details": [{"source": "fixture", "source_type": "fixture", "evidence": {}}],
                "signals": [{"kind": "header", "pattern": "wordpress", "source": "fixture"}],
                "signal_count": 1,
                "evidence": {"summary": "WordPress fingerprint observed.", "items": []}
            }],
            "source_status": [],
            "summary": {"observation_count": 1, "result_count": 1},
            "errors": [],
            "safety": {"active_http_requests": 0}
        });
        let output = normalize(
            &WebFingerprintPlusParser,
            &ParserInput {
                raw: RawOutputReference {
                    run_id: &identifiers.run_id,
                    value: &raw,
                },
                context: ParserContext {
                    identifiers: &identifiers,
                    actor_id: "test",
                },
            },
            "schema",
        )
        .expect("web fingerprint parser output must normalize");

        assert_eq!(output.spec.findings.len(), 1);
        let evidence = &output.spec.findings[0].evidence[0].data;
        assert_eq!(evidence["findingType"], "asset.web_fingerprint");
        assert_eq!(
            evidence["x-sentinelflow-web-fingerprint.technology"],
            "WordPress"
        );
        assert!(evidence["x-sentinelflow-web-fingerprint.signals"].is_array());
    }

    #[test]
    fn tls_certificate_check_plus_parser_emits_asset_findings() {
        let identifiers = ExecutionIdentifiers::generate("tls-certificate-check-plus");
        let raw = serde_json::json!({
            "source": "tls-certificate-check-plus",
            "target": {"type": "domain", "value": "example.com"},
            "mode": "fixture",
            "results": [{
                "type": "tls_certificate_result",
                "host": "www.example.com",
                "port": 443,
                "subject": "CN=www.example.com",
                "issuer": "CN=Example CA",
                "san": ["www.example.com", "example.com"],
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-12-31T23:59:59Z",
                "days_until_expiry": 197,
                "status": "valid",
                "signature_algorithm": "sha256WithRSAEncryption",
                "tls_version": "TLSv1.3",
                "chain_summary": [],
                "san_assets": ["www.example.com", "example.com"],
                "sources": ["fixture"],
                "source_count": 1,
                "source_details": [{"source": "fixture", "source_type": "fixture", "evidence": {}}],
                "confidence": 0.72,
                "evidence": {"summary": "TLS certificate observed.", "items": []}
            }],
            "source_status": [],
            "summary": {"endpoint_count": 1, "result_count": 1},
            "errors": [],
            "safety": {"active_tls_handshakes": 0}
        });
        let output = normalize(
            &TlsCertificateCheckPlusParser,
            &ParserInput {
                raw: RawOutputReference {
                    run_id: &identifiers.run_id,
                    value: &raw,
                },
                context: ParserContext {
                    identifiers: &identifiers,
                    actor_id: "test",
                },
            },
            "schema",
        )
        .expect("tls certificate parser output must normalize");

        assert_eq!(output.spec.findings.len(), 1);
        let evidence = &output.spec.findings[0].evidence[0].data;
        assert_eq!(evidence["findingType"], "asset.tls_certificate");
        assert_eq!(evidence["x-sentinelflow-tls-certificate.status"], "valid");
        assert!(evidence["x-sentinelflow-tls-certificate.san"].is_array());
    }

    #[test]
    fn fofa_import_plus_parser_emits_asset_findings() {
        let identifiers = ExecutionIdentifiers::generate("fofa-import-plus");
        let raw = serde_json::json!({
            "source": "fofa-import-plus",
            "target": {"type": "domain", "value": "example.com"},
            "mode": "fixture",
            "query": {"scope": "domain", "field": "domain", "value": "example.com", "user_query_allowed": false},
            "results": [{
                "type": "exposure_intel_result",
                "host": "www.example.com",
                "ip": "93.184.216.34",
                "port": 443,
                "protocol": "https",
                "service": "https",
                "title": "Example Domain",
                "headers": {"server": "example-edge"},
                "certificate": {"subject": "CN=www.example.com", "issuer": "CN=Example CA", "san": ["www.example.com"]},
                "observed_at": "2026-06-01T00:00:00Z",
                "sources": ["fixture"],
                "source_count": 1,
                "source_details": [{"source": "fixture", "source_type": "fixture", "evidence": {}}],
                "confidence": 0.78,
                "evidence": {"summary": "FOFA exposure intelligence observed.", "items": []}
            }],
            "source_status": [],
            "summary": {"observation_count": 1, "result_count": 1},
            "errors": [],
            "safety": {"user_query_allowed": false, "secret_emitted": false}
        });
        let output = normalize(
            &FofaImportPlusParser,
            &ParserInput {
                raw: RawOutputReference {
                    run_id: &identifiers.run_id,
                    value: &raw,
                },
                context: ParserContext {
                    identifiers: &identifiers,
                    actor_id: "test",
                },
            },
            "schema",
        )
        .expect("fofa import parser output must normalize");

        assert_eq!(output.spec.findings.len(), 1);
        let evidence = &output.spec.findings[0].evidence[0].data;
        assert_eq!(evidence["findingType"], "asset.exposure_intel");
        assert_eq!(evidence["x-sentinelflow-exposure-intel.provider"], "fofa");
        assert_eq!(evidence["x-sentinelflow-exposure-intel.port"], 443);
    }

    #[test]
    fn shodan_import_plus_parser_emits_asset_findings() {
        let identifiers = ExecutionIdentifiers::generate("shodan-import-plus");
        let raw = serde_json::json!({
            "source": "shodan-import-plus",
            "target": {"type": "ip", "value": "93.184.216.34"},
            "mode": "fixture",
            "query": {"scope": "ip", "field": "host", "value": "93.184.216.34", "user_query_allowed": false},
            "results": [{
                "type": "exposure_intel_result",
                "host": "www.example.com",
                "ip": "93.184.216.34",
                "port": 443,
                "protocol": "https",
                "service": "https",
                "title": "Example Domain",
                "banner": "HTTP/1.1 200 OK",
                "certificate": {"subject": "CN=www.example.com", "fingerprint": "sha256:example"},
                "first_seen": "2026-05-01T00:00:00Z",
                "last_seen": "2026-06-01T00:00:00Z",
                "observed_at": "2026-06-01T00:00:00Z",
                "sources": ["fixture"],
                "source_count": 1,
                "source_details": [{"source": "fixture", "source_type": "fixture", "evidence": {}}],
                "confidence": 0.82,
                "evidence": {"summary": "Shodan host intelligence observed.", "items": []}
            }],
            "source_status": [],
            "summary": {"observation_count": 1, "result_count": 1},
            "errors": [],
            "safety": {"user_query_allowed": false, "secret_emitted": false}
        });
        let output = normalize(
            &ShodanImportPlusParser,
            &ParserInput {
                raw: RawOutputReference {
                    run_id: &identifiers.run_id,
                    value: &raw,
                },
                context: ParserContext {
                    identifiers: &identifiers,
                    actor_id: "test",
                },
            },
            "schema",
        )
        .expect("shodan import parser output must normalize");

        assert_eq!(output.spec.findings.len(), 1);
        let evidence = &output.spec.findings[0].evidence[0].data;
        assert_eq!(evidence["findingType"], "asset.exposure_intel");
        assert_eq!(evidence["x-sentinelflow-exposure-intel.provider"], "shodan");
        assert_eq!(
            evidence["x-sentinelflow-exposure-intel.ip"],
            "93.184.216.34"
        );
    }

    #[test]
    fn censys_import_plus_parser_emits_asset_findings() {
        let identifiers = ExecutionIdentifiers::generate("censys-import-plus");
        let raw = serde_json::json!({
            "source": "censys-import-plus",
            "target": {"type": "ip", "value": "93.184.216.34"},
            "mode": "fixture",
            "query": {"scope": "ip", "field": "host.ip", "value": "93.184.216.34", "user_query_allowed": false},
            "results": [{
                "type": "exposure_intel_result",
                "host": "www.example.com",
                "ip": "93.184.216.34",
                "port": 443,
                "protocol": "https",
                "service": "HTTPS",
                "names": ["www.example.com", "example.com"],
                "certificate": {"subject": "CN=www.example.com", "fingerprint_sha256": "sha256:example-www"},
                "service_fingerprint": {"jarm": "29d29d00029d29d00042d43d000000example"},
                "first_observed_at": "2026-05-01T00:00:00Z",
                "last_observed_at": "2026-06-01T00:00:00Z",
                "observed_at": "2026-06-01T00:00:00Z",
                "sources": ["fixture"],
                "source_count": 1,
                "source_details": [{"source": "fixture", "source_type": "fixture", "evidence": {}}],
                "confidence": 0.84,
                "evidence": {"summary": "Censys exposure intelligence observed.", "items": []}
            }],
            "source_status": [],
            "summary": {"observation_count": 1, "result_count": 1},
            "errors": [],
            "safety": {"user_query_allowed": false, "secret_emitted": false}
        });
        let output = normalize(
            &CensysImportPlusParser,
            &ParserInput {
                raw: RawOutputReference {
                    run_id: &identifiers.run_id,
                    value: &raw,
                },
                context: ParserContext {
                    identifiers: &identifiers,
                    actor_id: "test",
                },
            },
            "schema",
        )
        .expect("censys import parser output must normalize");

        assert_eq!(output.spec.findings.len(), 1);
        let evidence = &output.spec.findings[0].evidence[0].data;
        assert_eq!(evidence["findingType"], "asset.exposure_intel");
        assert_eq!(evidence["x-sentinelflow-exposure-intel.provider"], "censys");
        assert_eq!(
            evidence["x-sentinelflow-exposure-intel.service_fingerprint"]["jarm"],
            "29d29d00029d29d00042d43d000000example"
        );
    }

    #[test]
    fn nessus_import_plus_parser_emits_vulnerability_findings() {
        let identifiers = ExecutionIdentifiers::generate("nessus-import-plus");
        let raw = serde_json::json!({
            "source": "nessus-import-plus",
            "target": {"type": "report", "value": "nessus-xml-fixture"},
            "mode": "fixture",
            "format": "nessus_xml",
            "results": [{
                "type": "vulnerability_import_result",
                "host": "api.example.com",
                "host_ip": "93.184.216.35",
                "port": 8443,
                "protocol": "tcp",
                "service": "https",
                "plugin_id": "100002",
                "plugin_name": "Example Critical Vulnerability",
                "plugin_family": "Web Servers",
                "severity": 4,
                "severity_label": "critical",
                "cve": ["CVE-2026-0002"],
                "cwe": [],
                "cvss_base_score": 9.8,
                "synopsis": "Example critical vulnerability was reported.",
                "description": "Synthetic critical finding.",
                "solution": "Apply the vendor patch.",
                "plugin_output": "HTTP 500 proof from scanner report.",
                "sources": ["nessus_xml"],
                "source_count": 1,
                "source_details": [{"source": "nessus_xml", "plugin_id": "100002"}],
                "confidence": 0.9,
                "evidence": {"summary": "Example critical vulnerability was reported.", "items": []}
            }],
            "source_status": [],
            "summary": {"result_count": 1},
            "errors": [],
            "safety": {"active_target_connections": 0, "scanner_invocations": 0}
        });
        let output = normalize(
            &NessusImportPlusParser,
            &ParserInput {
                raw: RawOutputReference {
                    run_id: &identifiers.run_id,
                    value: &raw,
                },
                context: ParserContext {
                    identifiers: &identifiers,
                    actor_id: "test",
                },
            },
            "schema",
        )
        .expect("nessus import parser output must normalize");

        assert_eq!(output.spec.findings.len(), 1);
        assert_eq!(output.spec.findings[0].severity, FindingSeverity::Critical);
        let evidence = &output.spec.findings[0].evidence[0].data;
        assert_eq!(evidence["findingType"], "risk.vuln_import");
        assert_eq!(evidence["x-sentinelflow-vuln-import.plugin_id"], "100002");
        assert_eq!(
            evidence["x-sentinelflow-vuln-import.cve"][0],
            "CVE-2026-0002"
        );
    }

    #[test]
    fn openvas_import_plus_parser_emits_vulnerability_findings() {
        let identifiers = ExecutionIdentifiers::generate("openvas-import-plus");
        let raw = serde_json::json!({
            "source": "openvas-import-plus",
            "target": {"type": "report", "value": "openvas-xml-fixture"},
            "mode": "fixture",
            "format": "openvas_xml",
            "results": [{
                "type": "vulnerability_import_result",
                "host": "api.example.com",
                "port": 8443,
                "protocol": "tcp",
                "nvt_oid": "1.3.6.1.4.1.25623.1.0.100002",
                "plugin_name": "Example OpenVAS Critical Web Finding",
                "family": "Web application abuses",
                "threat": "High",
                "qod": 95,
                "severity": 4,
                "severity_label": "critical",
                "cve": ["CVE-2026-1002", "CVE-2026-1003"],
                "cvss_base_score": 9.1,
                "description": "Example OpenVAS high finding. token=[REDACTED]",
                "solution": "Apply the Greenbone recommended remediation.",
                "solution_type": "VendorFix",
                "result_id": "res-2",
                "evidence_text": null,
                "sources": ["openvas_xml"],
                "source_count": 1,
                "source_details": [{"source": "openvas_xml", "nvt_oid": "1.3.6.1.4.1.25623.1.0.100002"}],
                "confidence": 0.89,
                "evidence": {"summary": "OpenVAS imported critical finding Example OpenVAS Critical Web Finding on api.example.com.", "items": []}
            }],
            "source_status": [],
            "summary": {"result_count": 1},
            "errors": [],
            "safety": {"active_target_connections": 0, "scanner_invocations": 0}
        });
        let output = normalize(
            &OpenvasImportPlusParser,
            &ParserInput {
                raw: RawOutputReference {
                    run_id: &identifiers.run_id,
                    value: &raw,
                },
                context: ParserContext {
                    identifiers: &identifiers,
                    actor_id: "test",
                },
            },
            "schema",
        )
        .expect("openvas import parser output must normalize");

        assert_eq!(output.spec.findings.len(), 1);
        assert_eq!(output.spec.findings[0].severity, FindingSeverity::Critical);
        let evidence = &output.spec.findings[0].evidence[0].data;
        assert_eq!(evidence["findingType"], "risk.vuln_import");
        assert_eq!(evidence["x-sentinelflow-vuln-import.source"], "openvas");
        assert_eq!(
            evidence["x-sentinelflow-vuln-import.nvt_oid"],
            "1.3.6.1.4.1.25623.1.0.100002"
        );
        assert_eq!(
            evidence["x-sentinelflow-vuln-import.cve"][1],
            "CVE-2026-1003"
        );
    }

    #[test]
    fn nuclei_adapter_plus_parser_emits_web_scan_findings() {
        let identifiers = ExecutionIdentifiers::generate("nuclei-adapter-plus");
        let raw = serde_json::json!({
            "source": "nuclei-adapter-plus",
            "target": {"type": "url", "value": "https://www.example.com"},
            "mode": "fixture",
            "format": "nuclei_jsonl",
            "results": [{
                "type": "nuclei_result",
                "matched_at": "https://www.example.com/",
                "host": "https://www.example.com",
                "ip": "93.184.216.34",
                "scheme": "https",
                "port": 443,
                "template_id": "http-missing-security-header",
                "template_path": "http/exposures/http-missing-security-header.yaml",
                "template_name": "Missing Security Header",
                "template_severity": "low",
                "tags": ["http", "headers", "exposure"],
                "description": "Example low impact header finding. token=[REDACTED]",
                "matcher_name": "missing-header",
                "extractor_name": null,
                "type_name": "http",
                "cve": [],
                "cwe": ["CWE-693"],
                "cvss_score": 3.1,
                "references": ["https://example.com/advisory/header"],
                "extracted_results": ["X-Frame-Options missing"],
                "request": null,
                "curl_command": null,
                "observed_at": "2026-01-01T00:00:00Z",
                "sources": ["nuclei_jsonl"],
                "source_count": 1,
                "source_details": [{"source": "nuclei_jsonl", "template_id": "http-missing-security-header"}],
                "confidence": 0.72,
                "evidence": {"summary": "Nuclei imported low template result http-missing-security-header on https://www.example.com/.", "items": []}
            }],
            "source_status": [],
            "summary": {"result_count": 1},
            "errors": [],
            "safety": {"active_target_connections": 0, "scanner_invocations": 0, "template_execution": false}
        });
        let output = normalize(
            &NucleiAdapterPlusParser,
            &ParserInput {
                raw: RawOutputReference {
                    run_id: &identifiers.run_id,
                    value: &raw,
                },
                context: ParserContext {
                    identifiers: &identifiers,
                    actor_id: "test",
                },
            },
            "schema",
        )
        .expect("nuclei adapter parser output must normalize");

        assert_eq!(output.spec.findings.len(), 1);
        assert_eq!(output.spec.findings[0].severity, FindingSeverity::Low);
        let evidence = &output.spec.findings[0].evidence[0].data;
        assert_eq!(evidence["findingType"], "risk.web_scan");
        assert_eq!(
            evidence["x-sentinelflow-nuclei.template_id"],
            "http-missing-security-header"
        );
        assert_eq!(evidence["x-sentinelflow-nuclei.cwe"][0], "CWE-693");
        assert_eq!(
            evidence["x-sentinelflow-nuclei.extracted_results"][0],
            "X-Frame-Options missing"
        );
    }

    #[test]
    fn zap_baseline_plus_parser_emits_web_scan_findings() {
        let identifiers = ExecutionIdentifiers::generate("zap-baseline-plus");
        let raw = serde_json::json!({
            "source": "zap-baseline-plus",
            "target": {"type": "url", "value": "https://www.example.com"},
            "mode": "fixture",
            "format": "zap_json",
            "results": [{
                "type": "zap_alert_result",
                "url": "https://www.example.com/",
                "site": "https://www.example.com",
                "host": "www.example.com",
                "port": 443,
                "ssl": true,
                "alert_id": "10020",
                "alert_ref": "10020",
                "alert_name": "X-Frame-Options Header Not Set",
                "risk": "low",
                "risk_description": "Low (Medium)",
                "confidence_label": "medium",
                "method": "GET",
                "parameter": null,
                "attack": null,
                "evidence_text": "HTTP/1.1 200 OK",
                "description": "Anti-clickjacking header missing. token=[REDACTED]",
                "other_info": null,
                "solution": "Set X-Frame-Options or CSP frame-ancestors.",
                "reference": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options"],
                "cwe_id": 1021,
                "wasc_id": 15,
                "source_id": "3",
                "sources": ["zap_json"],
                "source_count": 1,
                "source_details": [{"source": "zap_json", "site_index": 0, "alert_id": "10020"}],
                "confidence": 0.70,
                "evidence": {"summary": "ZAP imported low passive alert 10020 on https://www.example.com/.", "items": []}
            }],
            "source_status": [],
            "summary": {"result_count": 1},
            "errors": [],
            "safety": {"active_target_connections": 0, "scanner_invocations": 0, "active_scan_invocations": 0}
        });
        let output = normalize(
            &ZapBaselinePlusParser,
            &ParserInput {
                raw: RawOutputReference {
                    run_id: &identifiers.run_id,
                    value: &raw,
                },
                context: ParserContext {
                    identifiers: &identifiers,
                    actor_id: "test",
                },
            },
            "schema",
        )
        .expect("ZAP baseline parser output must normalize");

        assert_eq!(output.spec.findings.len(), 1);
        assert_eq!(output.spec.findings[0].severity, FindingSeverity::Low);
        let evidence = &output.spec.findings[0].evidence[0].data;
        assert_eq!(evidence["findingType"], "risk.web_scan");
        assert_eq!(evidence["x-sentinelflow-zap.alert_id"], "10020");
        assert_eq!(evidence["x-sentinelflow-zap.cwe_id"], 1021);
        assert_eq!(evidence["x-sentinelflow-zap.confidence_label"], "medium");
    }

    #[test]
    fn cloud_asset_import_plus_parser_emits_cloud_asset_findings() {
        let identifiers = ExecutionIdentifiers::generate("cloud-asset-import-plus");
        let raw = serde_json::json!({
            "source": "cloud-asset-import-plus",
            "target": {"type": "cloud_inventory", "value": "multicloud-fixture"},
            "mode": "fixture",
            "results": [{
                "type": "cloud_asset_result",
                "provider": "alibaba",
                "resource_type": "security_group",
                "resource_id": "sg-ali-001",
                "name": "public-web",
                "scope_id": "ali-account-001",
                "region": "cn-hangzhou",
                "status": null,
                "public_ips": [],
                "private_ips": [],
                "dns_names": [],
                "internet_exposed": true,
                "exposure_reasons": ["open_security_group_rule"],
                "risk": "medium",
                "tags": {"environment": "production"},
                "security_rules": [{
                    "direction": "ingress",
                    "protocol": "TCP",
                    "from_port": 22,
                    "to_port": 22,
                    "source": "0.0.0.0/0",
                    "access": "Accept"
                }],
                "sources": ["alibaba:security_group"],
                "source_count": 1,
                "source_details": [{"source": "alibaba:security_group"}],
                "confidence": 0.92,
                "evidence": {"summary": "alibaba security_group asset public-web imported from offline inventory.", "items": []}
            }],
            "source_status": [],
            "summary": {"result_count": 1},
            "errors": [],
            "safety": {"cloud_api_calls": 0, "credential_use": false, "active_asset_connections": 0}
        });
        let output = normalize(
            &CloudAssetImportPlusParser,
            &ParserInput {
                raw: RawOutputReference {
                    run_id: &identifiers.run_id,
                    value: &raw,
                },
                context: ParserContext {
                    identifiers: &identifiers,
                    actor_id: "test",
                },
            },
            "schema",
        )
        .expect("cloud asset parser output must normalize");

        assert_eq!(output.spec.findings.len(), 1);
        assert_eq!(output.spec.findings[0].severity, FindingSeverity::Medium);
        let evidence = &output.spec.findings[0].evidence[0].data;
        assert_eq!(evidence["findingType"], "asset.cloud");
        assert_eq!(evidence["x-sentinelflow-cloud.provider"], "alibaba");
        assert_eq!(
            evidence["x-sentinelflow-cloud.exposure_reasons"][0],
            "open_security_group_rule"
        );
        assert_eq!(
            evidence["x-sentinelflow-cloud.security_rules"][0]["source"],
            "0.0.0.0/0"
        );
    }

    #[test]
    fn cmdb_sync_plus_parser_emits_cmdb_asset_findings() {
        let identifiers = ExecutionIdentifiers::generate("cmdb-sync-plus");
        let raw = serde_json::json!({
            "source": "cmdb-sync-plus",
            "target": {"type": "cmdb", "value": "enterprise-cmdb-fixture"},
            "mode": "writeback_plan",
            "results": [{
                "type": "cmdb_asset_result",
                "external_id": "ci-api-001",
                "asset_type": "service",
                "name": "api.example.com",
                "addresses": ["203.0.113.55"],
                "department": "Platform",
                "business_system": "Public API",
                "owner": "bob@example.com token=[REDACTED]",
                "criticality": "critical",
                "status": "active",
                "updated_at": "2026-06-17T08:30:00Z",
                "sources": ["cmdb_inventory"],
                "source_count": 1,
                "source_details": [{"source": "cmdb_inventory", "external_id": "ci-api-001"}],
                "confidence": 0.95,
                "evidence": {"summary": "CMDB asset api.example.com (ci-api-001) imported with ownership metadata.", "items": []}
            }],
            "operations": [{
                "operation_id": "cmdb-op-example",
                "action": "update",
                "match": {"external_id": "ci-api-001"},
                "changes": {"criticality": {"from": "high", "to": "critical"}},
                "preconditions": {"matched_record_count": 1},
                "requires_gateway_write": true,
                "reason": "SentinelFlow wins allowed field conflicts"
            }],
            "source_status": [],
            "summary": {"result_count": 1, "operation_count": 1},
            "errors": [],
            "safety": {"network_requests": 0, "direct_cmdb_writes": 0}
        });
        let output = normalize(
            &CmdbSyncPlusParser,
            &ParserInput {
                raw: RawOutputReference {
                    run_id: &identifiers.run_id,
                    value: &raw,
                },
                context: ParserContext {
                    identifiers: &identifiers,
                    actor_id: "test",
                },
            },
            "schema",
        )
        .expect("CMDB sync parser output must normalize");

        assert_eq!(output.spec.findings.len(), 1);
        assert_eq!(output.spec.findings[0].severity, FindingSeverity::Info);
        let evidence = &output.spec.findings[0].evidence[0].data;
        assert_eq!(evidence["findingType"], "asset.cmdb");
        assert_eq!(evidence["x-sentinelflow-cmdb.external_id"], "ci-api-001");
        assert_eq!(evidence["x-sentinelflow-cmdb.department"], "Platform");
        assert_eq!(
            evidence["x-sentinelflow-cmdb.business_system"],
            "Public API"
        );
    }

    #[test]
    fn markdown_report_plus_parser_emits_report_finding() {
        let identifiers = ExecutionIdentifiers::generate("markdown-report-plus");
        let raw = serde_json::json!({
            "source": "markdown-report-plus",
            "target": {"type": "report", "value": "asset-discovery-fixture"},
            "mode": "asset_discovery",
            "report": {
                "type": "markdown_report",
                "title": "Asset Discovery Delivery Report",
                "markdown": "# Asset Discovery Delivery Report\n\n## Summary\n\n- Findings rendered: 2\n",
                "sections": ["summary", "asset-discovery", "findings"],
                "bytes": 72,
                "truncated": false,
                "redaction_count": 1
            },
            "summary": {"finding_count": 2, "error_count": 0},
            "source_status": [],
            "errors": [],
            "safety": {"network_connections": 0, "secret_redaction_enabled": true}
        });
        let output = normalize(
            &MarkdownReportPlusParser,
            &ParserInput {
                raw: RawOutputReference {
                    run_id: &identifiers.run_id,
                    value: &raw,
                },
                context: ParserContext {
                    identifiers: &identifiers,
                    actor_id: "test",
                },
            },
            "schema",
        )
        .expect("markdown report parser output must normalize");

        assert_eq!(output.spec.findings.len(), 1);
        let evidence = &output.spec.findings[0].evidence[0].data;
        assert_eq!(evidence["findingType"], "report.markdown");
        assert_eq!(
            evidence["x-sentinelflow-report.title"],
            "Asset Discovery Delivery Report"
        );
        assert_eq!(evidence["x-sentinelflow-report.redaction_count"], 1);
    }
}
