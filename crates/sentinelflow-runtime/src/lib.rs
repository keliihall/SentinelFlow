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
    let sdk_scaffold = request.plugin_root.join(".sentinelflow-scaffold").is_file();
    let example_plugin = example_label && (known_example || sdk_scaffold);
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
                "title": "Fixture records imported",
                "severity": FindingSeverity::Info,
                "summary": format!("Imported {} synthetic records from {source}.", records.len()),
                "evidence": [{
                    "evidenceType": "fixture-record-count",
                    "description": "Count of structured records supplied over stdin.",
                    "data": {"source": source, "count": records.len()}
                }]
            })] },
            "errors": []
        }))
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
}
