//! Controlled JSON, JSONL, and CSV content import.

use std::time::Instant;

use async_trait::async_trait;
use sentinelflow_runtime::{
    Adapter, AdapterCapabilities, ExecutionRequest, ExecutionResult, ExecutionStatus, RuntimeError,
    RuntimeErrorKind, authorize_execution,
};
use sentinelflow_schema::v1alpha1::{AdapterKind, FileImportFormat};
use serde_json::{Map, Value};

/// File Import Adapter. It accepts content in the request and never opens a path.
#[derive(Clone, Copy, Debug, Default)]
pub struct FileImportAdapter;

/// Validated import request.
pub struct PreparedImport {
    request: ExecutionRequest,
    format: FileImportFormat,
    content: String,
    max_records: usize,
}

/// Running import state.
pub struct RunningImport {
    prepared: PreparedImport,
    started: Instant,
}

#[async_trait]
impl Adapter for FileImportAdapter {
    type Prepared = PreparedImport;
    type Running = RunningImport;

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            cancellation: false,
            streaming_logs: false,
            resource_limits: true,
            asynchronous_tasks: false,
        }
    }

    async fn prepare(&self, request: ExecutionRequest) -> Result<Self::Prepared, RuntimeError> {
        authorize_execution(&request)?;
        if request.manifest.spec.runtime.adapter != AdapterKind::FileImport {
            return Err(runtime(
                "$.manifest.spec.runtime.adapter",
                "file import adapter required",
            ));
        }
        let config = request
            .manifest
            .spec
            .runtime
            .file_import
            .clone()
            .ok_or_else(|| {
                runtime(
                    "$.manifest.spec.runtime.fileImport",
                    "configuration missing",
                )
            })?;
        let format = match request.input.get("format").and_then(Value::as_str) {
            Some("json") => FileImportFormat::Json,
            Some("jsonl") => FileImportFormat::Jsonl,
            Some("csv") => FileImportFormat::Csv,
            _ => {
                return Err(runtime(
                    "$.input.format",
                    "format must be json, jsonl, or csv",
                ));
            }
        };
        if !config.formats.contains(&format) {
            return Err(runtime(
                "$.input.format",
                "format is not allowed by the Manifest",
            ));
        }
        let content = request
            .input
            .get("content")
            .and_then(Value::as_str)
            .ok_or_else(|| runtime("$.input.content", "content must be a string"))?
            .to_owned();
        if content.len() > config.max_bytes {
            return Err(runtime(
                "$.input.content",
                "content exceeds the configured byte limit",
            ));
        }
        Ok(PreparedImport {
            request,
            format,
            content,
            max_records: config.max_records,
        })
    }

    async fn execute(&self, prepared: Self::Prepared) -> Result<Self::Running, RuntimeError> {
        Ok(RunningImport {
            prepared,
            started: Instant::now(),
        })
    }

    async fn collect(&self, running: Self::Running) -> Result<ExecutionResult, RuntimeError> {
        let records = parse_records(
            running.prepared.format,
            &running.prepared.content,
            running.prepared.max_records,
        )?;
        Ok(ExecutionResult {
            identifiers: running.prepared.request.identifiers,
            status: ExecutionStatus::Succeeded,
            output: Some(serde_json::json!({
                "source": "controlled-content",
                "records": records
            })),
            exit_code: None,
            duration_ms: running.started.elapsed().as_millis(),
        })
    }

    async fn cancel(&self, _run_id: &str) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(
            RuntimeErrorKind::Cancelled,
            None,
            "file imports complete synchronously and do not support cancellation",
        ))
    }
}

fn parse_records(
    format: FileImportFormat,
    content: &str,
    limit: usize,
) -> Result<Vec<Value>, RuntimeError> {
    let records = match format {
        FileImportFormat::Json => {
            let value: Value = serde_json::from_str(content)
                .map_err(|error| runtime("$.input.content", format!("invalid JSON: {error}")))?;
            value.as_array().cloned().unwrap_or_else(|| vec![value])
        }
        FileImportFormat::Jsonl => content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str(line).map_err(|error| {
                    runtime("$.input.content", format!("invalid JSONL record: {error}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        FileImportFormat::Csv => {
            let mut reader = csv::Reader::from_reader(content.as_bytes());
            let headers = reader
                .headers()
                .map_err(|error| runtime("$.input.content", format!("invalid CSV: {error}")))?
                .clone();
            reader
                .records()
                .map(|row| {
                    let row = row.map_err(|error| {
                        runtime("$.input.content", format!("invalid CSV row: {error}"))
                    })?;
                    let object = headers
                        .iter()
                        .zip(row.iter())
                        .map(|(key, value)| (key.to_owned(), Value::String(value.to_owned())))
                        .collect::<Map<_, _>>();
                    Ok(Value::Object(object))
                })
                .collect::<Result<Vec<_>, RuntimeError>>()?
        }
    };
    if records.len() > limit {
        return Err(runtime(
            "$.input.content",
            "record count exceeds the configured limit",
        ));
    }
    Ok(records)
}

fn runtime(field: &str, message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(
        RuntimeErrorKind::InputInvalid,
        Some(field.to_owned()),
        message,
    )
}
