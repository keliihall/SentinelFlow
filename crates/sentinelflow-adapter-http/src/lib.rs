//! Bounded HTTP Adapter with secret references, retry, pagination, and polling.

use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use reqwest::header::{HeaderName, HeaderValue};
use sentinelflow_runtime::{
    Adapter, AdapterCapabilities, ExecutionCancellation, ExecutionRequest, ExecutionResult,
    ExecutionStatus, RuntimeError, RuntimeErrorKind, authorize_execution,
};
use sentinelflow_schema::v1alpha1::{AdapterKind, HttpAdapterSpec, HttpMethod};
use serde_json::Value;
use tokio::sync::Mutex;
use url::Url;

/// HTTP Adapter using a reusable client.
#[derive(Clone, Debug)]
pub struct HttpAdapter {
    client: reqwest::Client,
    runs: Arc<Mutex<HashMap<String, ExecutionCancellation>>>,
}

impl Default for HttpAdapter {
    fn default() -> Self {
        Self {
            client: reqwest::Client::new(),
            runs: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

/// Validated HTTP request.
pub struct PreparedHttp {
    request: ExecutionRequest,
    config: HttpAdapterSpec,
    url: Url,
    headers: Vec<(HeaderName, HeaderValue)>,
}

/// Running HTTP request.
pub struct RunningHttp {
    prepared: PreparedHttp,
    cancellation: ExecutionCancellation,
    started: Instant,
}

#[async_trait]
impl Adapter for HttpAdapter {
    type Prepared = PreparedHttp;
    type Running = RunningHttp;

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            cancellation: true,
            streaming_logs: false,
            resource_limits: false,
            asynchronous_tasks: true,
        }
    }

    async fn prepare(&self, request: ExecutionRequest) -> Result<Self::Prepared, RuntimeError> {
        authorize_execution(&request)?;
        if request.manifest.spec.runtime.adapter != AdapterKind::Http {
            return Err(runtime(
                "$.manifest.spec.runtime.adapter",
                "http adapter required",
            ));
        }
        let config = request
            .manifest
            .spec
            .runtime
            .http
            .clone()
            .ok_or_else(|| runtime("$.manifest.spec.runtime.http", "configuration missing"))?;
        let url = Url::parse(&config.url)
            .map_err(|error| runtime("$.manifest.spec.runtime.http.url", error.to_string()))?;
        validate_url(&url)?;
        let mut headers = Vec::new();
        for header in &config.headers {
            let name = HeaderName::from_bytes(header.name.as_bytes()).map_err(|error| {
                runtime("$.manifest.spec.runtime.http.headers", error.to_string())
            })?;
            let value = if let Some(value) = &header.value {
                value.clone()
            } else {
                let reference = header.secret_ref.as_ref().ok_or_else(|| {
                    runtime("$.manifest.spec.runtime.http.headers", "secretRef missing")
                })?;
                env::var(reference).map_err(|_| {
                    runtime(
                        "$.manifest.spec.runtime.http.headers.secretRef",
                        "referenced secret is unavailable",
                    )
                })?
            };
            let value = HeaderValue::from_str(&value).map_err(|error| {
                runtime("$.manifest.spec.runtime.http.headers", error.to_string())
            })?;
            headers.push((name, value));
        }
        Ok(PreparedHttp {
            request,
            config,
            url,
            headers,
        })
    }

    async fn execute(&self, prepared: Self::Prepared) -> Result<Self::Running, RuntimeError> {
        let cancellation = ExecutionCancellation::new();
        self.runs.lock().await.insert(
            prepared.request.identifiers.run_id.clone(),
            cancellation.clone(),
        );
        Ok(RunningHttp {
            prepared,
            cancellation,
            started: Instant::now(),
        })
    }

    async fn collect(&self, running: Self::Running) -> Result<ExecutionResult, RuntimeError> {
        let run_id = running.prepared.request.identifiers.run_id.clone();
        let future = execute_http(&self.client, &running.prepared);
        let result: Result<Value, RuntimeError> = tokio::select! {
            value = tokio::time::timeout(running.prepared.request.timeout, future) => {
                value.unwrap_or_else(|_| {
                    Err(RuntimeError::new(
                        RuntimeErrorKind::Timeout,
                        None,
                        "HTTP request timed out",
                    ))
                })
            }
            () = running.cancellation.cancelled() => {
                Err(RuntimeError::new(RuntimeErrorKind::Cancelled, None, "HTTP request cancelled"))
            }
        };
        self.runs.lock().await.remove(&run_id);
        let value = result?;
        Ok(ExecutionResult {
            identifiers: running.prepared.request.identifiers,
            status: ExecutionStatus::Succeeded,
            output: Some(value),
            exit_code: None,
            duration_ms: running.started.elapsed().as_millis(),
        })
    }

    async fn cancel(&self, run_id: &str) -> Result<(), RuntimeError> {
        let runs = self.runs.lock().await;
        let cancellation = runs.get(run_id).ok_or_else(|| {
            RuntimeError::new(RuntimeErrorKind::Cancelled, None, "run is not active")
        })?;
        cancellation.cancel();
        Ok(())
    }
}

async fn execute_http(
    client: &reqwest::Client,
    prepared: &PreparedHttp,
) -> Result<Value, RuntimeError> {
    let mut url = prepared.url.clone();
    let mut pages = Vec::new();
    let max_pages = prepared
        .config
        .pagination
        .as_ref()
        .map_or(1, |pagination| pagination.max_pages);
    for _ in 0..max_pages {
        let mut last_error = None;
        let mut response_value = None;
        for _ in 0..=prepared.config.retries {
            match send_once(client, prepared, url.clone()).await {
                Ok(value) => {
                    response_value = Some(value);
                    break;
                }
                Err(error) => last_error = Some(error),
            }
        }
        let mut value = response_value.ok_or_else(|| {
            last_error.unwrap_or_else(|| runtime("$.http", "HTTP request failed"))
        })?;
        if let Some(polling) = &prepared.config.polling {
            value = poll_until_complete(client, prepared, value, polling).await?;
        }
        let next = prepared.config.pagination.as_ref().and_then(|pagination| {
            value
                .get(&pagination.next_field)
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
        pages.push(value);
        let Some(next) = next else {
            break;
        };
        url = prepared
            .url
            .join(&next)
            .map_err(|error| runtime("$.http.pagination", error.to_string()))?;
        validate_same_origin(&prepared.url, &url)?;
    }
    Ok(if pages.len() == 1 {
        pages.remove(0)
    } else {
        serde_json::json!({"pages": pages})
    })
}

async fn send_once(
    client: &reqwest::Client,
    prepared: &PreparedHttp,
    url: Url,
) -> Result<Value, RuntimeError> {
    let mut builder = match prepared.config.method {
        HttpMethod::Get => client.get(url),
        HttpMethod::Post => client.post(url).json(&prepared.request.input),
    };
    for (name, value) in &prepared.headers {
        builder = builder.header(name, value);
    }
    let response = builder
        .send()
        .await
        .map_err(|error| runtime("$.http", error.to_string()))?;
    if !response.status().is_success() {
        return Err(runtime(
            "$.http.status",
            format!("HTTP status {}", response.status()),
        ));
    }
    decode_response(
        response,
        prepared.request.manifest.spec.runtime.output_limit_bytes,
    )
    .await
}

async fn poll_until_complete(
    client: &reqwest::Client,
    prepared: &PreparedHttp,
    mut value: Value,
    polling: &sentinelflow_schema::v1alpha1::HttpPollingSpec,
) -> Result<Value, RuntimeError> {
    for _ in 0..polling.max_attempts {
        if value.get(&polling.status_field).and_then(Value::as_str) == Some(&polling.success_value)
        {
            return Ok(value);
        }
        let location = value
            .get(&polling.location_field)
            .and_then(Value::as_str)
            .ok_or_else(|| runtime("$.http.polling", "poll location is missing"))?;
        let url = prepared
            .url
            .join(location)
            .map_err(|error| runtime("$.http.polling", error.to_string()))?;
        validate_same_origin(&prepared.url, &url)?;
        tokio::time::sleep(std::time::Duration::from_millis(polling.interval_ms)).await;
        let mut builder = client.get(url);
        for (name, header_value) in &prepared.headers {
            builder = builder.header(name, header_value);
        }
        let response = builder
            .send()
            .await
            .map_err(|error| runtime("$.http.polling", error.to_string()))?;
        if !response.status().is_success() {
            return Err(runtime(
                "$.http.polling.status",
                format!("HTTP status {}", response.status()),
            ));
        }
        value = decode_response(
            response,
            prepared.request.manifest.spec.runtime.output_limit_bytes,
        )
        .await?;
    }
    Err(runtime("$.http.polling", "polling attempts exhausted"))
}

async fn decode_response(response: reqwest::Response, limit: usize) -> Result<Value, RuntimeError> {
    if response
        .content_length()
        .is_some_and(|length| length > u64::try_from(limit).unwrap_or(u64::MAX))
    {
        return Err(RuntimeError::new(
            RuntimeErrorKind::OutputLimit,
            Some("$.http.response".to_owned()),
            "HTTP response exceeds the configured output limit",
        ));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| runtime("$.http.response", error.to_string()))?;
    if bytes.len() > limit {
        return Err(RuntimeError::new(
            RuntimeErrorKind::OutputLimit,
            Some("$.http.response".to_owned()),
            "HTTP response exceeds the configured output limit",
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| runtime("$.http.response", format!("invalid JSON response: {error}")))
}

fn validate_url(url: &Url) -> Result<(), RuntimeError> {
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
    if url.scheme() == "https" || (url.scheme() == "http" && loopback) {
        Ok(())
    } else {
        Err(runtime(
            "$.manifest.spec.runtime.http.url",
            "only HTTPS or loopback HTTP endpoints are allowed",
        ))
    }
}

fn validate_same_origin(base: &Url, next: &Url) -> Result<(), RuntimeError> {
    if base.scheme() == next.scheme()
        && base.host_str() == next.host_str()
        && base.port_or_known_default() == next.port_or_known_default()
    {
        Ok(())
    } else {
        Err(runtime(
            "$.http.redirect",
            "cross-origin pagination or polling is denied",
        ))
    }
}

fn runtime(field: &str, message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(RuntimeErrorKind::Process, Some(field.to_owned()), message)
}
