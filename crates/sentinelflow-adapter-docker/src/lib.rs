//! Controlled Docker Adapter using the Docker CLI as an isolated child process.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Instant,
};

use async_trait::async_trait;
use sentinelflow_runtime::{
    Adapter, AdapterCapabilities, ExecutionCancellation, ExecutionRequest, ExecutionResult,
    ExecutionStatus, RuntimeError, RuntimeErrorKind, authorize_execution,
};
use sentinelflow_schema::v1alpha1::{
    AdapterKind, DockerAdapterSpec, DockerMountSpec, DockerNetworkPolicy, RuntimeMode,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    sync::Mutex,
    task::JoinHandle,
};

/// Docker Adapter configured with a Docker-compatible CLI executable.
#[derive(Clone, Debug)]
pub struct DockerAdapter {
    program: PathBuf,
    runs: Arc<Mutex<HashMap<String, ExecutionCancellation>>>,
}

impl Default for DockerAdapter {
    fn default() -> Self {
        Self::new("docker")
    }
}

impl DockerAdapter {
    /// Creates an Adapter using the supplied Docker-compatible CLI path.
    #[must_use]
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            runs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn force_remove(&self, run_id: &str) {
        let _ = Command::new(&self.program)
            .args(["rm", "-f", &container_name(run_id)])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
    }
}

/// Validated Docker invocation.
#[derive(Debug)]
pub struct PreparedDocker {
    request: ExecutionRequest,
    arguments: Vec<String>,
    input: Vec<u8>,
}

/// Active Docker CLI process.
pub struct RunningDocker {
    request: ExecutionRequest,
    child: Child,
    stdout: JoinHandle<Result<Vec<u8>, RuntimeError>>,
    stderr: JoinHandle<Result<Vec<u8>, RuntimeError>>,
    cancellation: ExecutionCancellation,
    started: Instant,
}

#[async_trait]
impl Adapter for DockerAdapter {
    type Prepared = PreparedDocker;
    type Running = RunningDocker;

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            cancellation: true,
            streaming_logs: false,
            resource_limits: true,
            asynchronous_tasks: false,
        }
    }

    async fn prepare(&self, request: ExecutionRequest) -> Result<Self::Prepared, RuntimeError> {
        authorize_execution(&request)?;
        if request.manifest.spec.runtime.adapter != AdapterKind::Docker
            || request.manifest.spec.runtime.mode != RuntimeMode::Container
        {
            return Err(runtime(
                RuntimeErrorKind::InputInvalid,
                "$.manifest.spec.runtime",
                "Docker Adapter requires adapter=docker and mode=container",
            ));
        }
        let config = request
            .manifest
            .spec
            .runtime
            .docker
            .clone()
            .ok_or_else(|| {
                runtime(
                    RuntimeErrorKind::InputInvalid,
                    "$.manifest.spec.runtime.docker",
                    "configuration missing",
                )
            })?;
        let arguments = build_arguments(&request, &config)?;
        let input = serde_json::to_vec(&request.input).map_err(|error| {
            runtime(
                RuntimeErrorKind::InputInvalid,
                "$.input",
                format!("failed to serialize input: {error}"),
            )
        })?;
        Ok(PreparedDocker {
            request,
            arguments,
            input,
        })
    }

    async fn execute(&self, prepared: Self::Prepared) -> Result<Self::Running, RuntimeError> {
        let mut child = Command::new(&self.program)
            .args(&prepared.arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| {
                runtime(
                    RuntimeErrorKind::RunnerUnavailable,
                    "$.manifest.spec.runtime.docker.image",
                    format!("failed to start Docker CLI: {error}"),
                )
            })?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            runtime(
                RuntimeErrorKind::Process,
                "$.input",
                "Docker stdin was not captured",
            )
        })?;
        stdin.write_all(&prepared.input).await.map_err(|error| {
            runtime(
                RuntimeErrorKind::Process,
                "$.input",
                format!("failed to write container input: {error}"),
            )
        })?;
        stdin.shutdown().await.map_err(|error| {
            runtime(
                RuntimeErrorKind::Process,
                "$.input",
                format!("failed to close container input: {error}"),
            )
        })?;

        let stdout = child.stdout.take().ok_or_else(|| {
            runtime(
                RuntimeErrorKind::Process,
                "$.output",
                "Docker stdout was not captured",
            )
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            runtime(
                RuntimeErrorKind::Process,
                "$.output",
                "Docker stderr was not captured",
            )
        })?;
        let limit = prepared.request.manifest.spec.runtime.output_limit_bytes;
        let stdout = tokio::spawn(read_bounded(stdout, limit));
        let stderr = tokio::spawn(read_bounded(stderr, limit));
        let cancellation = ExecutionCancellation::new();
        self.runs.lock().await.insert(
            prepared.request.identifiers.run_id.clone(),
            cancellation.clone(),
        );
        Ok(RunningDocker {
            request: prepared.request,
            child,
            stdout,
            stderr,
            cancellation,
            started: Instant::now(),
        })
    }

    async fn collect(&self, mut running: Self::Running) -> Result<ExecutionResult, RuntimeError> {
        let run_id = running.request.identifiers.run_id.clone();
        let wait_result = tokio::select! {
            status = running.child.wait() => status.map_err(|error| {
                runtime(RuntimeErrorKind::Process, "$.runtime", format!("Docker wait failed: {error}"))
            }),
            () = tokio::time::sleep(running.request.timeout) => {
                Err(runtime(RuntimeErrorKind::Timeout, "$.timeout", "Docker execution timed out"))
            }
            () = running.cancellation.cancelled() => {
                Err(runtime(RuntimeErrorKind::Cancelled, "$.runtime", "Docker execution was cancelled"))
            }
        };
        if wait_result.is_err() {
            let _ = running.child.kill().await;
            self.force_remove(&run_id).await;
        }
        let stdout = join_output(running.stdout).await?;
        let stderr = join_output(running.stderr).await?;
        self.runs.lock().await.remove(&run_id);
        let status = wait_result?;
        if !status.success() {
            return Err(runtime(
                RuntimeErrorKind::ExitFailure,
                "$.runtime",
                format!(
                    "Docker CLI exited with code {}: {}",
                    status
                        .code()
                        .map_or_else(|| "unknown".to_owned(), |code| code.to_string()),
                    String::from_utf8_lossy(&stderr).trim()
                ),
            ));
        }
        let output = serde_json::from_slice(&stdout).map_err(|error| {
            runtime(
                RuntimeErrorKind::OutputInvalid,
                "$.output",
                format!("container output is not JSON: {error}"),
            )
        })?;
        Ok(ExecutionResult {
            identifiers: running.request.identifiers,
            status: ExecutionStatus::Succeeded,
            output: Some(output),
            exit_code: status.code(),
            duration_ms: running.started.elapsed().as_millis(),
        })
    }

    async fn cancel(&self, run_id: &str) -> Result<(), RuntimeError> {
        if let Some(cancellation) = self.runs.lock().await.get(run_id) {
            cancellation.cancel();
        }
        self.force_remove(run_id).await;
        Ok(())
    }
}

fn build_arguments(
    request: &ExecutionRequest,
    config: &DockerAdapterSpec,
) -> Result<Vec<String>, RuntimeError> {
    let mut arguments = vec![
        "run".to_owned(),
        "--rm".to_owned(),
        "--name".to_owned(),
        container_name(&request.identifiers.run_id),
        "--network".to_owned(),
        match config.network {
            DockerNetworkPolicy::None => "none",
            DockerNetworkPolicy::Bridge => "bridge",
        }
        .to_owned(),
        "--cpus".to_owned(),
        format!("{:.3}", f64::from(config.cpu_millis) / 1000.0),
        "--memory".to_owned(),
        format!("{}m", config.memory_mib),
    ];
    for mount in &config.mounts {
        arguments.extend(["--mount".to_owned(), mount_argument(request, mount)?]);
    }
    arguments.push(config.image.clone());
    arguments.extend(config.command.iter().cloned());
    Ok(arguments)
}

fn mount_argument(
    request: &ExecutionRequest,
    mount: &DockerMountSpec,
) -> Result<String, RuntimeError> {
    let declared = Path::new(&mount.source);
    if declared.is_absolute()
        || declared
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(runtime(
            RuntimeErrorKind::InvalidPath,
            "$.manifest.spec.runtime.docker.mounts.source",
            "mount source must be plugin-relative and cannot contain parent traversal",
        ));
    }
    let examples_root = request
        .plugin_root
        .join("examples")
        .canonicalize()
        .map_err(|error| {
            runtime(
                RuntimeErrorKind::InvalidPath,
                "$.manifest.spec.runtime.docker.mounts.source",
                format!("examples directory is unavailable: {error}"),
            )
        })?;
    let source = request
        .plugin_root
        .join(declared)
        .canonicalize()
        .map_err(|error| {
            runtime(
                RuntimeErrorKind::InvalidPath,
                "$.manifest.spec.runtime.docker.mounts.source",
                format!("mount source is unavailable: {error}"),
            )
        })?;
    if !source.starts_with(&examples_root) || !source.is_dir() || !mount.target.starts_with('/') {
        return Err(runtime(
            RuntimeErrorKind::InvalidPath,
            "$.manifest.spec.runtime.docker.mounts",
            "mounts are limited to plugin examples directories and absolute container targets",
        ));
    }
    let mut value = format!("type=bind,src={},dst={}", source.display(), mount.target);
    if mount.read_only {
        value.push_str(",readonly");
    }
    Ok(value)
}

async fn read_bounded(
    reader: impl AsyncRead + Unpin,
    limit: usize,
) -> Result<Vec<u8>, RuntimeError> {
    let mut bytes = Vec::new();
    reader
        .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| runtime(RuntimeErrorKind::Process, "$.output", error.to_string()))?;
    if bytes.len() > limit {
        return Err(runtime(
            RuntimeErrorKind::OutputLimit,
            "$.output",
            "Docker output exceeded the configured limit",
        ));
    }
    Ok(bytes)
}

async fn join_output(
    task: JoinHandle<Result<Vec<u8>, RuntimeError>>,
) -> Result<Vec<u8>, RuntimeError> {
    task.await.map_err(|error| {
        runtime(
            RuntimeErrorKind::Process,
            "$.output",
            format!("output task failed: {error}"),
        )
    })?
}

fn container_name(run_id: &str) -> String {
    let suffix: String = run_id
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '-')
        .take(48)
        .collect();
    format!("sentinelflow-{suffix}")
}

fn runtime(kind: RuntimeErrorKind, field: &str, message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(kind, Some(field.to_owned()), message)
}
