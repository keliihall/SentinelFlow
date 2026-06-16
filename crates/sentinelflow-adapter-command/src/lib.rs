//! Controlled out-of-process Command Adapter for `SentinelFlow`.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::time::Instant;

use async_trait::async_trait;
use jsonschema::JSONSchema;
use sentinelflow_runtime::{
    Adapter, AdapterCapabilities, ExecutionCancellation, ExecutionRequest, ExecutionResult,
    ExecutionStatus, RuntimeEnvironment, RuntimeError, RuntimeErrorKind, authorize_execution,
};
use sentinelflow_schema::v1alpha1::{AdapterKind, RuntimeMode};
use serde_json::Value;
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

const CANCEL_NONE: u8 = 0;
const CANCEL_USER: u8 = 1;
const CANCEL_OUTPUT_LIMIT: u8 = 2;

#[derive(Clone, Debug)]
struct RunControl {
    cancellation: ExecutionCancellation,
    reason: Arc<AtomicU8>,
}

/// Command Adapter configured with candidate environment values.
#[derive(Clone, Debug, Default)]
pub struct CommandAdapter {
    environment: RuntimeEnvironment,
    runs: Arc<Mutex<HashMap<String, RunControl>>>,
}

impl CommandAdapter {
    /// Creates an adapter with no inheritable host environment variables.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an adapter with candidate environment values. The Manifest allowlist
    /// is still applied during preparation.
    #[must_use]
    pub fn with_environment(environment: RuntimeEnvironment) -> Self {
        Self {
            environment,
            runs: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

/// Prepared command state. No process has started yet.
#[derive(Debug)]
pub struct PreparedCommand {
    request: ExecutionRequest,
    executable: PathBuf,
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    input: Vec<u8>,
    output_schema: Value,
    temporary_directory: TempDir,
}

/// Running command state collected by [`CommandAdapter`].
pub struct RunningCommand {
    request: ExecutionRequest,
    child: Child,
    stdout: JoinHandle<Result<Vec<u8>, ReadError>>,
    stderr: JoinHandle<Result<(), ReadError>>,
    cancellation: ExecutionCancellation,
    reason: Arc<AtomicU8>,
    output_schema: Value,
    temporary_directory: TempDir,
    started: Instant,
}

impl RunningCommand {
    /// Returns the active run identifier.
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.request.identifiers.run_id
    }
}

#[derive(Debug)]
enum ReadError {
    Io(std::io::Error),
    Limit,
}

#[async_trait]
impl Adapter for CommandAdapter {
    type Prepared = PreparedCommand;
    type Running = RunningCommand;

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            cancellation: true,
            streaming_logs: false,
            resource_limits: false,
            asynchronous_tasks: false,
        }
    }

    async fn prepare(&self, request: ExecutionRequest) -> Result<Self::Prepared, RuntimeError> {
        authorize_execution(&request)?;
        validate_execution_identity(&request)?;
        let plugin_root = canonical_directory(&request.plugin_root, "$.pluginRoot")?;
        let (executable, output_schema) = validate_execution_files(&request, &plugin_root)?;
        let input = encode_input(&request.input)?;
        let temporary_directory = isolated_directory()?;
        let authorization_scope = request.authorization_scope.clone().unwrap_or_default();
        let environment = build_environment(&self.environment, &request, &authorization_scope);
        let arguments = request.manifest.spec.runtime.args.clone();
        Ok(PreparedCommand {
            request,
            executable,
            arguments,
            environment,
            input,
            output_schema,
            temporary_directory,
        })
    }

    async fn execute(&self, prepared: Self::Prepared) -> Result<Self::Running, RuntimeError> {
        let PreparedCommand {
            request,
            executable,
            arguments,
            environment,
            input,
            output_schema,
            temporary_directory,
        } = prepared;
        let mut command = Command::new(&executable);
        command
            .args(&arguments)
            .current_dir(temporary_directory.path())
            .env_clear()
            .envs(&environment)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        command.process_group(0);

        let mut child = command.spawn().map_err(|error| {
            RuntimeError::new(
                RuntimeErrorKind::RunnerUnavailable,
                Some("$.manifest.spec.runtime.entrypoint".to_owned()),
                format!("failed to start declared runner: {error}"),
            )
        })?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            RuntimeError::new(
                RuntimeErrorKind::Process,
                None,
                "runner stdin was not available",
            )
        })?;
        stdin.write_all(&input).await.map_err(|error| {
            RuntimeError::new(
                RuntimeErrorKind::Process,
                Some("$.input".to_owned()),
                format!("failed to send JSON input to runner: {error}"),
            )
        })?;
        stdin.shutdown().await.map_err(|error| {
            RuntimeError::new(
                RuntimeErrorKind::Process,
                Some("$.input".to_owned()),
                format!("failed to close runner stdin: {error}"),
            )
        })?;

        let stdout = child.stdout.take().ok_or_else(|| {
            RuntimeError::new(
                RuntimeErrorKind::Process,
                None,
                "runner stdout was not available",
            )
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            RuntimeError::new(
                RuntimeErrorKind::Process,
                None,
                "runner stderr was not available",
            )
        })?;
        let cancellation = ExecutionCancellation::new();
        let reason = Arc::new(AtomicU8::new(CANCEL_NONE));
        let count = Arc::new(AtomicUsize::new(0));
        let limit = request.manifest.spec.runtime.output_limit_bytes;
        let stdout_task = tokio::spawn(read_stdout(
            stdout,
            Arc::clone(&count),
            limit,
            cancellation.clone(),
            Arc::clone(&reason),
        ));
        let stderr_task = tokio::spawn(read_stderr(
            stderr,
            count,
            limit,
            cancellation.clone(),
            Arc::clone(&reason),
        ));
        self.runs.lock().await.insert(
            request.identifiers.run_id.clone(),
            RunControl {
                cancellation: cancellation.clone(),
                reason: Arc::clone(&reason),
            },
        );

        Ok(RunningCommand {
            request,
            child,
            stdout: stdout_task,
            stderr: stderr_task,
            cancellation,
            reason,
            output_schema,
            temporary_directory,
            started: Instant::now(),
        })
    }

    async fn collect(&self, mut running: Self::Running) -> Result<ExecutionResult, RuntimeError> {
        let timeout = running.request.timeout;
        let run_id = running.request.identifiers.run_id.clone();
        let child_id = running.child.id();
        let wait_result = tokio::select! {
            status = running.child.wait() => WaitResult::Exited(status),
            () = tokio::time::sleep(timeout) => WaitResult::TimedOut,
            () = running.cancellation.cancelled() => WaitResult::Cancelled,
        };

        let terminal_error = match wait_result {
            WaitResult::Exited(status) => {
                let status = status.map_err(|error| {
                    RuntimeError::new(
                        RuntimeErrorKind::Process,
                        None,
                        format!("failed to wait for runner: {error}"),
                    )
                })?;
                if status.success() {
                    None
                } else {
                    Some(RuntimeError::new(
                        RuntimeErrorKind::ExitFailure,
                        None,
                        format!(
                            "runner exited unsuccessfully with code {}",
                            status
                                .code()
                                .map_or_else(|| "unknown".to_owned(), |code| code.to_string())
                        ),
                    ))
                }
            }
            WaitResult::TimedOut => {
                terminate_process_group(&mut running.child, child_id).await;
                Some(RuntimeError::new(
                    RuntimeErrorKind::Timeout,
                    Some("$.timeout".to_owned()),
                    "runner exceeded the requested timeout and was terminated",
                ))
            }
            WaitResult::Cancelled => {
                terminate_process_group(&mut running.child, child_id).await;
                if running.reason.load(Ordering::SeqCst) == CANCEL_OUTPUT_LIMIT {
                    Some(RuntimeError::new(
                        RuntimeErrorKind::OutputLimit,
                        Some("$.manifest.spec.runtime.outputLimitBytes".to_owned()),
                        "combined runner output exceeded the configured limit",
                    ))
                } else {
                    Some(RuntimeError::new(
                        RuntimeErrorKind::Cancelled,
                        None,
                        "runner was cancelled and terminated",
                    ))
                }
            }
        };

        self.runs.lock().await.remove(&run_id);
        let stdout = join_stdout(running.stdout).await?;
        join_stderr(running.stderr).await?;
        if let Some(error) = terminal_error {
            return Err(error);
        }

        let output: Value = serde_json::from_slice(&stdout).map_err(|error| {
            RuntimeError::new(
                RuntimeErrorKind::OutputInvalid,
                Some("$.output".to_owned()),
                format!("runner output is not valid JSON: {error}"),
            )
        })?;
        validate_schema_value(
            &running.output_schema,
            &output,
            RuntimeErrorKind::OutputInvalid,
            "$.output",
        )?;
        let _isolation_guard = running.temporary_directory;
        Ok(ExecutionResult {
            identifiers: running.request.identifiers,
            status: ExecutionStatus::Succeeded,
            output: Some(output),
            exit_code: Some(0),
            duration_ms: running.started.elapsed().as_millis(),
        })
    }

    async fn cancel(&self, run_id: &str) -> Result<(), RuntimeError> {
        let runs = self.runs.lock().await;
        let control = runs.get(run_id).ok_or_else(|| {
            RuntimeError::new(
                RuntimeErrorKind::Cancelled,
                Some("$.identifiers.runId".to_owned()),
                "run is not active",
            )
        })?;
        let _ = control.reason.compare_exchange(
            CANCEL_NONE,
            CANCEL_USER,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        control.cancellation.cancel();
        Ok(())
    }
}

enum WaitResult {
    Exited(std::io::Result<std::process::ExitStatus>),
    TimedOut,
    Cancelled,
}

async fn read_stdout<R>(
    reader: R,
    count: Arc<AtomicUsize>,
    limit: usize,
    cancellation: ExecutionCancellation,
    reason: Arc<AtomicU8>,
) -> Result<Vec<u8>, ReadError>
where
    R: AsyncRead + Unpin,
{
    read_bounded(reader, count, limit, cancellation, reason, true)
        .await
        .map(Option::unwrap_or_default)
}

async fn read_stderr<R>(
    reader: R,
    count: Arc<AtomicUsize>,
    limit: usize,
    cancellation: ExecutionCancellation,
    reason: Arc<AtomicU8>,
) -> Result<(), ReadError>
where
    R: AsyncRead + Unpin,
{
    read_bounded(reader, count, limit, cancellation, reason, false)
        .await
        .map(|_| ())
}

async fn read_bounded<R>(
    mut reader: R,
    count: Arc<AtomicUsize>,
    limit: usize,
    cancellation: ExecutionCancellation,
    reason: Arc<AtomicU8>,
    retain: bool,
) -> Result<Option<Vec<u8>>, ReadError>
where
    R: AsyncRead + Unpin,
{
    let mut retained = retain.then(Vec::new);
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer).await.map_err(ReadError::Io)?;
        if read == 0 {
            return Ok(retained);
        }
        let previous = count.fetch_add(read, Ordering::SeqCst);
        if previous.saturating_add(read) > limit {
            let _ = reason.compare_exchange(
                CANCEL_NONE,
                CANCEL_OUTPUT_LIMIT,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
            cancellation.cancel();
            return Err(ReadError::Limit);
        }
        if let Some(bytes) = &mut retained {
            bytes.extend_from_slice(&buffer[..read]);
        }
    }
}

async fn join_stdout(
    handle: JoinHandle<Result<Vec<u8>, ReadError>>,
) -> Result<Vec<u8>, RuntimeError> {
    match handle.await {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(ReadError::Limit)) => Err(RuntimeError::new(
            RuntimeErrorKind::OutputLimit,
            Some("$.manifest.spec.runtime.outputLimitBytes".to_owned()),
            "combined runner output exceeded the configured limit",
        )),
        Ok(Err(ReadError::Io(error))) => Err(RuntimeError::new(
            RuntimeErrorKind::Process,
            None,
            format!("failed to read runner stdout: {error}"),
        )),
        Err(error) => Err(RuntimeError::new(
            RuntimeErrorKind::System,
            None,
            format!("stdout reader task failed: {error}"),
        )),
    }
}

async fn join_stderr(handle: JoinHandle<Result<(), ReadError>>) -> Result<(), RuntimeError> {
    match handle.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(ReadError::Limit)) => Err(RuntimeError::new(
            RuntimeErrorKind::OutputLimit,
            Some("$.manifest.spec.runtime.outputLimitBytes".to_owned()),
            "combined runner output exceeded the configured limit",
        )),
        Ok(Err(ReadError::Io(error))) => Err(RuntimeError::new(
            RuntimeErrorKind::Process,
            None,
            format!("failed to read runner stderr: {error}"),
        )),
        Err(error) => Err(RuntimeError::new(
            RuntimeErrorKind::System,
            None,
            format!("stderr reader task failed: {error}"),
        )),
    }
}

fn canonical_directory(path: &Path, field: &str) -> Result<PathBuf, RuntimeError> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        RuntimeError::new(
            RuntimeErrorKind::InvalidPath,
            Some(field.to_owned()),
            format!("directory cannot be resolved: {error}"),
        )
    })?;
    if !canonical.is_dir() {
        return Err(RuntimeError::new(
            RuntimeErrorKind::InvalidPath,
            Some(field.to_owned()),
            "path is not a directory",
        ));
    }
    Ok(canonical)
}

fn resolve_runner(plugin_root: &Path, entrypoint: &str) -> Result<PathBuf, RuntimeError> {
    let relative = Path::new(entrypoint);
    if !safe_relative_path(relative)
        || !relative.starts_with("runner")
        || relative.components().count() < 2
    {
        return Err(RuntimeError::new(
            RuntimeErrorKind::InvalidPath,
            Some("$.manifest.spec.runtime.entrypoint".to_owned()),
            "entrypoint must be a relative path beneath runner/",
        ));
    }
    let executable = fs::canonicalize(plugin_root.join(relative)).map_err(|error| {
        RuntimeError::new(
            RuntimeErrorKind::RunnerUnavailable,
            Some("$.manifest.spec.runtime.entrypoint".to_owned()),
            format!("runner cannot be resolved: {error}"),
        )
    })?;
    let runner_root = fs::canonicalize(plugin_root.join("runner")).map_err(|error| {
        RuntimeError::new(
            RuntimeErrorKind::RunnerUnavailable,
            Some("$.manifest.spec.runtime.entrypoint".to_owned()),
            format!("runner directory cannot be resolved: {error}"),
        )
    })?;
    if !executable.starts_with(&runner_root) || !executable.is_file() {
        return Err(RuntimeError::new(
            RuntimeErrorKind::InvalidPath,
            Some("$.manifest.spec.runtime.entrypoint".to_owned()),
            "runner path escapes runner/ or is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&executable)
            .map_err(|error| {
                RuntimeError::new(
                    RuntimeErrorKind::RunnerUnavailable,
                    Some("$.manifest.spec.runtime.entrypoint".to_owned()),
                    format!("runner metadata is unavailable: {error}"),
                )
            })?
            .permissions()
            .mode();
        if mode & 0o111 == 0 {
            return Err(RuntimeError::new(
                RuntimeErrorKind::RunnerUnavailable,
                Some("$.manifest.spec.runtime.entrypoint".to_owned()),
                "runner is not executable",
            ));
        }
    }
    Ok(executable)
}

fn resolve_regular_file(
    plugin_root: &Path,
    relative: &str,
    field: &str,
) -> Result<PathBuf, RuntimeError> {
    let relative = Path::new(relative);
    if !safe_relative_path(relative) {
        return Err(RuntimeError::new(
            RuntimeErrorKind::InvalidPath,
            Some(field.to_owned()),
            "path must be relative without parent traversal",
        ));
    }
    let canonical = fs::canonicalize(plugin_root.join(relative)).map_err(|error| {
        RuntimeError::new(
            RuntimeErrorKind::InvalidPath,
            Some(field.to_owned()),
            format!("path cannot be resolved: {error}"),
        )
    })?;
    if !canonical.starts_with(plugin_root) || !canonical.is_file() {
        return Err(RuntimeError::new(
            RuntimeErrorKind::InvalidPath,
            Some(field.to_owned()),
            "path escapes the plugin root or is not a regular file",
        ));
    }
    Ok(canonical)
}

fn safe_relative_path(path: &Path) -> bool {
    !path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::RootDir))
}

fn read_json(path: &Path, field: &str) -> Result<Value, RuntimeError> {
    let bytes = fs::read(path).map_err(|error| {
        RuntimeError::new(
            RuntimeErrorKind::System,
            Some(field.to_owned()),
            format!("failed to read JSON Schema: {error}"),
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        RuntimeError::new(
            RuntimeErrorKind::System,
            Some(field.to_owned()),
            format!("invalid JSON Schema document: {error}"),
        )
    })
}

fn validate_instance(
    schema_path: &Path,
    instance: &Value,
    kind: RuntimeErrorKind,
) -> Result<(), RuntimeError> {
    let schema = read_json(schema_path, "$.schema")?;
    validate_schema_value(&schema, instance, kind, "$.input")
}

fn validate_schema_value(
    schema: &Value,
    instance: &Value,
    kind: RuntimeErrorKind,
    field: &str,
) -> Result<(), RuntimeError> {
    let compiled = JSONSchema::compile(schema).map_err(|error| {
        RuntimeError::new(
            RuntimeErrorKind::System,
            Some("$.schema".to_owned()),
            format!("JSON Schema cannot be compiled: {error}"),
        )
    })?;
    if let Err(errors) = compiled.validate(instance) {
        let messages = errors
            .map(|error| format!("${}: {error}", error.instance_path))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(RuntimeError::new(kind, Some(field.to_owned()), messages));
    }
    Ok(())
}

async fn terminate_process_group(child: &mut Child, child_id: Option<u32>) {
    #[cfg(unix)]
    if let Some(id) = child_id {
        use nix::sys::signal::{Signal, killpg};
        use nix::unistd::Pid;
        if let Ok(id) = i32::try_from(id) {
            let _ = killpg(Pid::from_raw(id), Signal::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill().await;
    }
    let _ = child.wait().await;
}

fn validate_execution_identity(request: &ExecutionRequest) -> Result<(), RuntimeError> {
    if request.identifiers.tool_id != request.manifest.metadata.name {
        return Err(RuntimeError::new(
            RuntimeErrorKind::PolicyDenied,
            Some("$.identifiers.toolId".to_owned()),
            "tool identifier does not match the Manifest",
        ));
    }
    if request.manifest.spec.runtime.mode != RuntimeMode::Process {
        return Err(RuntimeError::new(
            RuntimeErrorKind::PolicyDenied,
            Some("$.manifest.spec.runtime.mode".to_owned()),
            "Command Adapter only supports process mode",
        ));
    }
    if request.manifest.spec.runtime.adapter != AdapterKind::Command {
        return Err(RuntimeError::new(
            RuntimeErrorKind::PolicyDenied,
            Some("$.manifest.spec.runtime.adapter".to_owned()),
            "Command Adapter only accepts command manifests",
        ));
    }
    Ok(())
}

fn validate_execution_files(
    request: &ExecutionRequest,
    plugin_root: &Path,
) -> Result<(PathBuf, Value), RuntimeError> {
    let entrypoint = request
        .manifest
        .spec
        .runtime
        .entrypoint
        .as_deref()
        .ok_or_else(|| {
            RuntimeError::new(
                RuntimeErrorKind::RunnerUnavailable,
                Some("$.manifest.spec.runtime.entrypoint".to_owned()),
                "runner entrypoint is not declared",
            )
        })?;
    let executable = resolve_runner(plugin_root, entrypoint)?;
    let input_schema = resolve_regular_file(
        plugin_root,
        &request.manifest.spec.input_schema,
        "$.manifest.spec.inputSchema",
    )?;
    let output_schema_path = resolve_regular_file(
        plugin_root,
        &request.manifest.spec.output_schema,
        "$.manifest.spec.outputSchema",
    )?;
    validate_instance(
        &input_schema,
        &request.input,
        RuntimeErrorKind::InputInvalid,
    )?;
    let output_schema = read_json(&output_schema_path, "$.manifest.spec.outputSchema")?;
    Ok((executable, output_schema))
}

fn encode_input(input: &Value) -> Result<Vec<u8>, RuntimeError> {
    serde_json::to_vec(input).map_err(|error| {
        RuntimeError::new(
            RuntimeErrorKind::InputInvalid,
            Some("$.input".to_owned()),
            format!("input cannot be encoded as JSON: {error}"),
        )
    })
}

fn isolated_directory() -> Result<TempDir, RuntimeError> {
    tempfile::Builder::new()
        .prefix("sentinelflow-run-")
        .tempdir()
        .map_err(|error| {
            RuntimeError::new(
                RuntimeErrorKind::System,
                Some("$.runtime.temporaryDirectory".to_owned()),
                format!("failed to create isolated temporary directory: {error}"),
            )
        })
}

fn build_environment(
    candidates: &RuntimeEnvironment,
    request: &ExecutionRequest,
    authorization_scope: &str,
) -> BTreeMap<String, String> {
    let mut environment = BTreeMap::new();
    for name in &request.manifest.spec.runtime.environment_allowlist {
        if let Some(value) = candidates.values.get(name) {
            environment.insert(name.clone(), value.clone());
        }
    }
    for (name, value) in [
        ("SENTINELFLOW_TASK_ID", &request.identifiers.task_id),
        ("SENTINELFLOW_RUN_ID", &request.identifiers.run_id),
        ("SENTINELFLOW_STEP_ID", &request.identifiers.step_id),
        ("SENTINELFLOW_TOOL_ID", &request.identifiers.tool_id),
        (
            "SENTINELFLOW_CORRELATION_ID",
            &request.identifiers.correlation_id,
        ),
    ] {
        environment.insert(name.to_owned(), value.clone());
    }
    environment.insert(
        "SENTINELFLOW_AUTHORIZATION_SCOPE".to_owned(),
        authorization_scope.to_owned(),
    );
    environment
}
