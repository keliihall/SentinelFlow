//! CLI command dispatch.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::env;
use std::fs;
use std::time::{Duration, Instant};

use sentinelflow_adapter_command::CommandAdapter;
use sentinelflow_adapter_docker::DockerAdapter;
use sentinelflow_adapter_file_import::FileImportAdapter;
use sentinelflow_adapter_http::HttpAdapter;
use sentinelflow_orchestrator::plan;
use sentinelflow_policy::{ApprovalRecord, ApprovalStatus, TaskPolicyRequest, evaluate_task};
use sentinelflow_registry::{
    InstallOutcome, RegistryError, ToolRegistry, discover_plugins, install_plugin, validate_plugin,
};
use sentinelflow_report::{generate_markdown, generate_task_markdown};
use sentinelflow_runtime::{
    Adapter, ExecutionIdentifiers, ExecutionRequest, ExecutionResult, ExecutionStatus,
    ParserContext, ParserInput, RawOutputReference, RuntimeEnvironment, RuntimeError,
    RuntimeErrorKind, builtin_parser, normalize,
};
use sentinelflow_schema::v1alpha1::{
    AdapterKind, AuditOutcome, FailurePolicy, RiskLevel, TaskSpec, TaskStepSpec, TaskTargetSpec,
    ToolManifest, Validate, ValidationContext, from_json_slice,
};
use sentinelflow_store::{AuditContext, ResultArtifact, RunArtifact, WorkspaceStore, now_rfc3339};
use sentinelflow_store::{TaskArtifact, TaskStatus, TaskStepStatus};
use tokio::task::JoinSet;

use crate::cli::{
    ApprovalCommand, ApprovalDecisionArguments, ApprovalRequestArguments, AuditCommand, Command,
    ConfigCommand, ExportFormat, FileArgument, PathArgument, PluginCommand, PolicyCommand,
    PolicyExplainArguments, ReportCommand, ReportGenerateArguments, ResultCommand,
    ResultExportArguments, RiskArgument, TaskCommand, TaskIdArgument, TaskRunArguments,
    ToolCommand, ToolRunArguments,
};
use crate::config::{self, ConfigOverrides};
use crate::workspace;
use crate::{Cli, CliError};

/// Dispatches one parsed command.
pub async fn execute(cli: Cli) -> Result<(), CliError> {
    let overrides = ConfigOverrides {
        workspace_dir: cli.workspace,
        schema_root: cli.schema_root,
        log_level: cli.log_level,
        api_endpoint: cli.api_endpoint,
        auth_token: cli.auth_token,
    };

    match cli.command {
        Command::Init => {
            let workspace_dir = config::bootstrap_workspace(&overrides);
            workspace::initialize(&workspace_dir)?;
            println!(
                "initialized SentinelFlow workspace at {}",
                workspace_dir.display()
            );
            Ok(())
        }
        Command::Config {
            command: ConfigCommand::Show,
        } => show_config(overrides),
        Command::Tool {
            command: ToolCommand::Validate(argument),
        } => validate_resource::<ToolManifest>(&argument, overrides, "ToolManifest"),
        Command::Task {
            command: TaskCommand::Validate(argument),
        } => validate_task_command(&argument, overrides),
        Command::Task {
            command: TaskCommand::Plan(argument),
        } => plan_task_command(&argument, overrides),
        Command::Task {
            command: TaskCommand::Run(arguments),
        } => run_task(&arguments, overrides).await,
        Command::Task {
            command: TaskCommand::Status(arguments),
        } => task_status(&arguments, overrides),
        Command::Task {
            command: TaskCommand::Logs(arguments),
        } => task_logs(&arguments, overrides),
        Command::Task {
            command: TaskCommand::Cancel(arguments),
        } => cancel_task(&arguments, overrides),
        Command::Task {
            command: TaskCommand::Pause(arguments),
        } => pause_task(&arguments, overrides),
        Command::Task {
            command: TaskCommand::Resume(arguments),
        } => resume_task(&arguments, overrides).await,
        Command::Plugin {
            command: PluginCommand::Scaffold(argument),
        } => scaffold_plugin(&argument),
        Command::Plugin {
            command: PluginCommand::Test(argument),
        } => test_plugin(&argument, overrides).await,
        Command::Plugin {
            command: PluginCommand::Validate(argument),
        } => validate_plugin_command(&argument),
        Command::Plugin {
            command: PluginCommand::Install(argument),
        } => install_plugin_command(&argument, overrides),
        Command::Tool {
            command: ToolCommand::List,
        } => list_tools(overrides),
        Command::Tool {
            command: ToolCommand::Info { name },
        } => show_tool(&name, overrides),
        Command::Tool {
            command: ToolCommand::Run(arguments),
        } => run_tool(&arguments, overrides).await,
        Command::Report {
            command: ReportCommand::Generate(arguments),
        } => generate_report(&arguments, overrides),
        Command::Audit {
            command: AuditCommand::List,
        } => list_audit(overrides),
        Command::Policy {
            command: PolicyCommand::Explain(arguments),
        } => explain_policy(&arguments, overrides),
        Command::Approval {
            command: ApprovalCommand::Request(arguments),
        } => request_approval(&arguments, overrides),
        Command::Approval {
            command: ApprovalCommand::Approve(arguments),
        } => decide_approval(&arguments, overrides, ApprovalStatus::Approved),
        Command::Approval {
            command: ApprovalCommand::Reject(arguments),
        } => decide_approval(&arguments, overrides, ApprovalStatus::Rejected),
        Command::Approval {
            command: ApprovalCommand::Expire(arguments),
        } => decide_approval(&arguments, overrides, ApprovalStatus::Expired),
        Command::Result {
            command: ResultCommand::Export(arguments),
        } => export_result(&arguments, overrides),
        command => Err(CliError::not_implemented(command_name(&command))),
    }
}

#[allow(clippy::too_many_lines)]
async fn run_tool(
    arguments: &ToolRunArguments,
    overrides: ConfigOverrides,
) -> Result<(), CliError> {
    let config = config::load(overrides)?;
    workspace::initialize(&config.workspace_dir)?;
    let identifiers = ExecutionIdentifiers::generate(&arguments.tool);
    let context = AuditContext {
        identifiers: &identifiers,
        actor_id: &arguments.actor_id,
    };
    let mut store = open_store(&config.workspace_dir)?;
    store
        .record_audit(
            "tool.run.requested",
            AuditOutcome::Allowed,
            Some(&context),
            Some(identifiers.tool_id.clone()),
        )
        .map_err(store_error)?;
    let started_at = now_rfc3339().map_err(store_error)?;
    let clock = Instant::now();
    let execution = run_tool_inner(
        arguments,
        &config.workspace_dir,
        identifiers.clone(),
        &mut store,
        &context,
    )
    .await;

    let (execution, manifest, capability) = match execution {
        Ok(value) => value,
        Err(error) => {
            persist_failed_run(
                arguments,
                &identifiers,
                &started_at,
                clock.elapsed().as_millis(),
                &error,
                &mut store,
                &context,
            )?;
            return Err(error);
        }
    };

    store
        .record_audit(
            "tool.run.finished",
            AuditOutcome::Succeeded,
            Some(&context),
            Some(identifiers.run_id.clone()),
        )
        .map_err(store_error)?;
    let raw = execution.output.as_ref().ok_or_else(|| {
        CliError::runtime(
            "successful execution did not provide output",
            Some("$.execution.output".to_owned()),
        )
    })?;
    let parser_input = ParserInput {
        raw: RawOutputReference {
            run_id: &identifiers.run_id,
            value: raw,
        },
        context: ParserContext {
            identifiers: &identifiers,
            actor_id: &arguments.actor_id,
        },
    };
    let normalized = builtin_parser(&manifest.spec.parser.name)
        .and_then(|parser| normalize(parser.as_ref(), &parser_input, &manifest.spec.output_schema));
    let finished_at = now_rfc3339().map_err(store_error)?;
    match normalized {
        Ok(output) => {
            let run = completed_run(
                arguments,
                &identifiers,
                &started_at,
                &finished_at,
                &execution,
                &capability,
            );
            store.save_run(&run).map_err(store_error)?;
            store
                .save_result(&ResultArtifact {
                    run_id: identifiers.run_id.clone(),
                    output: Some(output.clone()),
                    errors: Vec::new(),
                })
                .map_err(store_error)?;
            store
                .record_audit(
                    "result.normalized",
                    AuditOutcome::Succeeded,
                    Some(&context),
                    Some(identifiers.run_id.clone()),
                )
                .map_err(store_error)?;
            let receipt = serde_json::json!({
                "identifiers": execution.identifiers,
                "status": execution.status,
                "output": output,
                "exitCode": execution.exit_code,
                "durationMs": execution.duration_ms
            });
            let rendered = serde_json::to_string_pretty(&receipt).map_err(|error| {
                CliError::system(
                    format!("failed to serialize execution receipt: {error}"),
                    Some("$.result".to_owned()),
                )
            })?;
            println!("{rendered}");
            Ok(())
        }
        Err(error) => {
            let cli_error = CliError::schema(
                error.error.error.message.clone(),
                error.error.error.field.clone(),
            );
            let run = RunArtifact {
                identifiers: identifiers.clone(),
                actor_id: arguments.actor_id.clone(),
                authorization_scope: arguments.authorization_scope.clone().unwrap_or_default(),
                capability: manifest
                    .spec
                    .capabilities
                    .first()
                    .map_or_else(|| "unknown".to_owned(), |item| item.name.clone()),
                target: arguments.target.clone(),
                status: ExecutionStatus::Failed,
                started_at,
                finished_at,
                duration_ms: execution.duration_ms,
                exit_code: execution.exit_code,
            };
            store.save_run(&run).map_err(store_error)?;
            store
                .save_result(&ResultArtifact {
                    run_id: identifiers.run_id.clone(),
                    output: None,
                    errors: vec![error.error],
                })
                .map_err(store_error)?;
            store
                .record_audit(
                    "result.normalized",
                    AuditOutcome::Failed,
                    Some(&context),
                    Some(identifiers.run_id.clone()),
                )
                .map_err(store_error)?;
            store
                .record_audit(
                    "tool.run.failed",
                    AuditOutcome::Failed,
                    Some(&context),
                    Some(identifiers.run_id.clone()),
                )
                .map_err(store_error)?;
            Err(cli_error)
        }
    }
}

async fn run_tool_inner(
    arguments: &ToolRunArguments,
    workspace_dir: &std::path::Path,
    identifiers: ExecutionIdentifiers,
    store: &mut WorkspaceStore,
    context: &AuditContext<'_>,
) -> Result<(ExecutionResult, ToolManifest, String), CliError> {
    let input_bytes = fs::read(&arguments.input).map_err(|error| {
        CliError::system(
            format!("failed to read {}: {error}", arguments.input.display()),
            Some("$.input".to_owned()),
        )
    })?;
    let input = serde_json::from_slice(&input_bytes).map_err(|error| {
        CliError::schema(
            format!("input is not valid JSON: {error}"),
            Some("$.input".to_owned()),
        )
    })?;
    let registry = load_registry(&workspace_dir.join("plugins"))?;
    let tool = registry.get(&arguments.tool).cloned().ok_or_else(|| {
        CliError::runtime(
            format!("tool is not registered: {}", arguments.tool),
            Some("$.tool".to_owned()),
        )
    })?;
    let capability = tool
        .manifest
        .spec
        .capabilities
        .first()
        .ok_or_else(|| {
            CliError::schema(
                "tool does not declare a capability",
                Some("$.manifest.spec.capabilities".to_owned()),
            )
        })?
        .name
        .clone();
    execute_registered_tool(
        tool,
        capability,
        input,
        arguments.authorization_scope.clone(),
        arguments.approve_high_risk,
        arguments.timeout_seconds,
        identifiers,
        store,
        context,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn execute_registered_tool(
    tool: sentinelflow_registry::RegisteredTool,
    capability: String,
    input: serde_json::Value,
    authorization_scope: Option<String>,
    approved: bool,
    timeout_seconds: Option<u64>,
    identifiers: ExecutionIdentifiers,
    store: &mut WorkspaceStore,
    context: &AuditContext<'_>,
) -> Result<(ExecutionResult, ToolManifest, String), CliError> {
    store.save_tool(&tool.manifest).map_err(store_error)?;
    let timeout =
        Duration::from_secs(timeout_seconds.unwrap_or(tool.manifest.spec.runtime.timeout_seconds));
    let request = ExecutionRequest {
        identifiers: identifiers.clone(),
        plugin_root: tool.plugin_root.clone(),
        manifest: tool.manifest.clone(),
        capability: capability.clone(),
        input,
        authorization_scope,
        approved,
        timeout,
    };
    let result = match request.manifest.spec.runtime.adapter {
        AdapterKind::Command => {
            let environment = RuntimeEnvironment {
                values: request
                    .manifest
                    .spec
                    .runtime
                    .environment_allowlist
                    .iter()
                    .filter_map(|name| env::var(name).ok().map(|value| (name.clone(), value)))
                    .collect::<BTreeMap<_, _>>(),
            };
            execute_with_adapter(
                &CommandAdapter::with_environment(environment),
                request,
                &identifiers.run_id,
                store,
                context,
            )
            .await?
        }
        AdapterKind::Docker => {
            execute_with_adapter(
                &DockerAdapter::default(),
                request,
                &identifiers.run_id,
                store,
                context,
            )
            .await?
        }
        AdapterKind::Http => {
            execute_with_adapter(
                &HttpAdapter::default(),
                request,
                &identifiers.run_id,
                store,
                context,
            )
            .await?
        }
        AdapterKind::FileImport => {
            execute_with_adapter(
                &FileImportAdapter,
                request,
                &identifiers.run_id,
                store,
                context,
            )
            .await?
        }
    };
    Ok((result, tool.manifest, capability))
}

async fn execute_with_adapter<A: Adapter>(
    adapter: &A,
    request: ExecutionRequest,
    run_id: &str,
    store: &mut WorkspaceStore,
    context: &AuditContext<'_>,
) -> Result<ExecutionResult, CliError> {
    let prepared = adapter.prepare(request).await.map_err(runtime_error)?;
    store
        .record_audit(
            "tool.run.started",
            AuditOutcome::Allowed,
            Some(context),
            Some(run_id.to_owned()),
        )
        .map_err(store_error)?;
    let running = adapter.execute(prepared).await.map_err(runtime_error)?;
    let collection = adapter.collect(running);
    tokio::pin!(collection);

    tokio::select! {
        result = &mut collection => result.map_err(runtime_error),
        signal = tokio::signal::ctrl_c() => {
            signal.map_err(|error| CliError::system(
                format!("failed to listen for cancellation: {error}"),
                None,
            ))?;
            adapter.cancel(run_id).await.map_err(runtime_error)?;
            collection.await.map_err(runtime_error)
        }
    }
}

async fn run_task(
    arguments: &TaskRunArguments,
    overrides: ConfigOverrides,
) -> Result<(), CliError> {
    let config = config::load(overrides)?;
    workspace::initialize(&config.workspace_dir)?;
    let task = read_task_spec(&arguments.file, &config.schema_root)?;
    let task_plan =
        plan(&task).map_err(|error| CliError::schema(error.message, Some(error.field)))?;
    let task_id = ExecutionIdentifiers::generate(&task.metadata.name).task_id;
    let mut store = open_store(&config.workspace_dir)?;
    let step_states = task
        .spec
        .targets
        .iter()
        .flat_map(|target| {
            task.spec
                .steps
                .iter()
                .map(move |step| (unit_key(&target.name, &step.name), TaskStepStatus::Pending))
        })
        .collect();
    let mut task_artifact = TaskArtifact {
        task_id: task_id.clone(),
        name: task.metadata.name.clone(),
        actor_id: arguments.actor_id.clone(),
        tool_id: task
            .spec
            .steps
            .iter()
            .map(|step| step.tool_ref.as_str())
            .collect::<Vec<_>>()
            .join(","),
        status: TaskStatus::Pending,
        target_count: task.spec.targets.len(),
        run_ids: Vec::new(),
        spec_snapshot: task,
        plan_snapshot: serde_json::to_value(task_plan).map_err(|error| {
            CliError::system(
                format!("failed to snapshot task plan: {error}"),
                Some("$.task.plan".to_owned()),
            )
        })?,
        step_states,
        outputs: BTreeMap::new(),
        started_at: now_rfc3339().map_err(store_error)?,
        finished_at: None,
        last_error: None,
    };
    record_task_state(&mut store, &task_artifact, TaskStatus::Pending, None)?;
    task_artifact.status = TaskStatus::Planning;
    record_task_state(&mut store, &task_artifact, TaskStatus::Planning, None)?;
    schedule_task(task_artifact, &config.workspace_dir).await
}

#[derive(Debug)]
struct UnitResult {
    key: String,
    step_name: String,
    output_alias: Option<String>,
    run_id: String,
    result: Result<(), CliError>,
}

#[allow(clippy::too_many_lines)]
async fn schedule_task(
    mut artifact: TaskArtifact,
    workspace_dir: &std::path::Path,
) -> Result<(), CliError> {
    let task = artifact.spec_snapshot.clone();
    let current_plan = match plan(&task) {
        Ok(plan) => plan,
        Err(error) => {
            let cli_error = CliError::schema(error.message, Some(error.field));
            mark_task_failed(workspace_dir, &mut artifact, &cli_error)?;
            return Err(cli_error);
        }
    };
    let current_snapshot = serde_json::to_value(current_plan).map_err(|error| {
        CliError::system(
            format!("failed to verify plan snapshot: {error}"),
            Some("$.task.plan".to_owned()),
        )
    })?;
    if current_snapshot != artifact.plan_snapshot {
        let error = CliError::system(
            "persisted Task Spec and plan snapshot do not match",
            Some("$.task.planSnapshot".to_owned()),
        );
        mark_task_failed(workspace_dir, &mut artifact, &error)?;
        return Err(error);
    }
    if open_store(workspace_dir)?
        .load_task(&artifact.task_id)
        .map_err(store_error)?
        .status
        == TaskStatus::Cancelling
    {
        artifact.status = TaskStatus::Cancelled;
        for status in artifact.step_states.values_mut() {
            if *status == TaskStepStatus::Pending {
                *status = TaskStepStatus::Cancelled;
            }
        }
        artifact.finished_at = Some(now_rfc3339().map_err(store_error)?);
        let error = CliError::runtime(
            "task was cancelled before execution",
            Some("$.task".to_owned()),
        );
        artifact.last_error = Some(error.to_standard_error());
        open_store(workspace_dir)?
            .save_task(&artifact)
            .map_err(store_error)?;
        record_task_state_audit(
            &mut open_store(workspace_dir)?,
            TaskStatus::Cancelled,
            AuditOutcome::Succeeded,
            &artifact.task_id,
        )?;
        return Err(error);
    }
    if open_store(workspace_dir)?
        .load_task(&artifact.task_id)
        .map_err(store_error)?
        .status
        == TaskStatus::Paused
    {
        artifact.status = TaskStatus::Paused;
        open_store(workspace_dir)?
            .save_task(&artifact)
            .map_err(store_error)?;
        record_task_state_audit(
            &mut open_store(workspace_dir)?,
            TaskStatus::Paused,
            AuditOutcome::Allowed,
            &artifact.task_id,
        )?;
        return Ok(());
    }
    if let Err(error) = preflight_task_policy(&task, workspace_dir) {
        let mut store = open_store(workspace_dir)?;
        let lowered_error = error.to_string().to_ascii_lowercase();
        artifact.status =
            if lowered_error.contains("approval") || lowered_error.contains("approved") {
                TaskStatus::ApprovalRequired
            } else {
                TaskStatus::Failed
            };
        artifact.finished_at = Some(now_rfc3339().map_err(store_error)?);
        artifact.last_error = Some(error.to_standard_error());
        store.save_task(&artifact).map_err(store_error)?;
        record_task_state_audit(
            &mut store,
            artifact.status,
            if artifact.status == TaskStatus::ApprovalRequired {
                AuditOutcome::Denied
            } else {
                AuditOutcome::Failed
            },
            &artifact.task_id,
        )?;
        store
            .record_audit(
                "policy.denied",
                AuditOutcome::Denied,
                None,
                Some(artifact.task_id.clone()),
            )
            .map_err(store_error)?;
        return Err(error);
    }
    artifact.status = TaskStatus::Running;
    record_task_state(
        &mut open_store(workspace_dir)?,
        &artifact,
        TaskStatus::Running,
        None,
    )?;

    let mut starts = VecDeque::new();
    let mut first_error = None;
    loop {
        let persisted = open_store(workspace_dir)?
            .load_task(&artifact.task_id)
            .map_err(store_error)?;
        if persisted.status == TaskStatus::Cancelling {
            artifact.status = TaskStatus::Cancelled;
            for status in artifact.step_states.values_mut() {
                if matches!(status, TaskStepStatus::Pending | TaskStepStatus::Running) {
                    *status = TaskStepStatus::Cancelled;
                }
            }
            artifact.finished_at = Some(now_rfc3339().map_err(store_error)?);
            let error = CliError::runtime("task was cancelled", Some("$.task".to_owned()));
            artifact.last_error = Some(error.to_standard_error());
            open_store(workspace_dir)?
                .save_task(&artifact)
                .map_err(store_error)?;
            record_task_state_audit(
                &mut open_store(workspace_dir)?,
                TaskStatus::Cancelled,
                AuditOutcome::Succeeded,
                &artifact.task_id,
            )?;
            return Err(error);
        }
        if persisted.status == TaskStatus::Paused {
            artifact.status = TaskStatus::Paused;
            open_store(workspace_dir)?
                .save_task(&artifact)
                .map_err(store_error)?;
            record_task_state_audit(
                &mut open_store(workspace_dir)?,
                TaskStatus::Paused,
                AuditOutcome::Allowed,
                &artifact.task_id,
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&artifact).map_err(|error| {
                    CliError::system(
                        format!("failed to serialize paused task: {error}"),
                        Some("$.task".to_owned()),
                    )
                })?
            );
            return Ok(());
        }

        propagate_dependency_failures(&task, &mut artifact);
        let mut ready = ready_units(&task, &artifact);
        if ready.is_empty() {
            if artifact
                .step_states
                .values()
                .any(|status| matches!(status, TaskStepStatus::Pending | TaskStepStatus::Running))
            {
                let error = CliError::runtime(
                    "task scheduler reached a state with no ready nodes",
                    Some("$.task.stepStates".to_owned()),
                );
                mark_task_failed(workspace_dir, &mut artifact, &error)?;
                return Err(error);
            }
            break;
        }

        while starts
            .front()
            .is_some_and(|started: &Instant| started.elapsed() >= Duration::from_secs(60))
        {
            starts.pop_front();
        }
        let rate_limit =
            usize::try_from(task.spec.policy.rate_limit_per_minute).unwrap_or(usize::MAX);
        if starts.len() >= rate_limit {
            let delay = Duration::from_secs(60)
                .saturating_sub(starts.front().expect("rate queue is non-empty").elapsed());
            tokio::time::sleep(delay).await;
            continue;
        }
        let available_rate = rate_limit.saturating_sub(starts.len());
        ready.truncate(task.spec.policy.max_concurrency.min(available_rate));

        let mut joins = JoinSet::new();
        for (target, step) in ready {
            let key = unit_key(&target.name, &step.name);
            let input = mapped_step_input(workspace_dir, &task, &artifact, target, step)?;
            let mut identifiers = ExecutionIdentifiers::generate(&step.tool_ref);
            identifiers.task_id.clone_from(&artifact.task_id);
            artifact.run_ids.push(identifiers.run_id.clone());
            artifact
                .step_states
                .insert(key.clone(), TaskStepStatus::Running);
            open_store(workspace_dir)?
                .save_task(&artifact)
                .map_err(store_error)?;
            starts.push_back(Instant::now());
            joins.spawn(execute_task_unit(
                workspace_dir.to_path_buf(),
                task.clone(),
                target.clone(),
                step.clone(),
                input,
                identifiers,
                artifact.actor_id.clone(),
            ));
        }

        while let Some(joined) = joins.join_next().await {
            let outcome = joined.map_err(|error| {
                CliError::system(
                    format!("scheduler worker failed: {error}"),
                    Some("$.task.scheduler".to_owned()),
                )
            })?;
            match outcome.result {
                Ok(()) => {
                    artifact
                        .step_states
                        .insert(outcome.key.clone(), TaskStepStatus::Completed);
                    artifact
                        .outputs
                        .insert(outcome.key.clone(), outcome.run_id.clone());
                    if let Some(alias) = outcome.output_alias {
                        let target = outcome.key.split_once('/').map_or("", |(target, _)| target);
                        artifact
                            .outputs
                            .insert(unit_key(target, &alias), outcome.run_id);
                    }
                }
                Err(error) => {
                    let cancelled = error.to_string().contains("cancel");
                    artifact.step_states.insert(
                        outcome.key,
                        if cancelled {
                            TaskStepStatus::Cancelled
                        } else {
                            TaskStepStatus::Failed
                        },
                    );
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                    let failure_policy = task
                        .spec
                        .steps
                        .iter()
                        .find(|step| step.name == outcome.step_name)
                        .map_or(FailurePolicy::Stop, |step| step.failure_policy);
                    if failure_policy == FailurePolicy::Stop {
                        for status in artifact.step_states.values_mut() {
                            if *status == TaskStepStatus::Pending {
                                *status = TaskStepStatus::Skipped;
                            }
                        }
                    }
                }
            }
            let external_status = open_store(workspace_dir)?
                .load_task(&artifact.task_id)
                .map_err(store_error)?
                .status;
            if external_status == TaskStatus::Cancelling {
                artifact.status = TaskStatus::Cancelling;
            } else if external_status == TaskStatus::Paused {
                artifact.status = TaskStatus::Paused;
            }
            open_store(workspace_dir)?
                .save_task(&artifact)
                .map_err(store_error)?;
        }
    }

    artifact.status = if artifact
        .step_states
        .values()
        .any(|status| *status == TaskStepStatus::Cancelled)
    {
        TaskStatus::Cancelled
    } else if artifact
        .step_states
        .values()
        .any(|status| *status == TaskStepStatus::Failed)
    {
        TaskStatus::Failed
    } else {
        TaskStatus::Completed
    };
    artifact.finished_at = Some(now_rfc3339().map_err(store_error)?);
    artifact.last_error = first_error.as_ref().map(CliError::to_standard_error);
    let mut store = open_store(workspace_dir)?;
    store.save_task(&artifact).map_err(store_error)?;
    record_task_state_audit(
        &mut store,
        artifact.status,
        if artifact.status == TaskStatus::Failed {
            AuditOutcome::Failed
        } else {
            AuditOutcome::Succeeded
        },
        &artifact.task_id,
    )?;
    if task.spec.policy.output_retention.days == 0 {
        for run_id in artifact.outputs.values().collect::<BTreeSet<_>>() {
            store.purge_result(run_id).map_err(store_error)?;
        }
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&artifact).map_err(|error| {
            CliError::system(
                format!("failed to serialize task receipt: {error}"),
                Some("$.task".to_owned()),
            )
        })?
    );
    if let Some(error) = first_error {
        Err(error)
    } else {
        Ok(())
    }
}

async fn execute_task_unit(
    workspace_dir: std::path::PathBuf,
    task: TaskSpec,
    target: TaskTargetSpec,
    step: TaskStepSpec,
    input: serde_json::Value,
    identifiers: ExecutionIdentifiers,
    actor_id: String,
) -> UnitResult {
    let key = unit_key(&target.name, &step.name);
    let run_id = identifiers.run_id.clone();
    let result = execute_task_unit_inner(
        &workspace_dir,
        &task,
        &target,
        &step,
        input,
        &identifiers,
        &actor_id,
    )
    .await;
    UnitResult {
        key,
        step_name: step.name,
        output_alias: step.output_as,
        run_id,
        result,
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_task_unit_inner(
    workspace_dir: &std::path::Path,
    task: &TaskSpec,
    target: &TaskTargetSpec,
    step: &TaskStepSpec,
    input: serde_json::Value,
    identifiers: &ExecutionIdentifiers,
    actor_id: &str,
) -> Result<(), CliError> {
    let registry = load_registry(&workspace_dir.join("plugins"))?;
    let tool = registry.get(&step.tool_ref).cloned().ok_or_else(|| {
        CliError::runtime(
            format!("tool is not registered: {}", step.tool_ref),
            Some("$.spec.steps.toolRef".to_owned()),
        )
    })?;
    let mut store = open_store(workspace_dir)?;
    let context = AuditContext {
        identifiers,
        actor_id,
    };
    store
        .record_audit(
            "tool.run.requested",
            AuditOutcome::Allowed,
            Some(&context),
            Some(target.name.clone()),
        )
        .map_err(store_error)?;
    let started_at = now_rfc3339().map_err(store_error)?;
    let clock = Instant::now();
    match execute_registered_tool(
        tool,
        step.capability.clone(),
        input,
        Some(task.spec.authorization_scope.clone()),
        task.spec.policy.approve_high_risk
            || task_approval_status(task, workspace_dir)? == Some(ApprovalStatus::Approved),
        task.spec.policy.timeout_seconds,
        identifiers.clone(),
        &mut store,
        &context,
    )
    .await
    {
        Ok((execution, manifest, capability)) => persist_task_target_success(
            task,
            target,
            identifiers,
            &started_at,
            actor_id,
            &execution,
            &manifest,
            &capability,
            &mut store,
            &context,
        ),
        Err(error) => {
            persist_task_target_failure(
                task,
                target,
                &step.capability,
                identifiers,
                &started_at,
                clock.elapsed().as_millis(),
                actor_id,
                &error,
                &mut store,
                &context,
            )?;
            Err(error)
        }
    }
}

fn preflight_task_policy(task: &TaskSpec, workspace_dir: &std::path::Path) -> Result<(), CliError> {
    let registry = load_registry(&workspace_dir.join("plugins"))?;
    let utc_minute = current_utc_minute();
    for (target_index, target) in task.spec.targets.iter().enumerate() {
        for (step_index, step) in task.spec.steps.iter().enumerate() {
            let tool = registry.get(&step.tool_ref).ok_or_else(|| {
                CliError::runtime(
                    format!("tool is not registered: {}", step.tool_ref),
                    Some(format!("$.spec.steps[{step_index}].toolRef")),
                )
            })?;
            let risk = tool
                .manifest
                .spec
                .capabilities
                .iter()
                .find(|capability| capability.name == step.capability)
                .map(|capability| capability.risk)
                .ok_or_else(|| {
                    CliError::schema(
                        format!(
                            "tool {} does not declare capability {}",
                            step.tool_ref, step.capability
                        ),
                        Some(format!("$.spec.steps[{step_index}].capability")),
                    )
                })?;
            let decision = evaluate_task(&TaskPolicyRequest {
                authorization_scope: &task.spec.authorization_scope,
                target: &target.name,
                risk,
                approval: task_approval_status(task, workspace_dir)?,
                utc_minute,
                running_nodes: 0,
                starts_this_minute: 0,
                policy: &task.spec.policy,
            });
            if !decision.allowed {
                return Err(CliError::authorization(
                    decision.reasons.join("; "),
                    Some(format!("$.spec.targets[{target_index}]")),
                ));
            }
        }
    }
    Ok(())
}

fn task_approval_status(
    task: &TaskSpec,
    workspace_dir: &std::path::Path,
) -> Result<Option<ApprovalStatus>, CliError> {
    let Some(approval_ref) = &task.spec.policy.approval_ref else {
        return Ok(task
            .spec
            .policy
            .approve_high_risk
            .then_some(ApprovalStatus::Approved));
    };
    let approval = open_store(workspace_dir)?
        .load_approval(approval_ref)
        .map_err(store_error)?;
    if approval.resource_ref != task.metadata.name {
        return Err(CliError::authorization(
            "approval resource does not match the Task Spec",
            Some("$.spec.policy.approvalRef".to_owned()),
        ));
    }
    Ok(Some(approval.status))
}

fn current_utc_minute() -> u16 {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    u16::try_from((seconds / 60) % (24 * 60)).unwrap_or(0)
}

fn unit_key(target: &str, step: &str) -> String {
    format!("{target}/{step}")
}

fn propagate_dependency_failures(task: &TaskSpec, artifact: &mut TaskArtifact) {
    let mut changed = true;
    while changed {
        changed = false;
        for target in &task.spec.targets {
            for step in &task.spec.steps {
                let key = unit_key(&target.name, &step.name);
                if artifact.step_states.get(&key) != Some(&TaskStepStatus::Pending) {
                    continue;
                }
                let blocked = step.depends_on.iter().any(|dependency| {
                    matches!(
                        artifact
                            .step_states
                            .get(&unit_key(&target.name, dependency)),
                        Some(
                            TaskStepStatus::Failed
                                | TaskStepStatus::Skipped
                                | TaskStepStatus::Cancelled
                        )
                    )
                });
                if blocked {
                    artifact.step_states.insert(key, TaskStepStatus::Skipped);
                    changed = true;
                }
            }
        }
    }
}

fn ready_units<'a>(
    task: &'a TaskSpec,
    artifact: &TaskArtifact,
) -> Vec<(&'a TaskTargetSpec, &'a TaskStepSpec)> {
    let mut ready = Vec::new();
    for target in &task.spec.targets {
        for step in &task.spec.steps {
            let key = unit_key(&target.name, &step.name);
            if artifact.step_states.get(&key) != Some(&TaskStepStatus::Pending) {
                continue;
            }
            if step.depends_on.iter().all(|dependency| {
                artifact
                    .step_states
                    .get(&unit_key(&target.name, dependency))
                    == Some(&TaskStepStatus::Completed)
            }) {
                ready.push((target, step));
            }
        }
    }
    ready
}

fn mapped_step_input(
    workspace_dir: &std::path::Path,
    task: &TaskSpec,
    artifact: &TaskArtifact,
    target: &TaskTargetSpec,
    step: &TaskStepSpec,
) -> Result<serde_json::Value, CliError> {
    let mut input = target.input.clone();
    let object = input.as_object_mut().ok_or_else(|| {
        CliError::schema(
            "task target input must be a JSON object when using DAG mappings",
            Some("$.spec.targets.input".to_owned()),
        )
    })?;
    let store = open_store(workspace_dir)?;
    for mapping in &step.input_from {
        let source_name = task
            .spec
            .steps
            .iter()
            .find(|candidate| {
                candidate.name == mapping.from
                    || candidate.output_as.as_deref() == Some(mapping.from.as_str())
            })
            .map(|candidate| candidate.name.as_str())
            .ok_or_else(|| {
                CliError::schema(
                    format!("input source does not exist: {}", mapping.from),
                    Some("$.spec.steps.inputFrom".to_owned()),
                )
            })?;
        let run_id = artifact
            .outputs
            .get(&unit_key(&target.name, source_name))
            .ok_or_else(|| {
                CliError::runtime(
                    format!("input source has no completed output: {}", mapping.from),
                    Some("$.task.outputs".to_owned()),
                )
            })?;
        let result = store.load_result(run_id).map_err(store_error)?;
        let output = result.output.ok_or_else(|| {
            CliError::runtime(
                format!("input source has no normalized output: {}", mapping.from),
                Some("$.task.outputs".to_owned()),
            )
        })?;
        let value = serde_json::to_value(output).map_err(|error| {
            CliError::system(
                format!("failed to map prior output: {error}"),
                Some("$.task.outputs".to_owned()),
            )
        })?;
        let mapped = value.pointer(&mapping.pointer).cloned().ok_or_else(|| {
            CliError::schema(
                format!(
                    "JSON Pointer {} did not match output {}",
                    mapping.pointer, mapping.from
                ),
                Some("$.spec.steps.inputFrom.pointer".to_owned()),
            )
        })?;
        object.insert(mapping.target.clone(), mapped);
    }
    Ok(input)
}

fn read_task_spec(
    path: &std::path::Path,
    schema_root: &std::path::Path,
) -> Result<TaskSpec, CliError> {
    let bytes = fs::read(path).map_err(|error| {
        CliError::system(
            format!("failed to read {}: {error}", path.display()),
            Some("$.file".to_owned()),
        )
    })?;
    let yaml: serde_yaml::Value = serde_yaml::from_slice(&bytes).map_err(|error| {
        CliError::schema(
            format!("Task Spec is not valid YAML or JSON: {error}"),
            Some("$.task".to_owned()),
        )
    })?;
    let json = serde_json::to_vec(&yaml).map_err(|error| {
        CliError::schema(
            format!("Task Spec cannot be represented as JSON: {error}"),
            Some("$.task".to_owned()),
        )
    })?;
    let task: TaskSpec = from_json_slice(&json)
        .map_err(|error| CliError::schema(error.message, Some(error.path)))?;
    task.validate(&ValidationContext::new(schema_root))
        .map_err(|errors| {
            CliError::schema(
                errors.to_string(),
                errors.errors().first().map(|error| error.path.clone()),
            )
        })?;
    Ok(task)
}

fn validate_task_command(
    argument: &FileArgument,
    overrides: ConfigOverrides,
) -> Result<(), CliError> {
    let config = config::load(overrides)?;
    let task = read_task_spec(&argument.file, &config.schema_root)?;
    plan(&task).map_err(|error| CliError::schema(error.message, Some(error.field)))?;
    println!("valid TaskSpec: {}", argument.file.display());
    Ok(())
}

fn plan_task_command(argument: &FileArgument, overrides: ConfigOverrides) -> Result<(), CliError> {
    let config = config::load(overrides)?;
    let task = read_task_spec(&argument.file, &config.schema_root)?;
    let plan = plan(&task).map_err(|error| CliError::schema(error.message, Some(error.field)))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&plan).map_err(|error| {
            CliError::system(
                format!("failed to serialize task plan: {error}"),
                Some("$.task.plan".to_owned()),
            )
        })?
    );
    Ok(())
}

fn explain_policy(
    arguments: &PolicyExplainArguments,
    overrides: ConfigOverrides,
) -> Result<(), CliError> {
    let config = config::load(overrides)?;
    let task = read_task_spec(&arguments.file, &config.schema_root)?;
    plan(&task).map_err(|error| CliError::schema(error.message, Some(error.field)))?;
    let registry = load_registry(&config.workspace_dir.join("plugins"))?;
    let mut explanations = Vec::new();
    for target in &task.spec.targets {
        for step in &task.spec.steps {
            let risk = registry
                .get(&step.tool_ref)
                .and_then(|tool| {
                    tool.manifest
                        .spec
                        .capabilities
                        .iter()
                        .find(|capability| capability.name == step.capability)
                })
                .map_or(RiskLevel::Critical, |capability| capability.risk);
            let decision = evaluate_task(&TaskPolicyRequest {
                authorization_scope: &task.spec.authorization_scope,
                target: &target.name,
                risk,
                approval: task_approval_status(&task, &config.workspace_dir)?,
                utc_minute: current_utc_minute(),
                running_nodes: 0,
                starts_this_minute: 0,
                policy: &task.spec.policy,
            });
            explanations.push(serde_json::json!({
                "target": target.name,
                "step": step.name,
                "tool": step.tool_ref,
                "capability": step.capability,
                "risk": risk,
                "decision": decision,
            }));
        }
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&explanations).map_err(|error| {
            CliError::system(
                format!("failed to serialize Policy Explain: {error}"),
                Some("$.policy".to_owned()),
            )
        })?
    );
    Ok(())
}

fn request_approval(
    arguments: &ApprovalRequestArguments,
    overrides: ConfigOverrides,
) -> Result<(), CliError> {
    let config = config::load(overrides)?;
    workspace::initialize(&config.workspace_dir)?;
    let mut store = open_store(&config.workspace_dir)?;
    let approval = ApprovalRecord {
        approval_id: ExecutionIdentifiers::generate(&arguments.resource).run_id,
        resource_ref: arguments.resource.clone(),
        risk: risk_argument(arguments.risk),
        status: ApprovalStatus::Pending,
        actor: arguments.actor.clone(),
    };
    store.save_approval(&approval).map_err(store_error)?;
    store
        .record_audit(
            "approval.requested",
            AuditOutcome::Allowed,
            None,
            Some(approval.approval_id.clone()),
        )
        .map_err(store_error)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&approval).map_err(|error| {
            CliError::system(
                format!("failed to serialize approval: {error}"),
                Some("$.approval".to_owned()),
            )
        })?
    );
    Ok(())
}

fn decide_approval(
    arguments: &ApprovalDecisionArguments,
    overrides: ConfigOverrides,
    status: ApprovalStatus,
) -> Result<(), CliError> {
    let config = config::load(overrides)?;
    let mut store = open_store(&config.workspace_dir)?;
    let mut approval = store
        .load_approval(&arguments.approval_id)
        .map_err(store_error)?;
    match status {
        ApprovalStatus::Approved => approval.approve(&arguments.actor),
        ApprovalStatus::Rejected => approval.reject(&arguments.actor),
        ApprovalStatus::Expired => approval.expire(&arguments.actor),
        ApprovalStatus::Pending => unreachable!("pending is not a decision"),
    }
    .map_err(|error| CliError::authorization(error.message, Some(error.field.to_owned())))?;
    store.save_approval(&approval).map_err(store_error)?;
    store
        .record_audit(
            match status {
                ApprovalStatus::Approved => "approval.approved",
                ApprovalStatus::Rejected => "approval.rejected",
                ApprovalStatus::Expired => "approval.expired",
                ApprovalStatus::Pending => unreachable!("pending is not a decision"),
            },
            AuditOutcome::Succeeded,
            None,
            Some(approval.approval_id.clone()),
        )
        .map_err(store_error)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&approval).map_err(|error| {
            CliError::system(
                format!("failed to serialize approval: {error}"),
                Some("$.approval".to_owned()),
            )
        })?
    );
    Ok(())
}

const fn risk_argument(risk: RiskArgument) -> RiskLevel {
    match risk {
        RiskArgument::Low => RiskLevel::Low,
        RiskArgument::Medium => RiskLevel::Medium,
        RiskArgument::High => RiskLevel::High,
        RiskArgument::Critical => RiskLevel::Critical,
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn persist_task_target_success(
    task: &TaskSpec,
    target: &sentinelflow_schema::v1alpha1::TaskTargetSpec,
    identifiers: &ExecutionIdentifiers,
    started_at: &str,
    actor_id: &str,
    execution: &ExecutionResult,
    manifest: &ToolManifest,
    capability: &str,
    store: &mut WorkspaceStore,
    context: &AuditContext<'_>,
) -> Result<(), CliError> {
    store
        .record_audit(
            "tool.run.finished",
            AuditOutcome::Succeeded,
            Some(context),
            Some(identifiers.run_id.clone()),
        )
        .map_err(store_error)?;
    let raw = execution
        .output
        .as_ref()
        .ok_or_else(|| CliError::runtime("successful execution did not provide output", None))?;
    let parser_input = ParserInput {
        raw: RawOutputReference {
            run_id: &identifiers.run_id,
            value: raw,
        },
        context: ParserContext {
            identifiers,
            actor_id,
        },
    };
    let mut output = match builtin_parser(&manifest.spec.parser.name)
        .and_then(|parser| normalize(parser.as_ref(), &parser_input, &manifest.spec.output_schema))
    {
        Ok(output) => output,
        Err(error) => {
            let cli_error = CliError::schema(
                error.error.error.message.clone(),
                error.error.error.field.clone(),
            );
            store
                .save_run(&RunArtifact {
                    identifiers: identifiers.clone(),
                    actor_id: actor_id.to_owned(),
                    authorization_scope: task.spec.authorization_scope.clone(),
                    capability: capability.to_owned(),
                    target: target.name.clone(),
                    status: ExecutionStatus::Failed,
                    started_at: started_at.to_owned(),
                    finished_at: now_rfc3339().map_err(store_error)?,
                    duration_ms: execution.duration_ms,
                    exit_code: execution.exit_code,
                })
                .map_err(store_error)?;
            store
                .save_result(&ResultArtifact {
                    run_id: identifiers.run_id.clone(),
                    output: None,
                    errors: vec![error.error],
                })
                .map_err(store_error)?;
            store
                .record_audit(
                    "result.normalized",
                    AuditOutcome::Failed,
                    Some(context),
                    Some(identifiers.run_id.clone()),
                )
                .map_err(store_error)?;
            store
                .record_audit(
                    "tool.run.failed",
                    AuditOutcome::Failed,
                    Some(context),
                    Some(identifiers.run_id.clone()),
                )
                .map_err(store_error)?;
            return Err(cli_error);
        }
    };
    if !task.spec.policy.output_retention.retain_evidence {
        for finding in &mut output.spec.findings {
            finding.evidence.clear();
        }
    }
    output.metadata.annotations.insert(
        "sentinelflow.io/retention-days".to_owned(),
        task.spec.policy.output_retention.days.to_string(),
    );
    output.metadata.annotations.insert(
        "sentinelflow.io/retain-evidence".to_owned(),
        task.spec
            .policy
            .output_retention
            .retain_evidence
            .to_string(),
    );
    let finished_at = now_rfc3339().map_err(store_error)?;
    store
        .save_run(&RunArtifact {
            identifiers: identifiers.clone(),
            actor_id: actor_id.to_owned(),
            authorization_scope: task.spec.authorization_scope.clone(),
            capability: capability.to_owned(),
            target: target.name.clone(),
            status: execution.status,
            started_at: started_at.to_owned(),
            finished_at,
            duration_ms: execution.duration_ms,
            exit_code: execution.exit_code,
        })
        .map_err(store_error)?;
    store
        .save_result(&ResultArtifact {
            run_id: identifiers.run_id.clone(),
            output: Some(output),
            errors: Vec::new(),
        })
        .map_err(store_error)?;
    store
        .record_audit(
            "result.normalized",
            AuditOutcome::Succeeded,
            Some(context),
            Some(identifiers.run_id.clone()),
        )
        .map_err(store_error)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn persist_task_target_failure(
    task: &TaskSpec,
    target: &sentinelflow_schema::v1alpha1::TaskTargetSpec,
    capability: &str,
    identifiers: &ExecutionIdentifiers,
    started_at: &str,
    duration_ms: u128,
    actor_id: &str,
    error: &CliError,
    store: &mut WorkspaceStore,
    context: &AuditContext<'_>,
) -> Result<(), CliError> {
    store
        .save_run(&RunArtifact {
            identifiers: identifiers.clone(),
            actor_id: actor_id.to_owned(),
            authorization_scope: task.spec.authorization_scope.clone(),
            capability: capability.to_owned(),
            target: target.name.clone(),
            status: ExecutionStatus::Failed,
            started_at: started_at.to_owned(),
            finished_at: now_rfc3339().map_err(store_error)?,
            duration_ms,
            exit_code: None,
        })
        .map_err(store_error)?;
    store
        .save_result(&ResultArtifact {
            run_id: identifiers.run_id.clone(),
            output: None,
            errors: vec![error.to_standard_error()],
        })
        .map_err(store_error)?;
    let (action, outcome) = if error.exit_code() == 4 {
        ("policy.denied", AuditOutcome::Denied)
    } else {
        ("tool.run.failed", AuditOutcome::Failed)
    };
    store
        .record_audit(action, outcome, Some(context), Some(target.name.clone()))
        .map_err(store_error)?;
    Ok(())
}

fn task_status(arguments: &TaskIdArgument, overrides: ConfigOverrides) -> Result<(), CliError> {
    let config = config::load(overrides)?;
    let store = open_store(&config.workspace_dir)?;
    let task = store.load_task(&arguments.task_id).map_err(store_error)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&task).map_err(|error| {
            CliError::system(
                format!("failed to serialize task status: {error}"),
                Some("$.task".to_owned()),
            )
        })?
    );
    Ok(())
}

fn task_logs(arguments: &TaskIdArgument, overrides: ConfigOverrides) -> Result<(), CliError> {
    let config = config::load(overrides)?;
    let store = open_store(&config.workspace_dir)?;
    for event in store.task_audit(&arguments.task_id).map_err(store_error)? {
        println!(
            "{}",
            serde_json::to_string(&event).map_err(|error| {
                CliError::system(
                    format!("failed to serialize task log: {error}"),
                    Some("$.task.logs".to_owned()),
                )
            })?
        );
    }
    Ok(())
}

fn record_task_state(
    store: &mut WorkspaceStore,
    task: &TaskArtifact,
    status: TaskStatus,
    outcome: Option<AuditOutcome>,
) -> Result<(), CliError> {
    store.save_task(task).map_err(store_error)?;
    record_task_state_audit(
        store,
        status,
        outcome.unwrap_or(AuditOutcome::Allowed),
        &task.task_id,
    )
}

fn record_task_state_audit(
    store: &mut WorkspaceStore,
    status: TaskStatus,
    outcome: AuditOutcome,
    task_id: &str,
) -> Result<(), CliError> {
    store
        .record_audit(
            &format!("task.state.{}", task_status_audit_suffix(status)),
            outcome,
            None,
            Some(task_id.to_owned()),
        )
        .map_err(store_error)?;
    Ok(())
}

const fn task_status_audit_suffix(status: TaskStatus) -> &'static str {
    match status {
        TaskStatus::Pending => "pending",
        TaskStatus::Planning => "planning",
        TaskStatus::ApprovalRequired => "approval_required",
        TaskStatus::Running => "running",
        TaskStatus::Paused => "paused",
        TaskStatus::Cancelling => "cancelling",
        TaskStatus::Cancelled => "cancelled",
        TaskStatus::Failed => "failed",
        TaskStatus::Completed => "completed",
    }
}

fn mark_task_failed(
    workspace_dir: &std::path::Path,
    task: &mut TaskArtifact,
    error: &CliError,
) -> Result<(), CliError> {
    task.status = TaskStatus::Failed;
    task.finished_at = Some(now_rfc3339().map_err(store_error)?);
    task.last_error = Some(error.to_standard_error());
    let mut store = open_store(workspace_dir)?;
    store.save_task(task).map_err(store_error)?;
    record_task_state_audit(
        &mut store,
        TaskStatus::Failed,
        AuditOutcome::Failed,
        &task.task_id,
    )
}

fn cancel_task(arguments: &TaskIdArgument, overrides: ConfigOverrides) -> Result<(), CliError> {
    let config = config::load(overrides)?;
    let mut store = open_store(&config.workspace_dir)?;
    let mut task = store.load_task(&arguments.task_id).map_err(store_error)?;
    if !matches!(
        task.status,
        TaskStatus::Planning
            | TaskStatus::ApprovalRequired
            | TaskStatus::Running
            | TaskStatus::Paused
    ) {
        return Err(CliError::runtime(
            format!("task cannot be cancelled from state {:?}", task.status),
            Some("$.task.status".to_owned()),
        ));
    }
    task.status = TaskStatus::Cancelling;
    store.save_task(&task).map_err(store_error)?;
    record_task_state_audit(
        &mut store,
        TaskStatus::Cancelling,
        AuditOutcome::Allowed,
        &task.task_id,
    )?;
    store
        .record_audit(
            "task.cancel.requested",
            AuditOutcome::Succeeded,
            None,
            Some(task.task_id.clone()),
        )
        .map_err(store_error)?;
    println!("cancellation requested for {}", task.task_id);
    Ok(())
}

fn pause_task(arguments: &TaskIdArgument, overrides: ConfigOverrides) -> Result<(), CliError> {
    let config = config::load(overrides)?;
    let mut store = open_store(&config.workspace_dir)?;
    let mut task = store.load_task(&arguments.task_id).map_err(store_error)?;
    if !matches!(task.status, TaskStatus::Planning | TaskStatus::Running) {
        return Err(CliError::runtime(
            format!("task cannot be paused from state {:?}", task.status),
            Some("$.task.status".to_owned()),
        ));
    }
    task.status = TaskStatus::Paused;
    store.save_task(&task).map_err(store_error)?;
    record_task_state_audit(
        &mut store,
        TaskStatus::Paused,
        AuditOutcome::Allowed,
        &task.task_id,
    )?;
    println!("pause requested for {}", task.task_id);
    Ok(())
}

async fn resume_task(
    arguments: &TaskIdArgument,
    overrides: ConfigOverrides,
) -> Result<(), CliError> {
    let config = config::load(overrides)?;
    let store = open_store(&config.workspace_dir)?;
    let mut task = store.load_task(&arguments.task_id).map_err(store_error)?;
    if !matches!(
        task.status,
        TaskStatus::Paused
            | TaskStatus::ApprovalRequired
            | TaskStatus::Cancelled
            | TaskStatus::Failed
    ) {
        return Err(CliError::runtime(
            format!("task cannot be resumed from state {:?}", task.status),
            Some("$.task.status".to_owned()),
        ));
    }
    for status in task.step_states.values_mut() {
        if matches!(
            status,
            TaskStepStatus::Running | TaskStepStatus::Cancelled | TaskStepStatus::Failed
        ) {
            *status = TaskStepStatus::Pending;
        }
    }
    task.finished_at = None;
    task.last_error = None;
    task.status = TaskStatus::Planning;
    let mut store = store;
    store.save_task(&task).map_err(store_error)?;
    record_task_state_audit(
        &mut store,
        TaskStatus::Planning,
        AuditOutcome::Allowed,
        &task.task_id,
    )?;
    schedule_task(task, &config.workspace_dir).await
}

fn runtime_error(error: RuntimeError) -> CliError {
    match error.kind {
        RuntimeErrorKind::PolicyDenied => CliError::authorization(error.message, error.field),
        RuntimeErrorKind::InputInvalid | RuntimeErrorKind::OutputInvalid => {
            CliError::schema(error.message, error.field)
        }
        RuntimeErrorKind::System => CliError::system(error.message, error.field),
        _ => CliError::runtime(error.message, error.field),
    }
}

fn completed_run(
    arguments: &ToolRunArguments,
    identifiers: &ExecutionIdentifiers,
    started_at: &str,
    finished_at: &str,
    execution: &ExecutionResult,
    capability: &str,
) -> RunArtifact {
    RunArtifact {
        identifiers: identifiers.clone(),
        actor_id: arguments.actor_id.clone(),
        authorization_scope: arguments.authorization_scope.clone().unwrap_or_default(),
        capability: capability.to_owned(),
        target: arguments.target.clone(),
        status: execution.status,
        started_at: started_at.to_owned(),
        finished_at: finished_at.to_owned(),
        duration_ms: execution.duration_ms,
        exit_code: execution.exit_code,
    }
}

fn persist_failed_run(
    arguments: &ToolRunArguments,
    identifiers: &ExecutionIdentifiers,
    started_at: &str,
    duration_ms: u128,
    error: &CliError,
    store: &mut WorkspaceStore,
    context: &AuditContext<'_>,
) -> Result<(), CliError> {
    let finished_at = now_rfc3339().map_err(store_error)?;
    store
        .save_run(&RunArtifact {
            identifiers: identifiers.clone(),
            actor_id: arguments.actor_id.clone(),
            authorization_scope: arguments.authorization_scope.clone().unwrap_or_default(),
            capability: "unknown".to_owned(),
            target: arguments.target.clone(),
            status: ExecutionStatus::Failed,
            started_at: started_at.to_owned(),
            finished_at,
            duration_ms,
            exit_code: None,
        })
        .map_err(store_error)?;
    store
        .save_result(&ResultArtifact {
            run_id: identifiers.run_id.clone(),
            output: None,
            errors: vec![error.to_standard_error()],
        })
        .map_err(store_error)?;
    let (action, outcome) = if error.exit_code() == 4 {
        ("policy.denied", AuditOutcome::Denied)
    } else {
        ("tool.run.failed", AuditOutcome::Failed)
    };
    store
        .record_audit(
            action,
            outcome,
            Some(context),
            Some(identifiers.run_id.clone()),
        )
        .map_err(store_error)?;
    Ok(())
}

fn open_store(workspace_dir: &std::path::Path) -> Result<WorkspaceStore, CliError> {
    WorkspaceStore::open(workspace_dir).map_err(store_error)
}

#[allow(clippy::needless_pass_by_value)]
fn store_error(error: sentinelflow_store::StoreError) -> CliError {
    CliError::system(error.to_string(), Some("$.store".to_owned()))
}

fn generate_report(
    arguments: &ReportGenerateArguments,
    overrides: ConfigOverrides,
) -> Result<(), CliError> {
    let config = config::load(overrides)?;
    let mut store = open_store(&config.workspace_dir)?;
    let (report_id, markdown, identifiers, actor_id) = if let Some(run_id) = &arguments.run {
        let bundle = store.load_bundle(run_id).map_err(store_error)?;
        (
            run_id.clone(),
            generate_markdown(&bundle),
            bundle.run.identifiers,
            bundle.run.actor_id,
        )
    } else if let Some(task_id) = &arguments.task {
        let task = store.load_task(task_id).map_err(store_error)?;
        let bundles = store.load_task_bundles(task_id).map_err(store_error)?;
        let audit = store.task_audit(task_id).map_err(store_error)?;
        let identifiers = bundles.first().map_or_else(
            || ExecutionIdentifiers::generate(&task.tool_id),
            |bundle| bundle.run.identifiers.clone(),
        );
        (
            task_id.clone(),
            generate_task_markdown(&task, &bundles, &audit),
            identifiers,
            task.actor_id,
        )
    } else {
        return Err(CliError::argument("either --run or --task is required"));
    };
    let path = store
        .save_report(&report_id, &markdown)
        .map_err(store_error)?;
    let context = AuditContext {
        identifiers: &identifiers,
        actor_id: &actor_id,
    };
    store
        .record_audit(
            "report.generated",
            AuditOutcome::Succeeded,
            Some(&context),
            Some(path.display().to_string()),
        )
        .map_err(store_error)?;
    println!("{}", path.display());
    Ok(())
}

fn list_audit(overrides: ConfigOverrides) -> Result<(), CliError> {
    let config = config::load(overrides)?;
    let store = open_store(&config.workspace_dir)?;
    for event in store.list_audit().map_err(store_error)? {
        println!(
            "{}",
            serde_json::to_string(&event).map_err(|error| {
                CliError::system(
                    format!("failed to serialize audit event: {error}"),
                    Some("$.audit".to_owned()),
                )
            })?
        );
    }
    Ok(())
}

fn export_result(
    arguments: &ResultExportArguments,
    overrides: ConfigOverrides,
) -> Result<(), CliError> {
    let config = config::load(overrides)?;
    let store = open_store(&config.workspace_dir)?;
    let run_id = match &arguments.run {
        Some(run_id) => run_id.clone(),
        None => store
            .latest_run_id()
            .map_err(store_error)?
            .ok_or_else(|| CliError::runtime("no persisted runs are available", None))?,
    };
    match arguments.format {
        ExportFormat::Json => {
            let result = store.load_result(&run_id).map_err(store_error)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&result).map_err(|error| {
                    CliError::system(
                        format!("failed to serialize result: {error}"),
                        Some("$.result".to_owned()),
                    )
                })?
            );
        }
        ExportFormat::Jsonl => export_jsonl(&store.load_result(&run_id).map_err(store_error)?)?,
        ExportFormat::Md => {
            let bundle = store.load_bundle(&run_id).map_err(store_error)?;
            print!("{}", generate_markdown(&bundle));
        }
    }
    Ok(())
}

fn export_jsonl(result: &ResultArtifact) -> Result<(), CliError> {
    if let Some(output) = &result.output {
        for finding in &output.spec.findings {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "kind": "Finding",
                    "runId": result.run_id,
                    "value": finding
                }))
                .map_err(|error| {
                    CliError::system(
                        format!("failed to serialize finding: {error}"),
                        Some("$.result".to_owned()),
                    )
                })?
            );
        }
        for error in &output.spec.errors {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "kind": "StandardError",
                    "runId": result.run_id,
                    "value": error
                }))
                .map_err(|error| {
                    CliError::system(
                        format!("failed to serialize error: {error}"),
                        Some("$.result".to_owned()),
                    )
                })?
            );
        }
    }
    for error in &result.errors {
        println!(
            "{}",
            serde_json::to_string(error).map_err(|serialization_error| {
                CliError::system(
                    format!("failed to serialize error: {serialization_error}"),
                    Some("$.result".to_owned()),
                )
            })?
        );
    }
    Ok(())
}

fn show_config(overrides: ConfigOverrides) -> Result<(), CliError> {
    let config = config::load(overrides)?;
    let output = serde_yaml::to_string(&config.redacted()).map_err(|error| {
        CliError::system(
            format!("failed to serialize effective configuration: {error}"),
            Some("$.config".to_owned()),
        )
    })?;
    print!("{output}");
    Ok(())
}

fn validate_resource<T>(
    argument: &FileArgument,
    overrides: ConfigOverrides,
    kind: &str,
) -> Result<(), CliError>
where
    T: serde::de::DeserializeOwned + Validate,
{
    let config = config::load(overrides)?;
    let bytes = fs::read(&argument.file).map_err(|error| {
        CliError::system(
            format!("failed to read {}: {error}", argument.file.display()),
            Some("$.file".to_owned()),
        )
    })?;
    let resource: T = from_json_slice(&bytes)
        .map_err(|error| CliError::schema(error.message, Some(error.path)))?;
    resource
        .validate(&ValidationContext::new(&config.schema_root))
        .map_err(|errors| {
            let field = errors.errors().first().map(|error| error.path.clone());
            CliError::schema(errors.to_string(), field)
        })?;
    println!("valid {kind}: {}", argument.file.display());
    Ok(())
}

fn scaffold_plugin(argument: &PathArgument) -> Result<(), CliError> {
    let root = &argument.path;
    if root.exists()
        && fs::read_dir(root)
            .map_err(|error| {
                CliError::system(
                    format!("failed to inspect {}: {error}", root.display()),
                    Some("$.plugin.path".to_owned()),
                )
            })?
            .next()
            .is_some()
    {
        return Err(CliError::argument(format!(
            "plugin scaffold destination is not empty: {}",
            root.display()
        )));
    }
    let name = root
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| CliError::argument("plugin path must end with a UTF-8 directory name"))?;
    if !valid_plugin_name(name) {
        return Err(CliError::argument(
            "plugin name must contain lowercase letters, digits, or hyphens",
        ));
    }
    for directory in [
        "runner",
        "parser",
        "schemas",
        "examples",
        "sdk/python/sentinelflow_sdk",
    ] {
        fs::create_dir_all(root.join(directory)).map_err(|error| {
            CliError::system(
                format!("failed to create plugin scaffold: {error}"),
                Some("$.plugin.path".to_owned()),
            )
        })?;
    }
    let manifest = PYTHON_PLUGIN_MANIFEST.replace("__NAME__", name);
    write_scaffold(&root.join("sentinelflow.tool.yaml"), &manifest)?;
    write_scaffold(
        &root.join(".sentinelflow-scaffold"),
        "generated-by=sentinelflow-plugin-scaffold-v1\n",
    )?;
    write_scaffold(
        &root.join("README.md"),
        &PYTHON_PLUGIN_README.replace("__NAME__", name),
    )?;
    write_scaffold(&root.join("runner/main.py"), PYTHON_PLUGIN_RUNNER)?;
    write_scaffold(
        &root.join("sdk/python/sentinelflow_sdk/__init__.py"),
        include_str!("../../../sdk/python/sentinelflow_sdk/__init__.py"),
    )?;
    write_scaffold(&root.join("parser/README.md"), PYTHON_PLUGIN_PARSER_README)?;
    write_scaffold(&root.join("schemas/input.schema.json"), ECHO_INPUT_SCHEMA)?;
    write_scaffold(&root.join("schemas/output.schema.json"), ECHO_OUTPUT_SCHEMA)?;
    write_scaffold(&root.join("examples/input.json"), ECHO_INPUT_EXAMPLE)?;
    write_scaffold(&root.join("examples/output.json"), ECHO_OUTPUT_EXAMPLE)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let runner = root.join("runner/main.py");
        let mut permissions = fs::metadata(&runner)
            .map_err(|error| {
                CliError::system(error.to_string(), Some("$.plugin.runner".to_owned()))
            })?
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&runner, permissions).map_err(|error| {
            CliError::system(error.to_string(), Some("$.plugin.runner".to_owned()))
        })?;
    }
    println!("scaffolded safe Python plugin at {}", root.display());
    Ok(())
}

async fn test_plugin(argument: &PathArgument, overrides: ConfigOverrides) -> Result<(), CliError> {
    let report = validate_plugin(&argument.path).map_err(|error| registry_system_error(&error))?;
    if !report.is_valid() {
        return Err(CliError::schema(
            "plugin contract validation failed",
            Some("$.plugin".to_owned()),
        ));
    }
    let manifest = report.manifest.ok_or_else(|| {
        CliError::schema(
            "validated plugin did not produce a Manifest",
            Some("$.plugin.manifest".to_owned()),
        )
    })?;
    let config = config::load(overrides)?;
    let temporary = tempfile::tempdir().map_err(|error| {
        CliError::system(
            format!("failed to create plugin test workspace: {error}"),
            Some("$.plugin.test".to_owned()),
        )
    })?;
    workspace::initialize(temporary.path())?;
    install_plugin(&argument.path, temporary.path().join("plugins")).map_err(registry_error)?;
    let test_arguments = ToolRunArguments {
        tool: manifest.metadata.name,
        input: argument.path.join("examples/input.json"),
        authorization_scope: Some("fixture:local-only".to_owned()),
        approve_high_risk: false,
        timeout_seconds: None,
        actor_id: "plugin-test".to_owned(),
        target: "safe plugin fixture".to_owned(),
    };
    run_tool(
        &test_arguments,
        ConfigOverrides {
            workspace_dir: Some(temporary.path().to_path_buf()),
            schema_root: Some(config.schema_root),
            log_level: None,
            api_endpoint: None,
            auth_token: None,
        },
    )
    .await?;
    println!("plugin test passed: {}", argument.path.display());
    Ok(())
}

fn valid_plugin_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn write_scaffold(path: &std::path::Path, content: &str) -> Result<(), CliError> {
    fs::write(path, content).map_err(|error| {
        CliError::system(
            format!("failed to write {}: {error}", path.display()),
            Some("$.plugin.scaffold".to_owned()),
        )
    })
}

fn validate_plugin_command(argument: &PathArgument) -> Result<(), CliError> {
    let report = validate_plugin(&argument.path).map_err(|error| registry_system_error(&error))?;
    let valid = report.is_valid();
    let first_failure = report
        .checks
        .iter()
        .find(|check| !check.passed)
        .and_then(|check| check.messages.first())
        .cloned();
    let output = serde_yaml::to_string(&report).map_err(|error| {
        CliError::system(
            format!("failed to serialize plugin validation report: {error}"),
            Some("$.validationReport".to_owned()),
        )
    })?;
    print!("{output}");
    if valid {
        Ok(())
    } else {
        Err(CliError::schema(
            first_failure.unwrap_or_else(|| "plugin validation failed".to_owned()),
            Some("$.plugin".to_owned()),
        ))
    }
}

const PYTHON_PLUGIN_MANIFEST: &str = r#"apiVersion: sentinelflow.io/v1alpha1
kind: ToolManifest
metadata:
  name: __NAME__
  labels:
    sentinelflow.io/example: "true"
spec:
  displayName: Safe Python SDK Example
  version: 0.1.0
  capabilities:
    - name: echo
      description: Returns caller-provided synthetic fixture data
      risk: low
      requiresApproval: false
  runtime:
    adapter: command
    mode: process
    entrypoint: runner/main.py
    args: []
    environmentAllowlist:
      - PATH
    timeoutSeconds: 5
    outputLimitBytes: 65536
  parser:
    mode: builtin
    name: example-echo-v1
  inputSchema: schemas/input.schema.json
  outputSchema: schemas/output.schema.json
extensions:
  sentinelflow.io/safetyProfile: synthetic-echo-only
"#;

const PYTHON_PLUGIN_RUNNER: &str = r#"#!/usr/bin/env python3
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sdk" / "python"))

from sentinelflow_sdk import run


def handle(payload):
    message = payload.get("message")
    if not isinstance(message, str):
        raise ValueError("message must be a string")
    return {"message": message}


if __name__ == "__main__":
    run(handle)
"#;

const PYTHON_PLUGIN_README: &str = r"# __NAME__

Safe SentinelFlow Python SDK fixture. It performs no network access and echoes only
the synthetic `message` supplied on standard input.
";

const PYTHON_PLUGIN_PARSER_README: &str =
    "Uses the trusted built-in `example-echo-v1` parser. No plugin code is loaded in-process.\n";

const ECHO_INPUT_SCHEMA: &str = r#"{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "additionalProperties": false,
  "required": ["message"],
  "properties": {"message": {"type": "string", "maxLength": 4096}}
}
"#;

const ECHO_OUTPUT_SCHEMA: &str = r#"{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "additionalProperties": false,
  "required": ["message"],
  "properties": {"message": {"type": "string", "maxLength": 4096}}
}
"#;

const ECHO_INPUT_EXAMPLE: &str = "{\n  \"message\": \"hello from a safe Python fixture\"\n}\n";
const ECHO_OUTPUT_EXAMPLE: &str = "{\n  \"message\": \"hello from a safe Python fixture\"\n}\n";

fn install_plugin_command(
    argument: &PathArgument,
    overrides: ConfigOverrides,
) -> Result<(), CliError> {
    let config = config::load(overrides)?;
    workspace::initialize(&config.workspace_dir)?;
    let plugins_root = config.workspace_dir.join("plugins");
    let mut store = open_store(&config.workspace_dir)?;
    let result = install_plugin(&argument.path, &plugins_root);
    let outcome = if result.is_ok() {
        AuditOutcome::Succeeded
    } else {
        AuditOutcome::Failed
    };
    store
        .record_audit(
            "plugin.install",
            outcome,
            None,
            Some(argument.path.display().to_string()),
        )
        .map_err(store_error)?;
    match result.map_err(registry_error)? {
        InstallOutcome::Installed(path) => {
            println!("installed plugin at {}", path.display());
        }
        InstallOutcome::AlreadyInstalled(path) => {
            println!("plugin already installed at {}", path.display());
        }
    }
    Ok(())
}

fn list_tools(overrides: ConfigOverrides) -> Result<(), CliError> {
    let config = config::load(overrides)?;
    let registry = load_registry(&config.workspace_dir.join("plugins"))?;
    println!("NAME\tVERSION\tCAPABILITIES\tRISK\tENABLED");
    for (name, tool) in registry.list() {
        let capabilities = tool
            .manifest
            .spec
            .capabilities
            .iter()
            .map(|capability| capability.name.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let risks = tool
            .manifest
            .spec
            .capabilities
            .iter()
            .map(|capability| format!("{:?}", capability.risk).to_lowercase())
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{}\t{}\t{}\t{}\t{}",
            name, tool.manifest.spec.version, capabilities, risks, tool.enabled
        );
    }
    Ok(())
}

fn show_tool(name: &str, overrides: ConfigOverrides) -> Result<(), CliError> {
    let config = config::load(overrides)?;
    let registry = load_registry(&config.workspace_dir.join("plugins"))?;
    let tool = registry.get(name).ok_or_else(|| {
        CliError::system(
            format!("tool is not registered: {name}"),
            Some("$.tool".to_owned()),
        )
    })?;
    let output = serde_yaml::to_string(&serde_json::json!({
        "name": tool.manifest.metadata.name,
        "displayName": tool.manifest.spec.display_name,
        "version": tool.manifest.spec.version,
        "enabled": tool.enabled,
        "pluginRoot": tool.plugin_root,
        "runtimeMode": tool.manifest.spec.runtime.mode,
        "inputSchema": tool.manifest.spec.input_schema,
        "outputSchema": tool.manifest.spec.output_schema,
        "capabilities": tool.manifest.spec.capabilities,
    }))
    .map_err(|error| {
        CliError::system(
            format!("failed to serialize tool information: {error}"),
            Some("$.tool".to_owned()),
        )
    })?;
    print!("{output}");
    Ok(())
}

fn load_registry(plugins_root: &std::path::Path) -> Result<ToolRegistry, CliError> {
    let discovery =
        discover_plugins([plugins_root]).map_err(|error| registry_system_error(&error))?;
    let mut registry = ToolRegistry::new();
    for plugin_root in discovery.plugins {
        let plugin = validate_plugin(&plugin_root)
            .map_err(|error| registry_system_error(&error))?
            .into_validated()
            .map_err(registry_error)?;
        registry.register(plugin).map_err(registry_error)?;
    }
    Ok(registry)
}

fn registry_error(error: RegistryError) -> CliError {
    match error {
        RegistryError::InvalidPlugin { path, message } => CliError::schema(
            format!("invalid plugin {}: {message}", path.display()),
            Some("$.plugin".to_owned()),
        ),
        other => registry_system_error(&other),
    }
}

fn registry_system_error(error: &RegistryError) -> CliError {
    CliError::system(error.to_string(), Some("$.registry".to_owned()))
}

fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Init => "init",
        Command::Config { .. } => "config show",
        Command::Tool { command } => match command {
            ToolCommand::Validate(_) => "tool validate",
            ToolCommand::List => "tool list",
            ToolCommand::Info { .. } => "tool info",
            ToolCommand::Run(_) => "tool run",
        },
        Command::Task { command } => match command {
            TaskCommand::Validate(_) => "task validate",
            TaskCommand::Run(_) => "task run",
            TaskCommand::Plan(_) => "task plan",
            TaskCommand::Status(_) => "task status",
            TaskCommand::Logs(_) => "task logs",
            TaskCommand::Cancel(_) => "task cancel",
            TaskCommand::Pause(_) => "task pause",
            TaskCommand::Resume(_) => "task resume",
        },
        Command::Plugin { command } => match command {
            PluginCommand::Scaffold(_) => "plugin scaffold",
            PluginCommand::Test(_) => "plugin test",
            PluginCommand::Validate(_) => "plugin validate",
            PluginCommand::Install(_) => "plugin install",
        },
        Command::Result { command } => match command {
            ResultCommand::Normalize => "result normalize",
            ResultCommand::Export(_) => "result export",
        },
        Command::Report { command } => match command {
            ReportCommand::Generate(_) => "report generate",
        },
        Command::Audit { command } => match command {
            AuditCommand::List => "audit list",
        },
        Command::Policy { command } => match command {
            PolicyCommand::Explain(_) => "policy explain",
        },
        Command::Approval { command } => match command {
            ApprovalCommand::Request(_) => "approval request",
            ApprovalCommand::Approve(_) => "approval approve",
            ApprovalCommand::Reject(_) => "approval reject",
            ApprovalCommand::Expire(_) => "approval expire",
        },
    }
}
