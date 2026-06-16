//! Process-level contract tests for the `sentinelflow` CLI.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use clap::Parser;
use sentinelflow_cli::Cli;
use tempfile::TempDir;

const CONFIG_ENVIRONMENT: [&str; 5] = [
    "SENTINELFLOW_WORKSPACE_DIR",
    "SENTINELFLOW_SCHEMA_ROOT",
    "SENTINELFLOW_LOG_LEVEL",
    "SENTINELFLOW_API_ENDPOINT",
    "SENTINELFLOW_AUTH_TOKEN",
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sentinelflow"));
    for variable in CONFIG_ENVIRONMENT {
        command.env_remove(variable);
    }
    command
}

fn run(args: &[&str], current_dir: &Path) -> Output {
    binary()
        .args(args)
        .current_dir(current_dir)
        .output()
        .expect("sentinelflow process must start")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("CLI output must be UTF-8")
}

#[test]
fn complete_command_tree_parses() {
    let commands: &[&[&str]] = &[
        &["sentinelflow", "init"],
        &["sentinelflow", "config", "show"],
        &["sentinelflow", "tool", "validate", "manifest.json"],
        &["sentinelflow", "task", "validate", "task.json"],
        &["sentinelflow", "tool", "list"],
        &["sentinelflow", "tool", "info", "example"],
        &["sentinelflow", "plugin", "scaffold", "plugin"],
        &["sentinelflow", "plugin", "test", "plugin"],
        &["sentinelflow", "plugin", "validate", "plugin"],
        &["sentinelflow", "plugin", "install", "plugin"],
        &[
            "sentinelflow",
            "tool",
            "run",
            "example",
            "--input",
            "input.json",
        ],
        &["sentinelflow", "task", "run", "task.yaml"],
        &["sentinelflow", "task", "plan", "task.yaml"],
        &["sentinelflow", "task", "status", "task-example"],
        &["sentinelflow", "task", "logs", "task-example"],
        &["sentinelflow", "task", "cancel", "task-example"],
        &["sentinelflow", "task", "pause", "task-example"],
        &["sentinelflow", "task", "resume", "task-example"],
        &["sentinelflow", "policy", "explain", "task.yaml"],
        &[
            "sentinelflow",
            "approval",
            "request",
            "--resource",
            "task-example",
            "--risk",
            "high",
        ],
        &["sentinelflow", "approval", "approve", "approval-example"],
        &["sentinelflow", "approval", "reject", "approval-example"],
        &["sentinelflow", "approval", "expire", "approval-example"],
        &["sentinelflow", "result", "normalize"],
        &["sentinelflow", "result", "export", "--format", "json"],
        &["sentinelflow", "report", "generate", "--run", "run-example"],
        &["sentinelflow", "audit", "list"],
    ];

    for command in commands {
        Cli::try_parse_from(*command)
            .unwrap_or_else(|error| panic!("failed to parse {command:?}: {error}"));
    }
}

#[test]
fn python_sdk_scaffold_runs_through_the_plugin_lifecycle() {
    let root = workspace_root();
    let temporary = TempDir::new().expect("temporary directory must be created");
    let plugin = temporary.path().join("example-python-sdk");
    let workspace = temporary.path().join(".sentinelflow");
    let plugin_arg = plugin.to_string_lossy();
    let workspace_arg = workspace.to_string_lossy();

    for arguments in [
        vec!["plugin", "scaffold", &plugin_arg],
        vec!["plugin", "test", &plugin_arg],
        vec!["plugin", "validate", &plugin_arg],
        vec![
            "--workspace",
            &workspace_arg,
            "plugin",
            "install",
            &plugin_arg,
        ],
    ] {
        let output = run(&arguments, &root);
        assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    }

    let input = plugin.join("examples/input.json");
    let output = run(
        &[
            "--workspace",
            &workspace_arg,
            "tool",
            "run",
            "example-python-sdk",
            "--input",
            &input.to_string_lossy(),
        ],
        &root,
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let receipt: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("execution receipt must be JSON");
    assert_eq!(receipt["status"], "succeeded");
    assert!(
        receipt["output"]["spec"]["findings"][0]["fingerprint"]
            .as_str()
            .is_some_and(|value| value.len() == 64)
    );
}

fn install_example(workspace: &Path, plugin: &Path, current_dir: &Path) {
    let output = run(
        &[
            "--workspace",
            &workspace.to_string_lossy(),
            "plugin",
            "install",
            &plugin.to_string_lossy(),
        ],
        current_dir,
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
}

#[test]
fn p4_dag_plan_run_mapping_cycle_and_failure_policy_work() {
    let root = workspace_root();
    let temporary = TempDir::new().expect("temporary directory");
    let workspace = temporary.path().join(".sentinelflow");
    for plugin in [
        "plugins/examples/example-echo",
        "plugins/examples/example-finding-consumer",
        "plugins/examples/example-failure",
    ] {
        install_example(&workspace, &root.join(plugin), &root);
    }

    let dag = root.join("tests/fixtures/task.dag.yaml");
    let planned = run(&["task", "plan", &dag.to_string_lossy()], &root);
    assert_eq!(planned.status.code(), Some(0), "{}", text(&planned.stderr));
    let plan: serde_json::Value =
        serde_json::from_slice(&planned.stdout).expect("plan must be JSON");
    assert_eq!(
        plan["executionOrder"],
        serde_json::json!(["produce", "consume"])
    );

    let executed = run(
        &[
            "--workspace",
            &workspace.to_string_lossy(),
            "task",
            "run",
            &dag.to_string_lossy(),
        ],
        &root,
    );
    assert_eq!(
        executed.status.code(),
        Some(0),
        "{}",
        text(&executed.stderr)
    );
    let receipt: serde_json::Value =
        serde_json::from_slice(&executed.stdout).expect("task receipt");
    assert_eq!(receipt["status"], "completed");
    let consumer_run = receipt["outputs"]["fixture-one/consume"]
        .as_str()
        .expect("consumer run");
    let consumer_result: serde_json::Value = serde_json::from_slice(
        &fs::read(
            workspace
                .join("results")
                .join(format!("{consumer_run}.json")),
        )
        .expect("consumer result"),
    )
    .expect("result JSON");
    assert_eq!(
        consumer_result["output"]["spec"]["values"]["message"],
        "consumed 1 finding(s)"
    );

    let cycle = run(
        &[
            "task",
            "plan",
            &root
                .join("tests/fixtures/task.cycle.yaml")
                .to_string_lossy(),
        ],
        &root,
    );
    assert_eq!(cycle.status.code(), Some(3));

    let partial = run(
        &[
            "--workspace",
            &workspace.to_string_lossy(),
            "task",
            "run",
            &root
                .join("tests/fixtures/task.failure-policy.yaml")
                .to_string_lossy(),
        ],
        &root,
    );
    assert_eq!(partial.status.code(), Some(5));
    let artifact = newest_task(&workspace);
    assert_eq!(artifact["stepStates"]["fixture-one/fails"], "failed");
    assert_eq!(
        artifact["stepStates"]["fixture-one/independent"],
        "completed"
    );
    assert_eq!(artifact["stepStates"]["fixture-one/dependent"], "skipped");
}

#[test]
#[allow(clippy::too_many_lines)]
fn p4_policy_denies_targets_and_requires_persisted_high_risk_approval() {
    let root = workspace_root();
    let temporary = TempDir::new().expect("temporary directory");
    let workspace = temporary.path().join(".sentinelflow");
    install_example(
        &workspace,
        &root.join("plugins/examples/example-high-risk"),
        &root,
    );

    let high_risk = root.join("tests/fixtures/task.high-risk.yaml");
    let explanation = run(
        &[
            "--workspace",
            &workspace.to_string_lossy(),
            "policy",
            "explain",
            &high_risk.to_string_lossy(),
        ],
        &root,
    );
    assert_eq!(
        explanation.status.code(),
        Some(0),
        "{}",
        text(&explanation.stderr)
    );
    let decisions: serde_json::Value =
        serde_json::from_slice(&explanation.stdout).expect("Policy Explain JSON");
    assert_eq!(decisions[0]["decision"]["allowed"], false);
    let denied = run(
        &[
            "--workspace",
            &workspace.to_string_lossy(),
            "task",
            "run",
            &high_risk.to_string_lossy(),
        ],
        &root,
    );
    assert_eq!(denied.status.code(), Some(4));
    assert!(text(&denied.stderr).contains("approved request"));

    let requested = run(
        &[
            "--workspace",
            &workspace.to_string_lossy(),
            "approval",
            "request",
            "--resource",
            "example-high-risk-task",
            "--risk",
            "high",
        ],
        &root,
    );
    assert_eq!(
        requested.status.code(),
        Some(0),
        "{}",
        text(&requested.stderr)
    );
    let approval: serde_json::Value =
        serde_json::from_slice(&requested.stdout).expect("approval request");
    let approval_id = approval["approvalId"].as_str().expect("approval id");
    let approved = run(
        &[
            "--workspace",
            &workspace.to_string_lossy(),
            "approval",
            "approve",
            approval_id,
        ],
        &root,
    );
    assert_eq!(
        approved.status.code(),
        Some(0),
        "{}",
        text(&approved.stderr)
    );

    let approved_task = temporary.path().join("approved.yaml");
    let source = fs::read_to_string(&high_risk).expect("high risk fixture");
    fs::write(
        &approved_task,
        source.replace(
            "approveHighRisk: false",
            &format!(
                "approveHighRisk: false\n    approvalRef: {approval_id}\n    outputRetention:\n      days: 0\n      retainEvidence: false"
            ),
        ),
    )
    .expect("approved task");
    let allowed = run(
        &[
            "--workspace",
            &workspace.to_string_lossy(),
            "task",
            "run",
            &approved_task.to_string_lossy(),
        ],
        &root,
    );
    assert_eq!(allowed.status.code(), Some(0), "{}", text(&allowed.stderr));
    assert_eq!(
        fs::read_dir(workspace.join("results"))
            .expect("results directory")
            .count(),
        0
    );

    let unauthorized = temporary.path().join("unauthorized.yaml");
    fs::write(
        &unauthorized,
        source.replace("allowedTargets: [fixture-one]", "allowedTargets: [other]"),
    )
    .expect("unauthorized task");
    let denied_target = run(
        &[
            "--workspace",
            &workspace.to_string_lossy(),
            "task",
            "run",
            &unauthorized.to_string_lossy(),
        ],
        &root,
    );
    assert_eq!(denied_target.status.code(), Some(4));
}

#[test]
#[allow(clippy::zombie_processes)]
fn p4_cancel_and_resume_preserve_consistent_snapshot_state() {
    let root = workspace_root();
    let temporary = TempDir::new().expect("temporary directory");
    let workspace = temporary.path().join(".sentinelflow");
    for plugin in [
        "plugins/examples/example-slow",
        "plugins/examples/example-echo",
    ] {
        install_example(&workspace, &root.join(plugin), &root);
    }
    let task_file = root.join("tests/fixtures/task.slow.yaml");
    let mut child = binary()
        .args([
            "--workspace",
            &workspace.to_string_lossy(),
            "task",
            "run",
            &task_file.to_string_lossy(),
        ])
        .current_dir(&root)
        .spawn()
        .expect("task process");

    let task_id = (0..60)
        .find_map(|_| {
            std::thread::sleep(std::time::Duration::from_millis(50));
            fs::read_dir(workspace.join("tasks"))
                .ok()?
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .find(|path| {
                    path.file_name()
                        .and_then(|value| value.to_str())
                        .is_some_and(|name| name.starts_with("task-"))
                        && path
                            .extension()
                            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
                })?
                .file_stem()
                .and_then(|value| value.to_str())
                .map(str::to_owned)
        })
        .expect("persisted task id");
    (0..60)
        .find_map(|_| {
            std::thread::sleep(std::time::Duration::from_millis(50));
            let artifact: serde_json::Value = serde_json::from_slice(
                &fs::read(workspace.join("tasks").join(format!("{task_id}.json"))).ok()?,
            )
            .ok()?;
            (artifact["stepStates"]["fixture-one/slow"] == "running").then_some(())
        })
        .expect("slow step must be running before cancellation");
    let cancelled = run(
        &[
            "--workspace",
            &workspace.to_string_lossy(),
            "task",
            "cancel",
            &task_id,
        ],
        &root,
    );
    assert_eq!(
        cancelled.status.code(),
        Some(0),
        "{}",
        text(&cancelled.stderr)
    );
    let _ = child.wait().expect("cancelled task process");
    let artifact: serde_json::Value = serde_json::from_slice(
        &fs::read(workspace.join("tasks").join(format!("{task_id}.json")))
            .expect("cancelled artifact"),
    )
    .expect("cancelled JSON");
    assert_eq!(artifact["status"], "cancelled");
    assert_eq!(
        artifact["planSnapshot"]["executionOrder"],
        serde_json::json!(["slow", "after"])
    );

    let resumed = run(
        &[
            "--workspace",
            &workspace.to_string_lossy(),
            "task",
            "resume",
            &task_id,
        ],
        &root,
    );
    assert_eq!(resumed.status.code(), Some(0), "{}", text(&resumed.stderr));
    let receipt: serde_json::Value =
        serde_json::from_slice(&resumed.stdout).expect("resume receipt");
    assert_eq!(receipt["status"], "completed");
    assert_eq!(receipt["stepStates"]["fixture-one/slow"], "completed");
    assert_eq!(receipt["stepStates"]["fixture-one/after"], "completed");
}

fn newest_task(workspace: &Path) -> serde_json::Value {
    let mut paths = fs::read_dir(workspace.join("tasks"))
        .expect("task directory")
        .map(|entry| entry.expect("task entry").path())
        .collect::<Vec<_>>();
    paths.sort_by_key(|path| {
        fs::metadata(path)
            .and_then(|metadata| metadata.modified())
            .ok()
    });
    serde_json::from_slice(&fs::read(paths.last().expect("task artifact")).expect("task bytes"))
        .expect("task JSON")
}

#[test]
fn init_is_idempotent_and_preserves_existing_configuration() {
    let temporary = TempDir::new().expect("temporary directory must be created");
    let workspace = temporary.path().join(".sentinelflow");
    let workspace_arg = workspace.to_string_lossy();

    let first = run(&["--workspace", &workspace_arg, "init"], temporary.path());
    assert_eq!(first.status.code(), Some(0), "{}", text(&first.stderr));

    for directory in [
        "plugins", "tools", "tasks", "runs", "results", "reports", "audit",
    ] {
        assert!(workspace.join(directory).is_dir(), "missing {directory}");
    }
    let config_path = workspace.join("config.yaml");
    assert!(config_path.is_file());

    let custom_config = "version: 1\nlogLevel: custom\ncustomMarker: keep-me\n";
    fs::write(&config_path, custom_config).expect("custom config must be written");

    let second = run(&["--workspace", &workspace_arg, "init"], temporary.path());
    assert_eq!(second.status.code(), Some(0), "{}", text(&second.stderr));
    assert_eq!(
        fs::read_to_string(config_path).expect("config must remain readable"),
        custom_config
    );
}

#[test]
fn config_show_merges_layers_and_redacts_sensitive_values() {
    let temporary = TempDir::new().expect("temporary directory must be created");
    let workspace = temporary.path().join(".sentinelflow");
    fs::create_dir_all(&workspace).expect("workspace must be created");
    fs::write(
        workspace.join("config.yaml"),
        format!(
            "version: 1\nworkspaceDir: '{}'\nschemaRoot: project-root\nlogLevel: warn\n\
             apiEndpoint: https://project.invalid\nauthToken: project-secret\n",
            workspace.display()
        ),
    )
    .expect("project config must be written");

    let output = binary()
        .args([
            "--workspace",
            &workspace.to_string_lossy(),
            "--log-level",
            "debug",
            "--auth-token",
            "cli-secret",
            "config",
            "show",
        ])
        .env("SENTINELFLOW_LOG_LEVEL", "error")
        .env("SENTINELFLOW_API_ENDPOINT", "https://environment.invalid")
        .current_dir(temporary.path())
        .output()
        .expect("sentinelflow process must start");

    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let stdout = text(&output.stdout);
    assert!(stdout.contains("logLevel: debug"));
    assert!(stdout.contains("apiEndpoint: https://environment.invalid"));
    assert!(stdout.contains("authToken: '********'") || stdout.contains("authToken: ********"));
    assert!(!stdout.contains("project-secret"));
    assert!(!stdout.contains("cli-secret"));
}

#[test]
fn tool_validate_accepts_valid_fixture_and_rejects_invalid_fixture() {
    let root = workspace_root();
    let temporary = TempDir::new().expect("temporary directory must be created");
    let workspace = temporary.path().join(".sentinelflow");
    let workspace_arg = workspace.to_string_lossy();
    let schema_root = root.to_string_lossy();
    let valid = root.join("tests/fixtures/v1alpha1/valid-tool-manifest.json");
    let invalid = root.join("tests/fixtures/v1alpha1/invalid-tool-manifest.json");

    let accepted = run(
        &[
            "--workspace",
            &workspace_arg,
            "--schema-root",
            &schema_root,
            "tool",
            "validate",
            &valid.to_string_lossy(),
        ],
        &root,
    );
    assert_eq!(
        accepted.status.code(),
        Some(0),
        "{}",
        text(&accepted.stderr)
    );

    let rejected = run(
        &[
            "--workspace",
            &workspace_arg,
            "--schema-root",
            &schema_root,
            "tool",
            "validate",
            &invalid.to_string_lossy(),
        ],
        &root,
    );
    assert_eq!(rejected.status.code(), Some(3));
    let stderr = text(&rejected.stderr);
    assert!(stderr.contains("SchemaValidationFailed"));
    assert!(stderr.contains("$.spec.capabilities[0].requiresApproval"));
}

#[test]
fn task_validate_accepts_valid_fixture_and_rejects_invalid_fixture() {
    let root = workspace_root();
    let temporary = TempDir::new().expect("temporary directory must be created");
    let workspace = temporary.path().join(".sentinelflow");
    let workspace_arg = workspace.to_string_lossy();
    let valid = root.join("tests/fixtures/v1alpha1/valid-task-spec.json");
    let invalid = root.join("tests/fixtures/v1alpha1/invalid-task-spec.json");

    let accepted = run(
        &[
            "--workspace",
            &workspace_arg,
            "task",
            "validate",
            &valid.to_string_lossy(),
        ],
        &root,
    );
    assert_eq!(
        accepted.status.code(),
        Some(0),
        "{}",
        text(&accepted.stderr)
    );

    let rejected = run(
        &[
            "--workspace",
            &workspace_arg,
            "task",
            "validate",
            &invalid.to_string_lossy(),
        ],
        &root,
    );
    assert_eq!(rejected.status.code(), Some(3));
    let stderr = text(&rejected.stderr);
    assert!(stderr.contains("SchemaValidationFailed"));
    assert!(stderr.contains("authorizationScope"));
}

#[test]
fn placeholder_and_argument_errors_use_stable_exit_codes() {
    let temporary = TempDir::new().expect("temporary directory must be created");

    let placeholders: &[&[&str]] = &[&["result", "normalize"]];
    for arguments in placeholders {
        let placeholder = run(arguments, temporary.path());
        assert_eq!(
            placeholder.status.code(),
            Some(5),
            "unexpected status for {arguments:?}"
        );
        assert!(
            text(&placeholder.stderr).contains("\"code\":\"NotImplemented\""),
            "unexpected error for {arguments:?}"
        );
    }

    let argument = run(&["tool", "validate"], temporary.path());
    assert_eq!(argument.status.code(), Some(2));
    assert!(text(&argument.stderr).contains("\"code\":\"InvalidArguments\""));
}

#[test]
#[allow(clippy::too_many_lines)]
fn plugin_validate_install_list_and_info_work_end_to_end() {
    let root = workspace_root();
    let plugin = root.join("plugins/examples/example-echo");
    let temporary = TempDir::new().expect("temporary directory must be created");
    let workspace = temporary.path().join(".sentinelflow");
    let workspace_arg = workspace.to_string_lossy();
    let plugin_arg = plugin.to_string_lossy();

    let validation = run(&["plugin", "validate", &plugin_arg], temporary.path());
    assert_eq!(
        validation.status.code(),
        Some(0),
        "{}",
        text(&validation.stderr)
    );
    let report = text(&validation.stdout);
    for stage in [
        "structure",
        "semantic",
        "compatibility",
        "dependencies",
        "safety",
    ] {
        assert!(report.contains(&format!("stage: {stage}")));
    }

    let first = run(
        &[
            "--workspace",
            &workspace_arg,
            "plugin",
            "install",
            &plugin_arg,
        ],
        temporary.path(),
    );
    assert_eq!(first.status.code(), Some(0), "{}", text(&first.stderr));
    assert!(text(&first.stdout).contains("installed plugin"));

    let second = run(
        &[
            "--workspace",
            &workspace_arg,
            "plugin",
            "install",
            &plugin_arg,
        ],
        temporary.path(),
    );
    assert_eq!(second.status.code(), Some(0), "{}", text(&second.stderr));
    assert!(text(&second.stdout).contains("already installed"));
    let audit_log =
        fs::read_to_string(workspace.join("audit/events.jsonl")).expect("audit log must exist");
    assert_eq!(audit_log.lines().count(), 2);
    assert!(audit_log.contains("\"action\":\"plugin.install\""));
    assert!(audit_log.contains("\"outcome\":\"succeeded\""));

    let list = run(
        &["--workspace", &workspace_arg, "tool", "list"],
        temporary.path(),
    );
    assert_eq!(list.status.code(), Some(0), "{}", text(&list.stderr));
    let list_output = text(&list.stdout);
    assert!(list_output.contains("example-echo"));
    assert!(list_output.contains("0.1.0"));
    assert!(list_output.contains("echo"));
    assert!(list_output.contains("low"));
    assert!(list_output.contains("true"));

    let info = run(
        &[
            "--workspace",
            &workspace_arg,
            "tool",
            "info",
            "example-echo",
        ],
        temporary.path(),
    );
    assert_eq!(info.status.code(), Some(0), "{}", text(&info.stderr));
    let info_output = text(&info.stdout);
    assert!(info_output.contains("displayName: Example Echo"));
    assert!(info_output.contains("runtimeMode: process"));
    assert!(info_output.contains("inputSchema: schemas/input.schema.json"));

    let input = plugin.join("examples/input.json");
    let execution_output = run(
        &[
            "--workspace",
            &workspace_arg,
            "tool",
            "run",
            "example-echo",
            "--input",
            &input.to_string_lossy(),
            "--authorization-scope",
            "local:echo",
        ],
        temporary.path(),
    );
    assert_eq!(
        execution_output.status.code(),
        Some(0),
        "{}",
        text(&execution_output.stderr)
    );
    let result: serde_json::Value =
        serde_json::from_slice(&execution_output.stdout).expect("execution result must be JSON");
    assert_eq!(result["status"], "succeeded");
    assert_eq!(
        result["output"]["spec"]["values"]["message"],
        "hello from a synthetic fixture"
    );
    assert_eq!(
        result["output"]["spec"]["findings"][0]["title"],
        "Example echo completed"
    );
    for field in ["taskId", "runId", "stepId", "toolId", "correlationId"] {
        assert!(
            result["identifiers"][field]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "missing identifier {field}"
        );
    }
    let audit_log =
        fs::read_to_string(workspace.join("audit/events.jsonl")).expect("audit log must exist");
    for action in [
        "tool.run.requested",
        "tool.run.started",
        "tool.run.finished",
        "result.normalized",
    ] {
        assert!(audit_log.contains(&format!("\"action\":\"{action}\"")));
    }
    for field in [
        "taskId",
        "runId",
        "stepId",
        "toolId",
        "actorId",
        "correlationId",
    ] {
        assert!(audit_log.contains(&format!("\"{field}\":")));
    }
    let run_id = result["identifiers"]["runId"]
        .as_str()
        .expect("run id")
        .to_owned();
    assert!(workspace.join(format!("runs/{run_id}.json")).is_file());
    assert!(workspace.join(format!("results/{run_id}.json")).is_file());
    assert!(workspace.join("state.db").is_file());

    let report = run(
        &[
            "--workspace",
            &workspace_arg,
            "report",
            "generate",
            "--run",
            &run_id,
        ],
        temporary.path(),
    );
    assert_eq!(report.status.code(), Some(0), "{}", text(&report.stderr));
    let report_path = workspace.join(format!("reports/{run_id}.md"));
    let markdown = fs::read_to_string(report_path).expect("report must exist");
    for section in [
        "## Summary",
        "## Target",
        "## Tool",
        "## Findings",
        "## Evidence",
        "## Errors",
        "## Audit Summary",
    ] {
        assert!(markdown.contains(section));
    }

    let export = run(
        &[
            "--workspace",
            &workspace_arg,
            "result",
            "export",
            "--run",
            &run_id,
            "--format",
            "jsonl",
        ],
        temporary.path(),
    );
    assert_eq!(export.status.code(), Some(0), "{}", text(&export.stderr));
    assert!(text(&export.stdout).contains("\"kind\":\"Finding\""));

    let audit = run(
        &["--workspace", &workspace_arg, "audit", "list"],
        temporary.path(),
    );
    assert_eq!(audit.status.code(), Some(0), "{}", text(&audit.stderr));
    assert!(text(&audit.stdout).contains("report.generated"));
}

#[test]
fn invalid_plugin_still_prints_all_validation_stages() {
    let root = workspace_root();
    let source = root.join("plugins/examples/example-echo");
    let temporary = TempDir::new().expect("temporary directory must be created");
    let invalid = temporary.path().join("invalid-plugin");
    copy_directory(&source, &invalid);
    fs::remove_dir_all(invalid.join("parser")).expect("parser directory must be removed");

    let output = run(
        &["plugin", "validate", &invalid.to_string_lossy()],
        temporary.path(),
    );
    assert_eq!(output.status.code(), Some(3));
    let report = text(&output.stdout);
    for stage in [
        "structure",
        "semantic",
        "compatibility",
        "dependencies",
        "safety",
    ] {
        assert!(report.contains(&format!("stage: {stage}")));
    }
    assert!(report.contains("stage: dependencies"));
    assert!(report.contains("passed: false"));
    assert!(text(&output.stderr).contains("\"code\":\"SchemaValidationFailed\""));
}

#[test]
#[allow(clippy::too_many_lines)]
fn tool_run_cli_rejects_missing_tool_input_and_authorization() {
    let root = workspace_root();
    let plugin = root.join("plugins/examples/example-echo");
    let temporary = TempDir::new().expect("temporary directory must be created");
    let workspace = temporary.path().join(".sentinelflow");
    let workspace_arg = workspace.to_string_lossy();
    let plugin_arg = plugin.to_string_lossy();
    let install = run(
        &[
            "--workspace",
            &workspace_arg,
            "plugin",
            "install",
            &plugin_arg,
        ],
        temporary.path(),
    );
    assert_eq!(install.status.code(), Some(0), "{}", text(&install.stderr));

    let input = plugin.join("examples/input.json");
    let missing_tool = run(
        &[
            "--workspace",
            &workspace_arg,
            "tool",
            "run",
            "does-not-exist",
            "--input",
            &input.to_string_lossy(),
            "--authorization-scope",
            "local:echo",
        ],
        temporary.path(),
    );
    assert_eq!(missing_tool.status.code(), Some(5));

    let default_scope = run(
        &[
            "--workspace",
            &workspace_arg,
            "tool",
            "run",
            "example-echo",
            "--input",
            &input.to_string_lossy(),
        ],
        temporary.path(),
    );
    assert_eq!(
        default_scope.status.code(),
        Some(0),
        "{}",
        text(&default_scope.stderr)
    );

    let excessive_timeout = run(
        &[
            "--workspace",
            &workspace_arg,
            "tool",
            "run",
            "example-echo",
            "--input",
            &input.to_string_lossy(),
            "--authorization-scope",
            "local:echo",
            "--timeout-seconds",
            "6",
        ],
        temporary.path(),
    );
    assert_eq!(excessive_timeout.status.code(), Some(4));
    assert!(text(&excessive_timeout.stderr).contains("$.timeout"));

    let invalid_input = temporary.path().join("invalid-input.json");
    fs::write(&invalid_input, "{}").expect("invalid input fixture");
    let invalid = run(
        &[
            "--workspace",
            &workspace_arg,
            "tool",
            "run",
            "example-echo",
            "--input",
            &invalid_input.to_string_lossy(),
            "--authorization-scope",
            "local:echo",
        ],
        temporary.path(),
    );
    assert_eq!(invalid.status.code(), Some(3));
    assert!(text(&invalid.stderr).contains("SchemaValidationFailed"));

    let installed_manifest = workspace
        .join("plugins/example-echo")
        .join("sentinelflow.tool.yaml");
    let original_manifest =
        fs::read_to_string(&installed_manifest).expect("installed manifest must be readable");
    fs::write(
        &installed_manifest,
        original_manifest.replace(
            "apiVersion: sentinelflow.io/v1alpha1",
            "apiVersion: sentinelflow.io/v9",
        ),
    )
    .expect("manifest must be corrupted");
    let invalid_manifest = run(
        &[
            "--workspace",
            &workspace_arg,
            "tool",
            "run",
            "example-echo",
            "--input",
            &input.to_string_lossy(),
            "--authorization-scope",
            "local:echo",
        ],
        temporary.path(),
    );
    assert_eq!(invalid_manifest.status.code(), Some(3));
    fs::write(&installed_manifest, &original_manifest).expect("manifest must be restored");

    let invalid_parser_manifest =
        original_manifest.replace("name: example-echo-v1", "name: fixture-invalid-output-v1");
    fs::write(&installed_manifest, invalid_parser_manifest).expect("invalid parser manifest");
    let invalid_parser = run(
        &[
            "--workspace",
            &workspace_arg,
            "tool",
            "run",
            "example-echo",
            "--input",
            &input.to_string_lossy(),
            "--authorization-scope",
            "local:echo",
        ],
        temporary.path(),
    );
    assert_eq!(invalid_parser.status.code(), Some(3));
    assert!(text(&invalid_parser.stderr).contains("normalization contract"));
    let persisted_parser_error = fs::read_dir(workspace.join("results"))
        .expect("results directory")
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read_to_string(entry.path()).ok())
        .any(|content| content.contains("ParserOutputInvalid"));
    assert!(persisted_parser_error);
    let audit_log =
        fs::read_to_string(workspace.join("audit/events.jsonl")).expect("audit log must exist");
    assert!(audit_log.contains("\"action\":\"result.normalized\",\"outcome\":\"failed\""));
    assert!(audit_log.contains("\"action\":\"tool.run.failed\",\"outcome\":\"failed\""));
    fs::write(&installed_manifest, &original_manifest).expect("manifest must be restored");

    let high_risk_manifest = original_manifest
        .replace("risk: low", "risk: high")
        .replace("requiresApproval: false", "requiresApproval: true");
    fs::write(&installed_manifest, high_risk_manifest).expect("high risk manifest");
    let unapproved = run(
        &[
            "--workspace",
            &workspace_arg,
            "tool",
            "run",
            "example-echo",
            "--input",
            &input.to_string_lossy(),
            "--authorization-scope",
            "local:echo",
        ],
        temporary.path(),
    );
    assert_eq!(unapproved.status.code(), Some(4));
    let approved = run(
        &[
            "--workspace",
            &workspace_arg,
            "tool",
            "run",
            "example-echo",
            "--input",
            &input.to_string_lossy(),
            "--authorization-scope",
            "local:echo",
            "--approve-high-risk",
        ],
        temporary.path(),
    );
    assert_eq!(
        approved.status.code(),
        Some(0),
        "{}",
        text(&approved.stderr)
    );
    fs::write(&installed_manifest, &original_manifest).expect("manifest must be restored");

    fs::remove_file(workspace.join("plugins/example-echo/runner/echo.py"))
        .expect("runner must be removed");
    let missing_runner = run(
        &[
            "--workspace",
            &workspace_arg,
            "tool",
            "run",
            "example-echo",
            "--input",
            &input.to_string_lossy(),
            "--authorization-scope",
            "local:echo",
        ],
        temporary.path(),
    );
    assert_eq!(missing_runner.status.code(), Some(5));
    assert!(text(&missing_runner.stderr).contains("runner cannot be resolved"));
}

#[test]
#[allow(clippy::too_many_lines)]
fn p2_4_single_step_task_mvp_runs_end_to_end() {
    let root = workspace_root();
    let temporary = TempDir::new().expect("temporary directory");
    let workspace = temporary.path().join(".sentinelflow");
    let workspace_arg = workspace.to_string_lossy();
    let plugin = root.join("plugins/examples/example-echo");

    let init = run(&["--workspace", &workspace_arg, "init"], temporary.path());
    assert_eq!(init.status.code(), Some(0), "{}", text(&init.stderr));
    let validation = run(
        &["plugin", "validate", &plugin.to_string_lossy()],
        temporary.path(),
    );
    assert_eq!(
        validation.status.code(),
        Some(0),
        "{}",
        text(&validation.stderr)
    );
    let install = run(
        &[
            "--workspace",
            &workspace_arg,
            "plugin",
            "install",
            &plugin.to_string_lossy(),
        ],
        temporary.path(),
    );
    assert_eq!(install.status.code(), Some(0), "{}", text(&install.stderr));
    let list = run(
        &["--workspace", &workspace_arg, "tool", "list"],
        temporary.path(),
    );
    assert_eq!(list.status.code(), Some(0), "{}", text(&list.stderr));
    assert!(text(&list.stdout).contains("example-echo"));

    let tool_input = root.join("tests/fixtures/input.example.json");
    let tool_run = run(
        &[
            "--workspace",
            &workspace_arg,
            "tool",
            "run",
            "example-echo",
            "--input",
            &tool_input.to_string_lossy(),
        ],
        temporary.path(),
    );
    assert_eq!(
        tool_run.status.code(),
        Some(0),
        "{}",
        text(&tool_run.stderr)
    );

    let task_spec = root.join("tests/fixtures/task.single-step.yaml");
    let unauthorized_task = temporary.path().join("unauthorized-task.yaml");
    fs::write(
        &unauthorized_task,
        fs::read_to_string(&task_spec)
            .expect("task fixture")
            .replace("      - fixture-two\n", ""),
    )
    .expect("unauthorized task fixture");
    let denied = run(
        &[
            "--workspace",
            &workspace_arg,
            "task",
            "run",
            &unauthorized_task.to_string_lossy(),
        ],
        temporary.path(),
    );
    assert_eq!(denied.status.code(), Some(4));
    assert!(text(&denied.stderr).contains("AuthorizationDenied"));

    let missing_tool_task = temporary.path().join("missing-tool-task.yaml");
    fs::write(
        &missing_tool_task,
        fs::read_to_string(&task_spec)
            .expect("task fixture")
            .replace("toolRef: example-echo", "toolRef: example-missing"),
    )
    .expect("missing tool task fixture");
    let missing_tool = run(
        &[
            "--workspace",
            &workspace_arg,
            "task",
            "run",
            &missing_tool_task.to_string_lossy(),
        ],
        temporary.path(),
    );
    assert_eq!(missing_tool.status.code(), Some(5));
    assert!(text(&missing_tool.stderr).contains("tool is not registered"));

    let task_run = run(
        &[
            "--workspace",
            &workspace_arg,
            "task",
            "run",
            &task_spec.to_string_lossy(),
        ],
        temporary.path(),
    );
    assert_eq!(
        task_run.status.code(),
        Some(0),
        "{}",
        text(&task_run.stderr)
    );
    let task: serde_json::Value = serde_json::from_slice(&task_run.stdout).expect("task receipt");
    assert_eq!(task["status"], "completed");
    assert_eq!(task["runIds"].as_array().map(Vec::len), Some(2));
    let task_id = task["taskId"].as_str().expect("task id");

    let status = run(
        &["--workspace", &workspace_arg, "task", "status", task_id],
        temporary.path(),
    );
    assert_eq!(status.status.code(), Some(0), "{}", text(&status.stderr));
    assert!(text(&status.stdout).contains("\"status\": \"completed\""));

    let logs = run(
        &["--workspace", &workspace_arg, "task", "logs", task_id],
        temporary.path(),
    );
    assert_eq!(logs.status.code(), Some(0), "{}", text(&logs.stderr));
    assert!(text(&logs.stdout).contains("result.normalized"));

    let report = run(
        &[
            "--workspace",
            &workspace_arg,
            "report",
            "generate",
            "--task",
            task_id,
        ],
        temporary.path(),
    );
    assert_eq!(report.status.code(), Some(0), "{}", text(&report.stderr));
    let markdown =
        fs::read_to_string(workspace.join(format!("reports/{task_id}.md"))).expect("task report");
    assert!(markdown.contains("# SentinelFlow Task Report"));
    assert!(markdown.contains("Target: fixture-one"));
    assert!(markdown.contains("Target: fixture-two"));

    let audit = run(
        &["--workspace", &workspace_arg, "audit", "list"],
        temporary.path(),
    );
    assert_eq!(audit.status.code(), Some(0), "{}", text(&audit.stderr));
    assert!(text(&audit.stdout).contains("report.generated"));
}

fn copy_directory(source: &Path, destination: &Path) {
    fs::create_dir(destination).expect("destination directory must be created");
    for entry in fs::read_dir(source).expect("source directory must be readable") {
        let entry = entry.expect("source entry must be readable");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if entry
            .file_type()
            .expect("file type must be readable")
            .is_dir()
        {
            copy_directory(&source_path, &destination_path);
        } else {
            fs::copy(source_path, destination_path).expect("file must be copied");
        }
    }
}
