//! Controlled Command Adapter success and failure contracts.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sentinelflow_adapter_command::CommandAdapter;
use sentinelflow_registry::validate_plugin;
use sentinelflow_runtime::{
    Adapter, ExecutionIdentifiers, ExecutionRequest, RuntimeEnvironment, RuntimeErrorKind,
};
use sentinelflow_schema::v1alpha1::RiskLevel;
use serde_json::{Value, json};
use tempfile::TempDir;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn copy_example() -> TempDir {
    let temporary = TempDir::new().expect("temporary directory");
    copy_directory(
        &workspace_root().join("plugins/examples/example-echo"),
        temporary.path(),
    );
    temporary
}

fn request(root: &Path, input: Value) -> ExecutionRequest {
    let plugin = validate_plugin(root)
        .expect("plugin validation must run")
        .into_validated()
        .expect("fixture plugin must be valid");
    ExecutionRequest {
        identifiers: ExecutionIdentifiers::generate("example-echo"),
        plugin_root: root.to_path_buf(),
        manifest: plugin.manifest,
        capability: "echo".to_owned(),
        input,
        authorization_scope: Some("local:echo".to_owned()),
        approved: false,
        timeout: Duration::from_secs(2),
    }
}

fn adapter() -> CommandAdapter {
    let mut values = BTreeMap::new();
    if let Ok(path) = std::env::var("PATH") {
        values.insert("PATH".to_owned(), path);
    }
    values.insert("UNLISTED_SECRET".to_owned(), "must-not-leak".to_owned());
    CommandAdapter::with_environment(RuntimeEnvironment { values })
}

#[tokio::test]
async fn example_echo_succeeds_with_normalized_output_and_identifiers() {
    let root = workspace_root().join("plugins/examples/example-echo");
    let request = request(&root, json!({"message": "hello"}));
    let expected = request.identifiers.clone();
    let adapter = adapter();
    let prepared = adapter.prepare(request).await.expect("prepare");
    let running = adapter.execute(prepared).await.expect("execute");
    let result = adapter.collect(running).await.expect("collect");

    assert_eq!(result.identifiers, expected);
    assert_eq!(result.output, Some(json!({"message": "hello"})));
    assert!(result.identifiers.task_id.starts_with("task-"));
    assert!(result.identifiers.run_id.starts_with("run-"));
    assert!(result.identifiers.step_id.starts_with("step-"));
    assert!(result.identifiers.correlation_id.starts_with("corr-"));
}

#[tokio::test]
async fn missing_authorization_and_unapproved_high_risk_are_denied() {
    let root = workspace_root().join("plugins/examples/example-echo");
    let adapter = adapter();

    let mut missing_scope = request(&root, json!({"message": "hello"}));
    missing_scope.authorization_scope = None;
    let error = adapter
        .prepare(missing_scope)
        .await
        .expect_err("missing scope must be denied");
    assert_eq!(error.kind, RuntimeErrorKind::PolicyDenied);
    assert_eq!(error.field.as_deref(), Some("$.authorizationScope"));

    let mut high_risk = request(&root, json!({"message": "hello"}));
    high_risk.manifest.spec.capabilities[0].risk = RiskLevel::High;
    high_risk.manifest.spec.capabilities[0].requires_approval = true;
    let error = adapter
        .prepare(high_risk)
        .await
        .expect_err("unapproved high risk must be denied");
    assert_eq!(error.kind, RuntimeErrorKind::PolicyDenied);
    assert_eq!(error.field.as_deref(), Some("$.approved"));

    let mut non_example = request(&root, json!({"message": "hello"}));
    non_example.manifest.metadata.name = "other-tool".to_owned();
    non_example.identifiers.tool_id = "other-tool".to_owned();
    let error = adapter
        .prepare(non_example)
        .await
        .expect_err("non-example tool must be denied");
    assert_eq!(error.kind, RuntimeErrorKind::PolicyDenied);
    assert_eq!(error.field.as_deref(), Some("$.toolId"));
}

#[tokio::test]
async fn invalid_input_missing_runner_and_path_traversal_are_rejected() {
    let temporary = copy_example();
    let adapter = adapter();

    let invalid_input = request(temporary.path(), json!({}));
    let error = adapter
        .prepare(invalid_input)
        .await
        .expect_err("invalid input must fail");
    assert_eq!(error.kind, RuntimeErrorKind::InputInvalid);

    let mut missing_runner = request(temporary.path(), json!({"message": "hello"}));
    missing_runner.manifest.spec.runtime.entrypoint = Some("runner/missing.py".to_owned());
    let error = adapter
        .prepare(missing_runner)
        .await
        .expect_err("missing runner must fail");
    assert_eq!(error.kind, RuntimeErrorKind::RunnerUnavailable);

    let mut traversal = request(temporary.path(), json!({"message": "hello"}));
    traversal.manifest.spec.runtime.entrypoint = Some("../outside".to_owned());
    let error = adapter
        .prepare(traversal)
        .await
        .expect_err("path traversal must fail");
    assert_eq!(error.kind, RuntimeErrorKind::InvalidPath);
}

#[tokio::test]
async fn timeout_is_enforced() {
    let temporary = copy_example();
    let adapter = adapter();

    write_runner(
        temporary.path(),
        "sleep.py",
        "#!/usr/bin/env python3\nimport time\ntime.sleep(5)\n",
    );
    let mut timeout = request(temporary.path(), json!({"message": "hello"}));
    timeout.manifest.spec.runtime.entrypoint = Some("runner/sleep.py".to_owned());
    timeout.timeout = Duration::from_millis(50);
    let prepared = adapter.prepare(timeout).await.expect("prepare timeout");
    let running = adapter.execute(prepared).await.expect("execute timeout");
    let error = adapter
        .collect(running)
        .await
        .expect_err("timeout must terminate");
    assert_eq!(error.kind, RuntimeErrorKind::Timeout);
}

#[tokio::test]
async fn abnormal_exit_is_reported() {
    let temporary = copy_example();
    let adapter = adapter();

    write_runner(
        temporary.path(),
        "exit.py",
        "#!/usr/bin/env python3\nraise SystemExit(7)\n",
    );
    let mut failed = request(temporary.path(), json!({"message": "hello"}));
    failed.manifest.spec.runtime.entrypoint = Some("runner/exit.py".to_owned());
    failed.timeout = Duration::from_secs(5);
    let prepared = adapter.prepare(failed).await.expect("prepare failure");
    let running = adapter.execute(prepared).await.expect("execute failure");
    let error = adapter
        .collect(running)
        .await
        .expect_err("abnormal exit must fail");
    assert_eq!(error.kind, RuntimeErrorKind::ExitFailure);
    assert!(!error.message.contains("stderr"));
}

#[tokio::test]
async fn output_limit_is_enforced() {
    let temporary = copy_example();
    let adapter = adapter();

    write_runner(
        temporary.path(),
        "large.py",
        "#!/usr/bin/env python3\nimport sys\nsys.stdout.write('x' * 80)\nsys.stdout.flush()\nsys.stderr.write('y' * 80)\n",
    );
    let mut large = request(temporary.path(), json!({"message": "hello"}));
    large.manifest.spec.runtime.entrypoint = Some("runner/large.py".to_owned());
    large.manifest.spec.runtime.output_limit_bytes = 128;
    large.timeout = Duration::from_secs(5);
    let prepared = adapter.prepare(large).await.expect("prepare large output");
    let running = adapter
        .execute(prepared)
        .await
        .expect("execute large output");
    let error = adapter
        .collect(running)
        .await
        .expect_err("large output must fail");
    assert_eq!(error.kind, RuntimeErrorKind::OutputLimit);
}

#[tokio::test]
async fn invalid_output_schema_is_rejected() {
    let temporary = copy_example();
    let adapter = adapter();

    write_runner(
        temporary.path(),
        "invalid-output.py",
        "#!/usr/bin/env python3\nimport json, sys\njson.dump({'message': 42}, sys.stdout)\n",
    );
    let mut invalid_output = request(temporary.path(), json!({"message": "hello"}));
    invalid_output.manifest.spec.runtime.entrypoint = Some("runner/invalid-output.py".to_owned());
    invalid_output.timeout = Duration::from_secs(5);
    let prepared = adapter
        .prepare(invalid_output)
        .await
        .expect("prepare invalid output");
    let running = adapter
        .execute(prepared)
        .await
        .expect("execute invalid output");
    let error = adapter
        .collect(running)
        .await
        .expect_err("invalid output Schema must fail");
    assert_eq!(error.kind, RuntimeErrorKind::OutputInvalid);
}

#[tokio::test]
async fn timeout_terminates_the_descendant_process_group() {
    let temporary = copy_example();
    let marker_root = TempDir::new().expect("marker directory");
    let marker = marker_root.path().join("descendant-survived");
    write_runner(
        temporary.path(),
        "descendant.py",
        "#!/usr/bin/env python3\n\
         import subprocess, sys, time\n\
         code = \"import pathlib,sys,time;time.sleep(0.3);pathlib.Path(sys.argv[1]).write_text('alive')\"\n\
         subprocess.Popen([sys.executable, '-c', code, sys.argv[1]])\n\
         time.sleep(5)\n",
    );
    let adapter = adapter();
    let mut request = request(temporary.path(), json!({"message": "hello"}));
    request.manifest.spec.runtime.entrypoint = Some("runner/descendant.py".to_owned());
    request.manifest.spec.runtime.args = vec![marker.display().to_string()];
    request.timeout = Duration::from_millis(50);
    let prepared = adapter.prepare(request).await.expect("prepare descendant");
    let running = adapter.execute(prepared).await.expect("execute descendant");
    let error = adapter
        .collect(running)
        .await
        .expect_err("timeout must terminate process group");
    assert_eq!(error.kind, RuntimeErrorKind::Timeout);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !marker.exists(),
        "descendant process survived group termination"
    );
}

#[tokio::test]
async fn caller_can_cancel_a_running_process() {
    let temporary = copy_example();
    write_runner(
        temporary.path(),
        "cancel.py",
        "#!/usr/bin/env python3\nimport time\ntime.sleep(5)\n",
    );
    let adapter = adapter();
    let mut request = request(temporary.path(), json!({"message": "hello"}));
    request.manifest.spec.runtime.entrypoint = Some("runner/cancel.py".to_owned());
    request.timeout = Duration::from_secs(4);
    let prepared = adapter.prepare(request).await.expect("prepare cancel");
    let running = adapter.execute(prepared).await.expect("execute cancel");
    let run_id = running.run_id().to_owned();
    let collector = adapter.clone();
    let collected = tokio::spawn(async move { collector.collect(running).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    adapter.cancel(&run_id).await.expect("cancel request");
    let error = collected
        .await
        .expect("collector task")
        .expect_err("cancelled run must fail");
    assert_eq!(error.kind, RuntimeErrorKind::Cancelled);
}

#[tokio::test]
async fn environment_is_allowlisted_and_arguments_are_not_shell_interpreted() {
    let temporary = copy_example();
    write_runner(
        temporary.path(),
        "environment.py",
        "#!/usr/bin/env python3\n\
         import json, os, sys\n\
         json.dump({'message': os.getcwd() + '|' + os.environ.get('UNLISTED_SECRET', 'absent') + '|' + sys.argv[1]}, sys.stdout)\n",
    );
    let adapter = adapter();
    let mut request = request(temporary.path(), json!({"message": "ignored"}));
    request.manifest.spec.runtime.entrypoint = Some("runner/environment.py".to_owned());
    request.manifest.spec.runtime.args = vec!["$(echo-not-executed)".to_owned()];
    let prepared = adapter.prepare(request).await.expect("prepare environment");
    let running = adapter
        .execute(prepared)
        .await
        .expect("execute environment");
    let result = adapter.collect(running).await.expect("collect environment");
    let message = result
        .output
        .as_ref()
        .and_then(|output| output["message"].as_str())
        .expect("message output");
    let mut parts = message.split('|');
    let working_directory = parts.next().expect("working directory");
    assert!(
        Path::new(working_directory)
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("sentinelflow-run-"))
    );
    assert!(!Path::new(working_directory).exists());
    assert_eq!(parts.next(), Some("absent"));
    assert_eq!(parts.next(), Some("$(echo-not-executed)"));
}

fn write_runner(root: &Path, name: &str, contents: &str) {
    let path = root.join("runner").join(name);
    fs::write(&path, contents).expect("runner must be written");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&path).expect("runner metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("runner permissions");
    }
}

fn copy_directory(source: &Path, destination: &Path) {
    for entry in fs::read_dir(source).expect("source directory") {
        let entry = entry.expect("source entry");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            fs::create_dir(&destination_path).expect("destination directory");
            copy_directory(&source_path, &destination_path);
        } else {
            fs::copy(source_path, destination_path).expect("copy file");
        }
    }
}
