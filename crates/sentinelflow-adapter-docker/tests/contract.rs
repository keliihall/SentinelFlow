//! Docker Adapter contract fixture using a fake local Docker CLI.

use std::{collections::BTreeMap, os::unix::fs::PermissionsExt, time::Duration};

use sentinelflow_adapter_docker::DockerAdapter;
use sentinelflow_runtime::{Adapter, ExecutionIdentifiers, ExecutionRequest, ExecutionStatus};
use sentinelflow_schema::v1alpha1::{
    AdapterKind, CapabilitySpec, DockerAdapterSpec, DockerNetworkPolicy, Metadata, ParserMode,
    ParserSpec, ProtocolVersion, RiskLevel, RuntimeMode, RuntimeSpec, ToolManifest,
    ToolManifestKind, ToolManifestSpec,
};
use tempfile::tempdir;

#[tokio::test]
async fn docker_adapter_contract_is_bounded_and_structured() {
    let directory = tempdir().unwrap();
    std::fs::create_dir(directory.path().join("examples")).unwrap();
    let fake_docker = directory.path().join("docker");
    std::fs::write(
        &fake_docker,
        "#!/bin/sh\ncat >/dev/null\nprintf '{\"message\":\"docker fixture\"}'\n",
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&fake_docker).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&fake_docker, permissions).unwrap();

    let manifest = ToolManifest {
        api_version: ProtocolVersion::V1Alpha1,
        kind: ToolManifestKind::Value,
        metadata: Metadata {
            name: "example-docker-adapter".to_owned(),
            namespace: None,
            uid: None,
            labels: BTreeMap::from([("sentinelflow.io/example".to_owned(), "true".to_owned())]),
            annotations: BTreeMap::new(),
        },
        spec: ToolManifestSpec {
            display_name: "Safe Docker Fixture".to_owned(),
            version: "0.1.0".to_owned(),
            capabilities: vec![CapabilitySpec {
                name: "fixture.echo".to_owned(),
                description: "Echo fixture data".to_owned(),
                risk: RiskLevel::Low,
                requires_approval: false,
            }],
            runtime: RuntimeSpec {
                adapter: AdapterKind::Docker,
                mode: RuntimeMode::Container,
                entrypoint: None,
                args: vec![],
                environment_allowlist: vec![],
                timeout_seconds: 5,
                output_limit_bytes: 1024,
                docker: Some(DockerAdapterSpec {
                    image: "sentinelflow/example-fixture:local".to_owned(),
                    command: vec![],
                    mounts: vec![],
                    network: DockerNetworkPolicy::None,
                    cpu_millis: 250,
                    memory_mib: 32,
                }),
                http: None,
                file_import: None,
            },
            parser: ParserSpec {
                mode: ParserMode::Builtin,
                name: "echo-v1".to_owned(),
            },
            input_schema: "unused".to_owned(),
            output_schema: "unused".to_owned(),
        },
        extensions: BTreeMap::new(),
    };
    let identifiers = ExecutionIdentifiers::generate("example-docker-adapter");
    let request = ExecutionRequest {
        identifiers,
        plugin_root: directory.path().to_path_buf(),
        manifest,
        capability: "fixture.echo".to_owned(),
        input: serde_json::json!({"fixture": true}),
        authorization_scope: Some("fixture:local-only".to_owned()),
        approved: false,
        timeout: Duration::from_secs(5),
    };

    let adapter = DockerAdapter::new(&fake_docker);
    let prepared = adapter.prepare(request).await.unwrap();
    let running = adapter.execute(prepared).await.unwrap();
    let result = adapter.collect(running).await.unwrap();
    assert_eq!(result.status, ExecutionStatus::Succeeded);
    assert_eq!(result.output.unwrap()["message"], "docker fixture");
}
