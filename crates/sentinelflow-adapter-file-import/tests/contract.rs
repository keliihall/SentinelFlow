//! File Import Adapter contract fixtures.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use sentinelflow_adapter_file_import::FileImportAdapter;
use sentinelflow_runtime::{Adapter, ExecutionIdentifiers, ExecutionRequest};
use sentinelflow_schema::v1alpha1::*;
use serde_json::json;

fn request(format: &str, content: &str) -> ExecutionRequest {
    ExecutionRequest {
        identifiers: ExecutionIdentifiers::generate("example-structured-import"),
        plugin_root: PathBuf::from("."),
        manifest: ToolManifest {
            api_version: ProtocolVersion::V1Alpha1,
            kind: ToolManifestKind::Value,
            metadata: Metadata {
                name: "example-structured-import".into(),
                namespace: None,
                uid: None,
                labels: BTreeMap::from([("sentinelflow.io/example".into(), "true".into())]),
                annotations: BTreeMap::new(),
            },
            spec: ToolManifestSpec {
                display_name: "Import".into(),
                version: "0.1.0".into(),
                capabilities: vec![CapabilitySpec {
                    name: "import".into(),
                    description: "fixture".into(),
                    risk: RiskLevel::Low,
                    requires_approval: false,
                }],
                runtime: RuntimeSpec {
                    adapter: AdapterKind::FileImport,
                    mode: RuntimeMode::Process,
                    entrypoint: None,
                    args: vec![],
                    environment_allowlist: vec![],
                    timeout_seconds: 5,
                    output_limit_bytes: 65536,
                    docker: None,
                    http: None,
                    file_import: Some(FileImportAdapterSpec {
                        formats: vec![
                            FileImportFormat::Json,
                            FileImportFormat::Jsonl,
                            FileImportFormat::Csv,
                        ],
                        max_bytes: 4096,
                        max_records: 10,
                    }),
                },
                parser: ParserSpec {
                    mode: ParserMode::Builtin,
                    name: "example-file-import-v1".into(),
                },
                input_schema: "unused".into(),
                output_schema: "unused".into(),
            },
            extensions: BTreeMap::new(),
        },
        capability: "import".into(),
        input: json!({"format": format, "content": content}),
        authorization_scope: Some("fixture:local-only".into()),
        approved: false,
        timeout: Duration::from_secs(1),
    }
}

#[tokio::test]
async fn imports_json_jsonl_and_csv_without_opening_paths() {
    let adapter = FileImportAdapter;
    for (format, content, count) in [
        ("json", r#"[{"id":1}]"#, 1),
        ("jsonl", "{\"id\":1}\n{\"id\":2}\n", 2),
        ("csv", "id,name\n1,fixture\n", 1),
    ] {
        let prepared = adapter
            .prepare(request(format, content))
            .await
            .expect("prepare");
        let running = adapter.execute(prepared).await.expect("execute");
        let result = adapter.collect(running).await.expect("collect");
        assert_eq!(
            result.output.unwrap()["records"].as_array().unwrap().len(),
            count
        );
    }
}
