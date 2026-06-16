//! HTTP Adapter contract fixture.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use axum::{Json, Router, routing::post};
use sentinelflow_adapter_http::HttpAdapter;
use sentinelflow_runtime::{Adapter, ExecutionIdentifiers, ExecutionRequest};
use sentinelflow_schema::v1alpha1::*;
use serde_json::{Value, json};

#[tokio::test]
async fn posts_to_loopback_fixture_and_returns_json() {
    let app = Router::new().route(
        "/fixture",
        post(|Json(value): Json<Value>| async move { Json(json!({"echo": value["message"]})) }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let request = request(format!("http://{address}/fixture"));
    let adapter = HttpAdapter::default();
    assert!(adapter.capabilities().asynchronous_tasks);
    let prepared = adapter.prepare(request).await.expect("prepare");
    let running = adapter.execute(prepared).await.expect("execute");
    let result = adapter.collect(running).await.expect("collect");
    assert_eq!(result.output.unwrap()["echo"], "fixture");
}

fn request(url: String) -> ExecutionRequest {
    ExecutionRequest {
        identifiers: ExecutionIdentifiers::generate("example-http-adapter"),
        plugin_root: PathBuf::from("."),
        manifest: ToolManifest {
            api_version: ProtocolVersion::V1Alpha1,
            kind: ToolManifestKind::Value,
            metadata: Metadata {
                name: "example-http-adapter".into(),
                namespace: None,
                uid: None,
                labels: BTreeMap::from([("sentinelflow.io/example".into(), "true".into())]),
                annotations: BTreeMap::new(),
            },
            spec: ToolManifestSpec {
                display_name: "HTTP".into(),
                version: "0.1.0".into(),
                capabilities: vec![CapabilitySpec {
                    name: "fixture".into(),
                    description: "fixture".into(),
                    risk: RiskLevel::Low,
                    requires_approval: false,
                }],
                runtime: RuntimeSpec {
                    adapter: AdapterKind::Http,
                    mode: RuntimeMode::Process,
                    entrypoint: None,
                    args: vec![],
                    environment_allowlist: vec![],
                    timeout_seconds: 5,
                    output_limit_bytes: 65536,
                    docker: None,
                    http: Some(HttpAdapterSpec {
                        url,
                        method: HttpMethod::Post,
                        headers: vec![],
                        retries: 1,
                        pagination: None,
                        polling: None,
                    }),
                    file_import: None,
                },
                parser: ParserSpec {
                    mode: ParserMode::Builtin,
                    name: "example-echo-v1".into(),
                },
                input_schema: "unused".into(),
                output_schema: "unused".into(),
            },
            extensions: BTreeMap::new(),
        },
        capability: "fixture".into(),
        input: json!({"message":"fixture"}),
        authorization_scope: Some("fixture:local-only".into()),
        approved: false,
        timeout: Duration::from_secs(2),
    }
}
