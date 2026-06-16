//! Contract tests for `sentinelflow.io/v1alpha1`.

use std::fs;
use std::path::{Path, PathBuf};

use jsonschema::JSONSchema;
use sentinelflow_core::constants::API_GROUP;
use sentinelflow_schema::v1alpha1::{
    Finding, TaskSpec, ToolManifest, Validate, ValidationContext, from_json_slice, schema_documents,
};
use serde::de::DeserializeOwned;
use serde_json::Value;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("schema crate must be located under workspace/crates")
        .to_path_buf()
}

fn fixture(name: &str) -> Vec<u8> {
    let path = workspace_root().join("tests/fixtures/v1alpha1").join(name);
    fs::read(path).expect("fixture must be readable")
}

fn schema(name: &str) -> Value {
    let path = workspace_root().join("schemas/v1alpha1").join(name);
    serde_json::from_slice(&fs::read(path).expect("schema must be readable"))
        .expect("checked-in schema must be valid JSON")
}

fn assert_json_schema_accepts(schema_name: &str, bytes: &[u8]) {
    let schema = schema(schema_name);
    let compiled = JSONSchema::compile(&schema).expect("generated schema must compile");
    let instance: Value = serde_json::from_slice(bytes).expect("fixture must be valid JSON");
    if let Err(errors) = compiled.validate(&instance) {
        let messages = errors.map(|error| error.to_string()).collect::<Vec<_>>();
        panic!("expected schema acceptance, got: {messages:?}");
    }
}

fn assert_json_schema_rejects_at(schema_name: &str, bytes: &[u8], expected_path: &str) {
    let schema = schema(schema_name);
    let compiled = JSONSchema::compile(&schema).expect("generated schema must compile");
    let instance: Value = serde_json::from_slice(bytes).expect("fixture must be valid JSON");
    let errors = compiled
        .validate(&instance)
        .expect_err("fixture must be rejected")
        .map(|error| (error.instance_path.to_string(), error.to_string()))
        .collect::<Vec<_>>();
    let expected_field = expected_path
        .rsplit('/')
        .next()
        .expect("expected path must contain a field");
    assert!(
        errors
            .iter()
            .any(|(path, message)| path == expected_path || message.contains(expected_field)),
        "expected error for {expected_path}, got {errors:?}"
    );
}

fn decode_and_validate<T>(bytes: &[u8]) -> Result<(), String>
where
    T: DeserializeOwned + Validate,
{
    let value: T = from_json_slice(bytes).map_err(|error| error.to_string())?;
    value
        .validate(&ValidationContext::new(workspace_root()))
        .map_err(|error| error.to_string())
}

#[test]
fn checked_in_schemas_match_rust_types() {
    for document in schema_documents().expect("Rust schemas must serialize") {
        let path = workspace_root()
            .join("schemas/v1alpha1")
            .join(document.filename);
        let checked_in = fs::read_to_string(&path).expect("checked-in schema must be readable");
        assert_eq!(
            checked_in,
            document.json,
            "{} is stale; run the schema generator example",
            path.display()
        );
    }
}

#[test]
fn all_checked_in_schemas_compile() {
    for document in schema_documents().expect("Rust schemas must serialize") {
        let schema: Value =
            serde_json::from_str(&document.json).expect("generated schema must be JSON");
        JSONSchema::compile(&schema)
            .unwrap_or_else(|error| panic!("{} did not compile: {error}", document.filename));
    }
}

#[test]
fn every_resource_schema_has_the_common_envelope() {
    let resource_schemas = [
        "tool-manifest.schema.json",
        "capability.schema.json",
        "tool-input.schema.json",
        "tool-output.schema.json",
        "finding.schema.json",
        "evidence.schema.json",
        "standard-error.schema.json",
        "audit-event.schema.json",
        "task-spec.schema.json",
        "policy.schema.json",
    ];

    for schema_name in resource_schemas {
        let schema = schema(schema_name);
        let properties = schema["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{schema_name} must define object properties"));
        for field in ["apiVersion", "kind", "metadata", "extensions"] {
            assert!(
                properties.contains_key(field),
                "{schema_name} must support {field}"
            );
        }
    }
}

#[test]
fn api_version_uses_the_canonical_api_group() {
    assert_eq!(
        sentinelflow_schema::v1alpha1::API_VERSION,
        format!("{API_GROUP}/v1alpha1")
    );
}

#[test]
fn valid_tool_manifest_passes_structure_and_semantics() {
    let bytes = fixture("valid-tool-manifest.json");
    assert_json_schema_accepts("tool-manifest.schema.json", &bytes);
    decode_and_validate::<ToolManifest>(&bytes).expect("valid manifest must pass");
}

#[test]
fn invalid_tool_manifest_reports_semantic_field_paths() {
    let bytes = fixture("invalid-tool-manifest.json");
    assert_json_schema_rejects_at(
        "tool-manifest.schema.json",
        &bytes,
        "/spec/capabilities/0/requiresApproval",
    );

    let error = decode_and_validate::<ToolManifest>(&bytes).expect_err("manifest must be rejected");
    assert!(error.contains("$.spec.capabilities[0].requiresApproval"));
    assert!(error.contains("$.spec.inputSchema"));
}

#[test]
fn valid_task_spec_passes_structure_and_semantics() {
    let bytes = fixture("valid-task-spec.json");
    assert_json_schema_accepts("task-spec.schema.json", &bytes);
    decode_and_validate::<TaskSpec>(&bytes).expect("valid task spec must pass");
}

#[test]
fn invalid_task_spec_is_rejected_at_authorization_scope() {
    let bytes = fixture("invalid-task-spec.json");
    assert_json_schema_rejects_at("task-spec.schema.json", &bytes, "/spec/authorizationScope");
    let error = decode_and_validate::<TaskSpec>(&bytes).expect_err("task spec must be rejected");
    assert!(
        error.contains("$.spec.authorizationScope"),
        "unexpected error: {error}"
    );
}

#[test]
fn blank_authorization_scope_is_semantically_rejected() {
    let mut value: Value =
        serde_json::from_slice(&fixture("valid-task-spec.json")).expect("fixture must be JSON");
    value["spec"]["authorizationScope"] = Value::String(" ".to_owned());
    let bytes = serde_json::to_vec(&value).expect("JSON value must serialize");

    assert_json_schema_accepts("task-spec.schema.json", &bytes);
    let error = decode_and_validate::<TaskSpec>(&bytes).expect_err("task spec must be rejected");
    assert!(
        error.contains("$.spec.authorizationScope"),
        "unexpected error: {error}"
    );
}

#[test]
fn valid_finding_passes_structure_and_semantics() {
    let bytes = fixture("valid-finding.json");
    assert_json_schema_accepts("finding.schema.json", &bytes);
    decode_and_validate::<Finding>(&bytes).expect("valid finding must pass");
}

#[test]
fn invalid_finding_is_rejected_at_title() {
    let bytes = fixture("invalid-finding.json");
    assert_json_schema_rejects_at("finding.schema.json", &bytes, "/spec/title");

    let error = decode_and_validate::<Finding>(&bytes).expect_err("finding must be rejected");
    assert!(error.contains("$.spec.title"), "unexpected error: {error}");
}

#[test]
fn invalid_api_version_and_kind_are_structurally_rejected() {
    let mut value: Value =
        serde_json::from_slice(&fixture("valid-finding.json")).expect("fixture must be JSON");
    value["apiVersion"] = Value::String("sentinelflow.io/v9".to_owned());
    value["kind"] = Value::String("ToolManifest".to_owned());
    let bytes = serde_json::to_vec(&value).expect("JSON value must serialize");

    assert_json_schema_rejects_at("finding.schema.json", &bytes, "/apiVersion");
    assert_json_schema_rejects_at("finding.schema.json", &bytes, "/kind");

    let error = from_json_slice::<Finding>(&bytes).expect_err("resource must be rejected");
    assert!(
        error.path.contains("apiVersion") || error.message.contains("sentinelflow.io/v9"),
        "unexpected error: {error}"
    );
}

#[test]
fn manifest_without_runtime_mode_is_structurally_rejected() {
    let mut value: Value =
        serde_json::from_slice(&fixture("valid-tool-manifest.json")).expect("fixture must be JSON");
    value["spec"]["runtime"]
        .as_object_mut()
        .expect("runtime must be an object")
        .remove("mode");
    let bytes = serde_json::to_vec(&value).expect("JSON value must serialize");

    assert_json_schema_rejects_at("tool-manifest.schema.json", &bytes, "/spec/runtime/mode");
    let error = from_json_slice::<ToolManifest>(&bytes).expect_err("manifest must be rejected");
    assert!(
        error.path.contains("runtime") || error.message.contains("mode"),
        "unexpected error: {error}"
    );
}
