//! JSON Schema generation for checked-in protocol documents.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use schemars::{JsonSchema, schema_for};
use serde_json::{Value, json};

use super::types::{
    AuditEvent, Capability, Evidence, Finding, Metadata, Policy, StandardError, TaskSpec,
    ToolInput, ToolManifest, ToolOutput,
};

/// One generated JSON Schema document.
#[derive(Clone, Debug)]
pub struct SchemaDocument {
    /// Repository filename.
    pub filename: &'static str,
    /// Pretty-printed schema JSON.
    pub json: String,
}

type SchemaPatch = fn(&mut Value);

fn document<T: JsonSchema>(
    filename: &'static str,
    patch: Option<SchemaPatch>,
) -> Result<SchemaDocument, serde_json::Error> {
    let schema = schema_for!(T);
    let mut value = serde_json::to_value(schema)?;
    if let Some(patch) = patch {
        patch(&mut value);
    }
    let mut document_json = serde_json::to_string_pretty(&value)?;
    document_json.push('\n');
    Ok(SchemaDocument {
        filename,
        json: document_json,
    })
}

fn require_approval_for_high_risk(schema: &mut Value) {
    let Some(capability) = schema
        .get_mut("definitions")
        .and_then(|definitions| definitions.get_mut("CapabilitySpec"))
        .and_then(Value::as_object_mut)
    else {
        return;
    };

    capability.insert(
        "allOf".to_owned(),
        json!([
            {
                "if": {
                    "properties": {
                        "risk": {
                            "enum": ["high", "critical"]
                        }
                    },
                    "required": ["risk"]
                },
                "then": {
                    "properties": {
                        "requiresApproval": {
                            "const": true
                        }
                    },
                    "required": ["requiresApproval"]
                }
            }
        ]),
    );
}

/// Generates every maintained `v1alpha1` JSON Schema.
///
/// # Errors
///
/// Returns a serialization error if a generated schema cannot be encoded as JSON.
pub fn schema_documents() -> Result<Vec<SchemaDocument>, serde_json::Error> {
    [
        document::<Metadata>("metadata.schema.json", None),
        document::<ToolManifest>(
            "tool-manifest.schema.json",
            Some(require_approval_for_high_risk),
        ),
        document::<Capability>(
            "capability.schema.json",
            Some(require_approval_for_high_risk),
        ),
        document::<ToolInput>("tool-input.schema.json", None),
        document::<ToolOutput>("tool-output.schema.json", None),
        document::<Finding>("finding.schema.json", None),
        document::<Evidence>("evidence.schema.json", None),
        document::<StandardError>("standard-error.schema.json", None),
        document::<AuditEvent>("audit-event.schema.json", None),
        document::<TaskSpec>("task-spec.schema.json", None),
        document::<Policy>("policy.schema.json", None),
    ]
    .into_iter()
    .collect()
}

/// Writes every maintained schema to `output_directory`.
///
/// # Errors
///
/// Returns filesystem errors encountered while creating or writing documents.
pub fn write_schema_documents(output_directory: impl AsRef<Path>) -> io::Result<Vec<PathBuf>> {
    let output_directory = output_directory.as_ref();
    fs::create_dir_all(output_directory)?;

    schema_documents()
        .map_err(io::Error::other)?
        .into_iter()
        .map(|document| {
            let path = output_directory.join(document.filename);
            fs::write(&path, document.json)?;
            Ok(path)
        })
        .collect()
}
