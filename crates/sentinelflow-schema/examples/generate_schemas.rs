//! Regenerates checked-in `v1alpha1` JSON Schema documents.

use std::io;
use std::path::PathBuf;

use sentinelflow_schema::v1alpha1::write_schema_documents;

fn main() -> io::Result<()> {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = workspace_root.join("schemas/v1alpha1");
    for path in write_schema_documents(output)? {
        println!("{}", path.display());
    }
    Ok(())
}
