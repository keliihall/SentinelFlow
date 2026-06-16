# v1alpha1 Schemas

This directory contains generated JSON Schema documents for
`sentinelflow.io/v1alpha1`.

Rust types in `sentinelflow-schema` are authoritative. Regenerate these documents
from the repository root:

```text
cargo run -p sentinelflow-schema --example generate_schemas
```

The contract test compares generated output byte-for-byte with these checked-in
files. Semantic constraints that require filesystem or cross-field context are
enforced by the Rust `Validate` trait.

See `docs/protocol-v1alpha1.md` for resource and validation details.
