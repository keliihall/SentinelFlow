//! Canonical product-wide identifiers.

/// Human-readable product name.
pub const PRODUCT_NAME: &str = "SentinelFlow";

/// Installed command-line binary name.
pub const CLI_BINARY: &str = "sentinelflow";

/// Local state directory relative to a user's selected workspace.
pub const WORKSPACE_DIR: &str = ".sentinelflow";

/// API group used by `SentinelFlow` protocol resources.
pub const API_GROUP: &str = "sentinelflow.io";

/// Prefix reserved for `SentinelFlow` environment variables.
pub const ENV_PREFIX: &str = "SENTINELFLOW_";

#[cfg(test)]
mod tests {
    use super::{API_GROUP, CLI_BINARY, ENV_PREFIX, PRODUCT_NAME, WORKSPACE_DIR};

    #[test]
    fn canonical_identifiers_are_stable() {
        assert_eq!(PRODUCT_NAME, "SentinelFlow");
        assert_eq!(CLI_BINARY, "sentinelflow");
        assert_eq!(WORKSPACE_DIR, ".sentinelflow");
        assert_eq!(API_GROUP, "sentinelflow.io");
        assert_eq!(ENV_PREFIX, "SENTINELFLOW_");
    }
}
