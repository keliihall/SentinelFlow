//! Runnable `SentinelFlow` API service.

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

use sentinelflow_api::{ApiConfig, development_router};
use sentinelflow_core::constants::ENV_PREFIX;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address = env::var(format!("{ENV_PREFIX}API_BIND"))
        .unwrap_or_else(|_| "127.0.0.1:8080".to_owned())
        .parse::<SocketAddr>()?;
    let workspace_dir = env::var(format!("{ENV_PREFIX}WORKSPACE_DIR"))
        .map_or_else(|_| PathBuf::from(".sentinelflow"), PathBuf::from);
    let schema_root = env::var(format!("{ENV_PREFIX}SCHEMA_ROOT"))
        .map_or_else(|_| PathBuf::from("."), PathBuf::from);

    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(
        listener,
        development_router(ApiConfig {
            workspace_dir,
            schema_root,
        }),
    )
    .await?;
    Ok(())
}
