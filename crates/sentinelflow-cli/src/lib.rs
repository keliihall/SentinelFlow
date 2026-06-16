//! Command-line interface implementation for `SentinelFlow`.

mod cli;
mod commands;
mod config;
mod error;
mod workspace;

pub use cli::Cli;
pub use cli::{
    ApprovalCommand, ApprovalDecisionArguments, ApprovalRequestArguments, AuditCommand, Command,
    ConfigCommand, FileArgument, PathArgument, PluginCommand, PolicyCommand,
    PolicyExplainArguments, ReportCommand, ReportGenerateArguments, ResultCommand, TaskCommand,
    TaskIdArgument, TaskRunArguments, ToolCommand,
};
pub use error::{CliError, ExitCode};

/// Executes one parsed command.
///
/// # Errors
///
/// Returns a stable CLI error for schema, policy, runtime, or system failures.
pub async fn execute(cli: Cli) -> Result<(), CliError> {
    commands::execute(cli).await
}
