//! Clap command definitions.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Parsed `sentinelflow` command line.
#[derive(Debug, Parser)]
#[command(
    name = "sentinelflow",
    version,
    about = "Manage external security validation tools under policy control",
    long_about = None
)]
pub struct Cli {
    /// Override the local `SentinelFlow` workspace directory.
    #[arg(long, global = true, value_name = "PATH")]
    pub workspace: Option<PathBuf>,

    /// Override the repository root used to resolve protocol Schema paths.
    #[arg(long, global = true, value_name = "PATH")]
    pub schema_root: Option<PathBuf>,

    /// Override the configured log level.
    #[arg(long, global = true, value_name = "LEVEL")]
    pub log_level: Option<String>,

    /// Override the configured API endpoint without starting an API service.
    #[arg(long, global = true, value_name = "URL")]
    pub api_endpoint: Option<String>,

    /// Override the configured authentication token.
    #[arg(long, global = true, value_name = "TOKEN")]
    pub auth_token: Option<String>,

    /// Command to execute.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level command groups.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Initialize a local `.sentinelflow` workspace.
    Init,
    /// Inspect effective configuration.
    Config {
        /// Configuration command.
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Manage tool manifests.
    Tool {
        /// Tool command.
        #[command(subcommand)]
        command: ToolCommand,
    },
    /// Manage task specifications.
    Task {
        /// Task command.
        #[command(subcommand)]
        command: TaskCommand,
    },
    /// Manage plugins.
    Plugin {
        /// Plugin command.
        #[command(subcommand)]
        command: PluginCommand,
    },
    /// Work with normalized results.
    Result {
        /// Result command.
        #[command(subcommand)]
        command: ResultCommand,
    },
    /// Generate reports.
    Report {
        /// Report command.
        #[command(subcommand)]
        command: ReportCommand,
    },
    /// Inspect audit events.
    Audit {
        /// Audit command.
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Explain policy decisions.
    Policy {
        /// Policy command.
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Manage approval requests.
    Approval {
        /// Approval command.
        #[command(subcommand)]
        command: ApprovalCommand,
    },
}

/// Configuration commands.
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Show merged configuration with sensitive values masked.
    Show,
}

/// Tool commands.
#[derive(Debug, Subcommand)]
pub enum ToolCommand {
    /// Validate a Tool Manifest without executing it.
    Validate(FileArgument),
    /// List registered tools.
    List,
    /// Show tool information.
    Info {
        /// Tool name.
        name: String,
    },
    /// Run a tool through the controlled runtime.
    Run(ToolRunArguments),
}

/// Task commands.
#[derive(Debug, Subcommand)]
pub enum TaskCommand {
    /// Validate a Task Spec without executing it.
    Validate(FileArgument),
    /// Run a task.
    Run(TaskRunArguments),
    /// Validate and preview a task DAG without executing it.
    Plan(FileArgument),
    /// Show task status.
    Status(TaskIdArgument),
    /// Show task logs.
    Logs(TaskIdArgument),
    /// Request cancellation of a running task.
    Cancel(TaskIdArgument),
    /// Pause scheduling after active nodes finish.
    Pause(TaskIdArgument),
    /// Resume a paused, cancelled, or failed task from its snapshots.
    Resume(TaskIdArgument),
}

/// Plugin commands.
#[derive(Debug, Subcommand)]
pub enum PluginCommand {
    /// Create a safe Python SDK plugin package.
    Scaffold(PathArgument),
    /// Validate and execute a plugin's fixture in a temporary workspace.
    Test(PathArgument),
    /// Validate a plugin package.
    Validate(PathArgument),
    /// Install a plugin package.
    Install(PathArgument),
}

/// Result commands.
#[derive(Debug, Subcommand)]
pub enum ResultCommand {
    /// Normalize a result.
    Normalize,
    /// Export a normalized result.
    Export(ResultExportArguments),
}

/// Report commands.
#[derive(Debug, Subcommand)]
pub enum ReportCommand {
    /// Generate a report.
    Generate(ReportGenerateArguments),
}

/// Audit commands.
#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// List audit events.
    List,
}

/// Policy inspection commands.
#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Explain Task Policy decisions without executing tools.
    Explain(PolicyExplainArguments),
}

/// Approval lifecycle commands.
#[derive(Debug, Subcommand)]
pub enum ApprovalCommand {
    /// Create a pending approval request.
    Request(ApprovalRequestArguments),
    /// Approve a pending request.
    Approve(ApprovalDecisionArguments),
    /// Reject a pending request.
    Reject(ApprovalDecisionArguments),
    /// Expire a pending request.
    Expire(ApprovalDecisionArguments),
}

/// Arguments for Policy Explain.
#[derive(Debug, Args)]
pub struct PolicyExplainArguments {
    /// Task Spec to evaluate.
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
}

/// Arguments for an approval request.
#[derive(Debug, Args)]
pub struct ApprovalRequestArguments {
    /// Task or run resource reference.
    #[arg(long)]
    pub resource: String,
    /// Requested risk level.
    #[arg(long, value_enum)]
    pub risk: RiskArgument,
    /// Requesting actor.
    #[arg(long, default_value = "local-cli")]
    pub actor: String,
}

/// Arguments for an approval decision.
#[derive(Debug, Args)]
pub struct ApprovalDecisionArguments {
    /// Approval identifier.
    pub approval_id: String,
    /// Decision actor.
    #[arg(long, default_value = "local-cli")]
    pub actor: String,
}

/// CLI risk values.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum RiskArgument {
    /// Low risk.
    Low,
    /// Medium risk.
    Medium,
    /// High risk.
    High,
    /// Critical risk.
    Critical,
}

/// A command argument that identifies an input file.
#[derive(Debug, Args)]
pub struct FileArgument {
    /// JSON resource file.
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
}

/// A command argument that identifies a plugin directory.
#[derive(Debug, Args)]
pub struct PathArgument {
    /// Plugin package directory.
    #[arg(value_name = "PATH")]
    pub path: PathBuf,
}

/// Arguments for one controlled tool execution.
#[derive(Debug, Args)]
pub struct ToolRunArguments {
    /// Registered tool name.
    pub tool: String,
    /// JSON input file.
    #[arg(long, value_name = "FILE")]
    pub input: PathBuf,
    /// Explicit authorization scope evaluated by Policy.
    #[arg(long, value_name = "SCOPE", default_value = "fixture:local-only")]
    pub authorization_scope: Option<String>,
    /// Explicit approval for high or critical risk capabilities.
    #[arg(long)]
    pub approve_high_risk: bool,
    /// Requested timeout in seconds.
    #[arg(long, value_name = "SECONDS")]
    pub timeout_seconds: Option<u64>,
    /// Actor identifier included in persisted logs and audit events.
    #[arg(long, value_name = "ACTOR", default_value = "local-cli")]
    pub actor_id: String,
    /// Non-sensitive target summary used in reports.
    #[arg(long, value_name = "TARGET", default_value = "local structured input")]
    pub target: String,
}

/// Supported normalized result export formats.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ExportFormat {
    /// Pretty-printed JSON artifact.
    Json,
    /// One normalized finding or error per line.
    Jsonl,
    /// Markdown report.
    Md,
}

/// Arguments for normalized result export.
#[derive(Debug, Args)]
pub struct ResultExportArguments {
    /// Run to export. Defaults to the most recent run.
    #[arg(long, value_name = "RUN_ID")]
    pub run: Option<String>,
    /// Export format.
    #[arg(long, value_enum, value_name = "FORMAT")]
    pub format: ExportFormat,
}

/// Arguments for Markdown report generation.
#[derive(Debug, Args)]
pub struct ReportGenerateArguments {
    /// Run to report.
    #[arg(
        long,
        value_name = "RUN_ID",
        conflicts_with = "task",
        required_unless_present = "task"
    )]
    pub run: Option<String>,
    /// Task to report.
    #[arg(
        long,
        value_name = "TASK_ID",
        conflicts_with = "run",
        required_unless_present = "run"
    )]
    pub task: Option<String>,
    /// Report template.
    #[arg(long, value_name = "TEMPLATE", default_value = "default")]
    pub template: String,
}

/// Arguments for a single-step task execution.
#[derive(Debug, Args)]
pub struct TaskRunArguments {
    /// YAML or JSON Task Spec.
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
    /// Actor identifier included in task logs.
    #[arg(long, value_name = "ACTOR", default_value = "local-cli")]
    pub actor_id: String,
}

/// Argument identifying a persisted task.
#[derive(Debug, Args)]
pub struct TaskIdArgument {
    /// Generated task identifier.
    #[arg(value_name = "TASK_ID")]
    pub task_id: String,
}
