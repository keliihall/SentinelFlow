//! `SentinelFlow` command-line entry point.

use std::process::ExitCode;

use clap::Parser;
use clap::error::ErrorKind;
use sentinelflow_cli::{Cli, CliError, execute};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            let _ = error.print();
            return ExitCode::SUCCESS;
        }
        Err(error) => return report_error(&CliError::argument(error.to_string())),
    };

    match execute(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => report_error(&error),
    }
}

fn report_error(error: &CliError) -> ExitCode {
    eprintln!("{}", error.to_standard_error_json());
    ExitCode::from(error.exit_code())
}
