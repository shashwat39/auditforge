use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "auditforge",
    version,
    about = "Normalize Linux auditd log records as JSON Lines"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Read an audit log once and write one JSON object per line.
    Parse {
        /// Audit log path, or `-` to read standard input.
        #[arg(long, value_name = "PATH")]
        input: String,
    },
    /// Follow an audit log until SIGTERM or SIGINT.
    Run {
        /// Audit log path to read and follow.
        #[arg(long, value_name = "PATH")]
        input: String,
    },
    /// Print the AuditForge version.
    Version,
}
