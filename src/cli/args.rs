//! Clap argument definitions.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use ruso_runtime::ExecutorConfig;
use ruso_script::{compile_program, parse, CompileError};

#[derive(Debug, Parser)]
#[command(
    name = "ruso",
    version,
    about = "Run Ruso vulnerability scan scripts",
    long_about = "Commands: scan, validate, compile, exec.\n\
                  Use RUST_LOG to override log levels (e.g. RUST_LOG=ruso=debug)."
)]
pub struct Cli {
    /// Less logging (-q once: warn, twice: error)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub quiet: u8,

    /// More logging (-v: debug, -vv: trace)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Parse, compile, and run a `.ruso` script against targets
    Scan(ScanArgs),

    /// Validate `.ruso` syntax (no network I/O)
    Validate(ValidateArgs),

    /// Compile `.ruso` to hex bytecode (writes `<name>.bc` next to each script)
    Compile(CompileArgs),

    /// Run compiled `.bc` against targets
    Exec(ExecArgs),
}

#[derive(Debug, Parser)]
pub struct ScriptArgs {
    /// Path to a `.ruso` file, or a directory (all `.ruso` files inside, recursively)
    #[arg(long, value_name = "PATH")]
    pub script: PathBuf,
}

#[derive(Debug, Parser)]
pub struct ScanArgs {
    #[command(flatten)]
    pub script: ScriptArgs,

    /// Target URL (`https://…`) or path to a file with one URL per line
    #[arg(long, value_name = "URL|FILE")]
    pub target: String,

    /// Default HTTP timeout for probes without an explicit timeout
    #[arg(long, default_value = "30s", value_name = "DURATION")]
    pub timeout: String,

    /// Do not follow HTTP redirects
    #[arg(long)]
    pub no_follow_redirects: bool,

    /// Verify TLS certificates for HTTPS and TCP `tls` probes (default: skip verify, scanner mode)
    #[arg(long)]
    pub verify_tls: bool,

    /// HTTP proxy URL (e.g. `http://127.0.0.1:8080`)
    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    /// Report format: human prints findings to stdout; json/csv require --report
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Human)]
    pub output: OutputFormat,

    /// Write json/csv report to this file (required when --output is json or csv)
    #[arg(long, value_name = "PATH")]
    pub report: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct ValidateArgs {
    #[command(flatten)]
    pub script: ScriptArgs,
}

#[derive(Debug, Parser)]
pub struct CompileArgs {
    #[command(flatten)]
    pub script: ScriptArgs,
}

#[derive(Debug, Parser)]
pub struct ExecArgs {
    /// Path to a `.bc` file, or a directory (all `.bc` files inside, recursively)
    #[arg(long, value_name = "PATH")]
    pub bytecode: PathBuf,

    /// Target URL (`https://…`) or path to a file with one URL per line
    #[arg(long, value_name = "URL|FILE")]
    pub target: String,

    #[arg(long, default_value = "30s", value_name = "DURATION")]
    pub timeout: String,

    #[arg(long)]
    pub no_follow_redirects: bool,

    #[arg(long)]
    pub verify_tls: bool,

    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    #[arg(short, long, value_enum, default_value_t = OutputFormat::Human)]
    pub output: OutputFormat,

    #[arg(long, value_name = "PATH")]
    pub report: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Human,
    Json,
    Csv,
}

/// Resolved log verbosity from global `-q` / `-v` flags (before `RUST_LOG` override).
#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub fn default_filter(self) -> &'static str {
        match self {
            LogLevel::Error => "ruso=error,reqwest=error",
            LogLevel::Warn => "ruso=warn,reqwest=warn",
            LogLevel::Info => "ruso=off,reqwest=off",
            LogLevel::Debug => "ruso_runtime::runtime::http=debug,ruso=warn,reqwest=warn",
            LogLevel::Trace => "ruso=trace,reqwest=debug",
        }
    }
}

impl Cli {
    pub fn log_level(&self) -> LogLevel {
        let level = self.verbose as i32 - self.quiet as i32;
        match level {
            ..=-2 => LogLevel::Error,
            -1 => LogLevel::Warn,
            0 => LogLevel::Info,
            1 => LogLevel::Debug,
            _ => LogLevel::Trace,
        }
    }

    pub fn is_verbose(&self) -> bool {
        self.verbose > 0
    }

    pub fn log_filter(&self) -> &'static str {
        self.log_level().default_filter()
    }
}

pub fn load_script(path: &PathBuf) -> Result<String, ExitCode> {
    std::fs::read_to_string(path).map_err(|err| {
        tracing::error!(script = %path.display(), error = %err, "failed to read script");
        ExitCode::from(1)
    })
}

pub fn validate_source(source: &str, path_display: &str) -> Result<(), ExitCode> {
    let program = parse(source).map_err(|err| {
        tracing::error!(script = %path_display, error = %err, "validation failed");
        ExitCode::from(1)
    })?;
    compile_program(&program).map_err(|err| {
        let message = match err {
            CompileError::MissingFindingTitle => {
                "missing `name` or `report` metadata (required when using match/evidence)"
            }
        };
        tracing::error!(script = %path_display, error = %message, "validation failed");
        ExitCode::from(1)
    })?;
    Ok(())
}

pub fn executor_config_from_exec(args: &ExecArgs) -> Result<ExecutorConfig, ExitCode> {
    let default_timeout = ruso_runtime::parse_duration(&args.timeout).map_err(|err| {
        tracing::error!(timeout = %args.timeout, error = %err, "invalid --timeout");
        ExitCode::from(1)
    })?;

    Ok(ExecutorConfig {
        base_url: String::new(),
        default_timeout,
        follow_redirect: !args.no_follow_redirects,
        verify_ssl: args.verify_tls,
        proxy: args.proxy.clone(),
    })
}

pub fn executor_base_config(args: &ScanArgs) -> Result<ExecutorConfig, ExitCode> {
    let default_timeout = ruso_runtime::parse_duration(&args.timeout).map_err(|err| {
        tracing::error!(timeout = %args.timeout, error = %err, "invalid --timeout");
        ExitCode::from(1)
    })?;

    Ok(ExecutorConfig {
        base_url: String::new(),
        default_timeout,
        follow_redirect: !args.no_follow_redirects,
        verify_ssl: args.verify_tls,
        proxy: args.proxy.clone(),
    })
}

pub fn executor_config_for_target(base: &ExecutorConfig, target: &str) -> ExecutorConfig {
    ExecutorConfig {
        base_url: target.to_string(),
        ..base.clone()
    }
}
