//! Clap argument definitions and parse-command output helpers.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;

use ruso_runtime::ExecutorConfig;
use ruso_script::{parse, Program};

#[derive(Debug, Parser)]
#[command(
    name = "ruso",
    version,
    about = "Run vulnerability scan scripts written in the Ruso DSL",
    long_about = "Parse and execute .ruso scripts against HTTP/DNS/TCP targets.\n\
                  Use RUST_LOG to override default log levels (e.g. RUST_LOG=ruso=debug)."
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
    /// Execute a script against a target
    Scan(ScanArgs),

    /// Parse a script and validate syntax (no network I/O)
    Parse(ParseArgs),

    /// Compile a script to bytecode (no network I/O)
    Compile(CompileArgs),

    /// Execute precompiled bytecode hex or `@file.bc` against a target
    Exec(ExecArgs),
}

#[derive(Debug, Parser)]
pub struct ScanArgs {
    /// Path to a `.ruso` script, or a directory (all `.ruso` files inside, recursively)
    #[arg(long, value_name = "PATH")]
    pub script: PathBuf,

    /// Target URL (`https://…`) or path to a file with one URL per line
    #[arg(long, value_name = "URL|FILE")]
    pub target: String,

    /// Default HTTP timeout for probes without an explicit timeout
    #[arg(long, default_value = "30s", value_name = "DURATION")]
    pub timeout: String,

    /// Do not follow HTTP redirects
    #[arg(long)]
    pub no_follow_redirects: bool,

    /// Disable TLS certificate verification
    #[arg(long)]
    pub insecure: bool,

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
pub struct CompileArgs {
    /// Path to a `.ruso` script
    #[arg(long, value_name = "PATH")]
    pub script: PathBuf,

    /// Output format: hex (default), hex-dump, or human disassembly
    #[arg(short, long, value_enum, default_value_t = CompileFormat::Hex)]
    pub format: CompileFormat,

    /// Write raw bytecode bytes to this file (in addition to stdout output)
    #[arg(long, value_name = "PATH")]
    pub write: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum CompileFormat {
    /// Continuous lowercase hex (for `ruso exec --bytecode …`)
    #[default]
    Hex,
    /// Hex with offsets (xxd-style)
    #[value(name = "hex-dump")]
    HexDump,
    /// Human-readable disassembly (not executable hex)
    Disasm,
}

#[derive(Debug, Parser)]
pub struct ExecArgs {
    /// Hex bytecode or `@path` to raw `.bc` file (from `ruso compile`)
    #[arg(long, value_name = "HEX|@FILE")]
    pub bytecode: String,

    /// Target URL (`https://…`) or path to a file with one URL per line
    #[arg(long, value_name = "URL|FILE")]
    pub target: String,

    #[arg(long, default_value = "30s", value_name = "DURATION")]
    pub timeout: String,

    #[arg(long)]
    pub no_follow_redirects: bool,

    #[arg(long)]
    pub insecure: bool,

    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    #[arg(short, long, value_enum, default_value_t = OutputFormat::Human)]
    pub output: OutputFormat,

    #[arg(long, value_name = "PATH")]
    pub report: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct ParseArgs {
    /// Path to a `.ruso` script
    #[arg(long, value_name = "PATH")]
    pub script: PathBuf,

    /// Parse result format on stdout
    #[arg(short, long, value_enum, default_value_t = ParseFormat::Summary)]
    pub format: ParseFormat,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Human,
    Json,
    Csv,
}

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum ParseFormat {
    #[default]
    Summary,
    Json,
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

pub fn parse_script(source: &str) -> Result<Program, ExitCode> {
    parse(source).map_err(|err| {
        tracing::error!(error = %err, "parse failed");
        ExitCode::from(1)
    })
}

/// HTTP/DNS/TCP settings shared across targets (`base_url` is set per target).
pub fn executor_config_from_exec(args: &ExecArgs) -> Result<ExecutorConfig, ExitCode> {
    let default_timeout = ruso_runtime::parse_duration(&args.timeout).map_err(|err| {
        tracing::error!(timeout = %args.timeout, error = %err, "invalid --timeout");
        ExitCode::from(1)
    })?;

    Ok(ExecutorConfig {
        base_url: String::new(),
        default_timeout,
        follow_redirect: !args.no_follow_redirects,
        verify_ssl: !args.insecure,
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
        verify_ssl: !args.insecure,
        proxy: args.proxy.clone(),
    })
}

pub fn executor_config_for_target(base: &ExecutorConfig, target: &str) -> ExecutorConfig {
    ExecutorConfig {
        base_url: target.to_string(),
        ..base.clone()
    }
}

pub fn print_parse_result(program: &Program, format: ParseFormat) -> Result<(), ExitCode> {
    match format {
        ParseFormat::Summary => {
            let name = program_metadata_name(program);
            let mut out = String::new();
            if let Some(name) = name {
                writeln!(out, "check: {name}").ok();
            }
            writeln!(out, "statements: {}", program.statements.len()).ok();
            print!("{out}");
        }
        ParseFormat::Json => {
            let payload = ParseOutput {
                check: program_metadata_name(program),
                statement_count: program.statements.len(),
            };
            let json = serde_json::to_string_pretty(&payload).map_err(|err| {
                tracing::error!(error = %err, "failed to encode parse result");
                ExitCode::from(1)
            })?;
            println!("{json}");
        }
    }
    Ok(())
}

fn program_metadata_name(program: &Program) -> Option<String> {
    program.statements.iter().find_map(|stmt| {
        if let ruso_script::Stmt::Name(value) = stmt {
            Some(value.clone())
        } else {
            None
        }
    })
}

#[derive(Serialize)]
struct ParseOutput {
    check: Option<String>,
    statement_count: usize,
}
