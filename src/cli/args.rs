//! Clap argument definitions.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use ruso_runtime::ExecutorConfig;
use ruso_script::{CompileError, compile_program, parse};

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

    /// Save a registry PAT or session token for later use
    Login(LoginArgs),

    /// Delete the stored registry credential for the current registry
    Logout(RegistryOnlyArgs),

    /// Print the user the stored credential belongs to
    Whoami(RegistryOnlyArgs),

    /// Upload a `.ruso` script to the registry
    Publish(PublishArgs),

    /// Download a `<namespace>/<name>[@<range>]` script into the local cache
    Install(InstallArgs),

    /// Search published scripts on the registry
    Search(SearchArgs),
}

#[derive(Debug, Parser)]
pub struct ScriptArgs {
    /// Path to a `.ruso` file, a directory of `.ruso` files, or a registry
    /// reference like `<namespace>/<name>[@<semver-range>]`. Registry
    /// references resolve via the local install cache and the registry
    /// configured by `--registry` / `$RUSO_REGISTRY_URL`.
    #[arg(long, value_name = "PATH|REF")]
    pub script: String,
}

/// Common `--registry` flag shared by every command that talks to a
/// backend. Inlined via `#[command(flatten)]` rather than `global` so it
/// only appears on relevant subcommands.
#[derive(Debug, Parser)]
pub struct RegistryArgs {
    /// Registry base URL. Overrides `$RUSO_REGISTRY_URL` and the built-in
    /// default.
    #[arg(long, value_name = "URL")]
    pub registry: Option<String>,
}

#[derive(Debug, Parser)]
pub struct RegistryOnlyArgs {
    #[command(flatten)]
    pub registry: RegistryArgs,
}

#[derive(Debug, Parser)]
pub struct LoginArgs {
    #[command(flatten)]
    pub registry: RegistryArgs,
    /// PAT (`ruso_pat_...`) or session token (`ruso_sess_...`). Omit to
    /// read the token from stdin (single line).
    #[arg(long, value_name = "TOKEN")]
    pub token: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Visibility {
    Public,
    Private,
}

#[derive(Debug, Parser)]
pub struct PublishArgs {
    #[command(flatten)]
    pub registry: RegistryArgs,
    /// Path to a `.ruso` source file.
    #[arg(value_name = "PATH")]
    pub path: PathBuf,
    /// Visibility for the first publish of this script. Subsequent
    /// publishes inherit the existing visibility — change with PATCH
    /// (not yet exposed in the CLI).
    #[arg(long, value_enum)]
    pub visibility: Option<Visibility>,
    /// Override the namespace. Defaults to your username (from `/v1/me`).
    #[arg(long, value_name = "NAMESPACE")]
    pub namespace: Option<String>,
}

#[derive(Debug, Parser)]
pub struct InstallArgs {
    #[command(flatten)]
    pub registry: RegistryArgs,
    /// One or more `<namespace>/<name>[@<range>]` references.
    #[arg(value_name = "REF", required = true, num_args = 1..)]
    pub refs: Vec<String>,
    /// Re-download even if a matching version is already cached.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Parser)]
pub struct SearchArgs {
    #[command(flatten)]
    pub registry: RegistryArgs,
    /// Free-text query (matches name + description + tags).
    #[arg(value_name = "QUERY")]
    pub query: Option<String>,
    /// Filter by tag. Repeat for AND semantics (`--tag auth --tag rce`).
    #[arg(long, value_name = "TAG")]
    pub tag: Vec<String>,
    #[arg(long, value_name = "SEVERITY")]
    pub severity: Option<String>,
    #[arg(long, value_name = "CVE")]
    pub cve: Option<String>,
    #[arg(long, value_name = "NAMESPACE")]
    pub namespace: Option<String>,
    #[arg(long, default_value_t = 1, value_name = "N")]
    pub page: u32,
    #[arg(long, default_value_t = 20, value_name = "N")]
    pub per_page: u32,
    /// Emit results as JSON to stdout instead of the table view.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct ScanArgs {
    #[command(flatten)]
    pub script: ScriptArgs,

    /// Target URL (`https://…`) or path to a file with one URL per line
    #[arg(long, value_name = "URL|FILE")]
    pub target: String,

    /// Default connect timeout for HTTP and socket probes (per-probe `timeout`
    /// in scripts overrides this for HTTP).
    #[arg(long, default_value = "30s", value_name = "DURATION")]
    pub timeout: String,

    /// Per-read I/O timeout for TCP/UDP/DNS socket probes.
    #[arg(long, default_value = "10s", value_name = "DURATION")]
    pub read_timeout: String,

    /// Maximum HTTP response body size in bytes. Larger responses are
    /// truncated; matchers operate on the truncated body.
    #[arg(long, default_value_t = 10 * 1024 * 1024, value_name = "BYTES")]
    pub max_response_bytes: usize,

    /// Do not follow HTTP redirects
    #[arg(long)]
    pub no_follow_redirects: bool,

    /// Disable TLS certificate verification (HTTPS and TCP `tls` probes).
    /// Default is to verify — pass `--insecure` only for environments where
    /// you accept MITM/finding-injection risk (e.g. self-signed lab certs).
    #[arg(long)]
    pub insecure: bool,

    /// HTTP proxy URL (e.g. `http://127.0.0.1:8080`)
    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    /// Maximum number of (target × script) combinations to run in parallel.
    /// Increase for faster bulk scans; decrease to be gentler on targets.
    #[arg(short = 'c', long, default_value_t = 16, value_name = "N")]
    pub concurrency: usize,

    /// Maximum concurrent in-flight scans against a single host. `0` disables
    /// (only the global `-c` bound applies). Use this to keep a high `-c`
    /// from piling many connections onto one sensitive target while still
    /// allowing wide parallelism across many distinct hosts.
    #[arg(long, default_value_t = 0, value_name = "N")]
    pub max_per_host: usize,

    /// Cap on how often a new script run may start, in scripts per second.
    /// `0` disables the cap. This throttles *script-launch* rate at the
    /// orchestrator — an individual script can still send many probes once
    /// running, so this is a coarse safety cap, not a per-request limit.
    #[arg(long, default_value_t = 0, value_name = "RPS")]
    pub rps: u32,

    /// Wall-clock budget per script run. Hostile or buggy bytecode (huge
    /// `repeat`, deep loops) cannot run beyond this. Default `5m`.
    #[arg(long, default_value = "5m", value_name = "DURATION")]
    pub script_timeout: String,

    /// Report format: human prints findings to stdout; json/csv require --report
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Human)]
    pub output: OutputFormat,

    /// Write json/csv report to this file (required when --output is json or csv)
    #[arg(long, value_name = "PATH")]
    pub report: Option<PathBuf>,

    /// Registry to resolve `<namespace>/<name>[@<range>]` references against.
    #[command(flatten)]
    pub registry: RegistryArgs,
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
    /// Path to a `.bc` file, a directory of `.bc` files, or a registry
    /// reference like `<namespace>/<name>[@<semver-range>]`.
    #[arg(long, value_name = "PATH|REF")]
    pub bytecode: String,

    /// Target URL (`https://…`) or path to a file with one URL per line
    #[arg(long, value_name = "URL|FILE")]
    pub target: String,

    /// Default connect timeout for HTTP and socket probes.
    #[arg(long, default_value = "30s", value_name = "DURATION")]
    pub timeout: String,

    /// Per-read I/O timeout for TCP/UDP/DNS socket probes.
    #[arg(long, default_value = "10s", value_name = "DURATION")]
    pub read_timeout: String,

    /// Maximum HTTP response body size in bytes.
    #[arg(long, default_value_t = 10 * 1024 * 1024, value_name = "BYTES")]
    pub max_response_bytes: usize,

    #[arg(long)]
    pub no_follow_redirects: bool,

    /// Disable TLS certificate verification. See `scan --insecure`.
    #[arg(long)]
    pub insecure: bool,

    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    /// Maximum number of (target × bytecode) combinations to run in parallel.
    #[arg(short = 'c', long, default_value_t = 16, value_name = "N")]
    pub concurrency: usize,

    /// Maximum concurrent in-flight scans against a single host. See
    /// `scan --max-per-host`. `0` disables (default).
    #[arg(long, default_value_t = 0, value_name = "N")]
    pub max_per_host: usize,

    /// Cap on script-launch rate in scripts per second. See `scan --rps`.
    /// `0` disables (default).
    #[arg(long, default_value_t = 0, value_name = "RPS")]
    pub rps: u32,

    /// Wall-clock budget per script run. Default `5m`.
    #[arg(long, default_value = "5m", value_name = "DURATION")]
    pub script_timeout: String,

    #[arg(short, long, value_enum, default_value_t = OutputFormat::Human)]
    pub output: OutputFormat,

    #[arg(long, value_name = "PATH")]
    pub report: Option<PathBuf>,

    /// Registry to resolve `<namespace>/<name>[@<range>]` references against.
    #[command(flatten)]
    pub registry: RegistryArgs,
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

pub fn load_script(path: &std::path::Path) -> Result<String, ExitCode> {
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
    let default_timeout = parse_cli_duration(&args.timeout, "--timeout")?;
    let read_timeout = parse_cli_duration(&args.read_timeout, "--read-timeout")?;
    let max_script_duration = Some(parse_cli_duration(
        &args.script_timeout,
        "--script-timeout",
    )?);

    if args.insecure {
        tracing::warn!(
            "TLS verification disabled via --insecure; MITM can plant findings or expose request data"
        );
    }

    Ok(ExecutorConfig {
        base_url: String::new(),
        default_timeout,
        read_timeout,
        max_response_bytes: args.max_response_bytes,
        follow_redirect: !args.no_follow_redirects,
        verify_ssl: !args.insecure,
        proxy: args.proxy.clone(),
        max_script_duration,
    })
}

pub fn executor_base_config(args: &ScanArgs) -> Result<ExecutorConfig, ExitCode> {
    let default_timeout = parse_cli_duration(&args.timeout, "--timeout")?;
    let read_timeout = parse_cli_duration(&args.read_timeout, "--read-timeout")?;
    let max_script_duration = Some(parse_cli_duration(
        &args.script_timeout,
        "--script-timeout",
    )?);

    if args.insecure {
        tracing::warn!(
            "TLS verification disabled via --insecure; MITM can plant findings or expose request data"
        );
    }

    Ok(ExecutorConfig {
        base_url: String::new(),
        default_timeout,
        read_timeout,
        max_response_bytes: args.max_response_bytes,
        follow_redirect: !args.no_follow_redirects,
        verify_ssl: !args.insecure,
        proxy: args.proxy.clone(),
        max_script_duration,
    })
}

fn parse_cli_duration(value: &str, flag: &str) -> Result<std::time::Duration, ExitCode> {
    ruso_runtime::parse_duration(value).map_err(|err| {
        tracing::error!(value = %value, flag = %flag, error = %err, "invalid duration");
        ExitCode::from(1)
    })
}

pub fn executor_config_for_target(base: &ExecutorConfig, target: &str) -> ExecutorConfig {
    ExecutorConfig {
        base_url: target.to_string(),
        ..base.clone()
    }
}
