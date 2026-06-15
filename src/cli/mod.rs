//! CLI: argument parsing, scan orchestration, and terminal output.

mod args;
mod banner;
mod cmd_registry;
mod credentials;
pub mod discover;
mod install_store;
pub mod registry;
mod report;
mod scheme;
mod style;
mod targets;
mod throttle;
mod ui;

use std::path::Path;
use std::process;
use std::sync::Arc;
use std::time::Instant;

use clap::Parser as _;

pub use args::{Cli, Command, ScanArgs};

use ruso_runtime::{MAGIC, bytes_to_hex, hex_to_bytes};
use ruso_script::{
    BytecodeProgram, CompileError, compile_program, encode_bytecode, load_program, run_program,
};

use self::args::{
    executor_base_config, executor_config_for_target, executor_config_from_exec, load_script,
    validate_source,
};
use self::cmd_registry::{ScriptInput, resolve_bytecode_input, resolve_script_input};
use self::discover::bytecode_path_for_script;
use self::report::{
    ScanResultRecord, ScanRunReport, emit_scan_report, exit_code_from_report, print_finding_line,
    print_live_run, validate_report_options,
};
use self::throttle::{HostThrottle, RateLimiter};

/// Binary entry: parse argv, init logging, dispatch subcommands.
pub async fn run() -> process::ExitCode {
    // Branding first, before clap can exit on `--help`/`--version`/no
    // subcommand, so every interactive invocation shows it. The registry line
    // reflects `$RUSO_REGISTRY_URL` (or the built-in default); a per-command
    // `--registry` override isn't known this early. TTY-gated, so piped/CI runs
    // and the report on stdout stay clean.
    banner::print(&registry::resolve_base_url(None));

    let cli = Cli::parse();
    let verbose = cli.is_verbose();
    crate::logging::init(cli.log_filter(), verbose);
    // Spinners self-gate on this: dormant when verbose (logs are the progress).
    ui::init(verbose);

    match cli.command {
        Command::Validate(args) => cmd_validate(args),
        Command::Compile(args) => cmd_compile(args),
        Command::Exec(args) => cmd_exec(args, verbose).await,
        Command::Scan(args) => cmd_scan(args, verbose).await,
        Command::Login(args) => cmd_registry::cmd_login(args).await,
        Command::Logout(args) => cmd_registry::cmd_logout(args),
        Command::Whoami(args) => cmd_registry::cmd_whoami(args).await,
        Command::Publish(args) => cmd_registry::cmd_publish(args).await,
        Command::Install(args) => cmd_registry::cmd_install(args).await,
        Command::Search(args) => cmd_registry::cmd_search(args).await,
        Command::Info(args) => cmd_registry::cmd_info(args).await,
        Command::Yank(args) => cmd_registry::cmd_yank(args).await,
        Command::Unyank(args) => cmd_registry::cmd_unyank(args).await,
        Command::Edit(args) => cmd_registry::cmd_edit(args).await,
        Command::Pat(args) => match args.action {
            args::PatCommand::List(a) => cmd_registry::cmd_pat_list(a).await,
            args::PatCommand::Create(a) => cmd_registry::cmd_pat_create(a).await,
            args::PatCommand::Revoke(a) => cmd_registry::cmd_pat_revoke(a).await,
        },
        Command::Admin(args) => match args.action {
            args::AdminCommand::Delete(a) => cmd_registry::cmd_admin_delete(a).await,
        },
    }
}

fn cmd_validate(args: args::ValidateArgs) -> process::ExitCode {
    let scripts = match self::discover::discover_scripts(Path::new(&args.script.script)) {
        Ok(scripts) => scripts,
        Err(err) => {
            ui::error(&err.to_string());
            return process::ExitCode::from(1);
        }
    };

    let _spinner = ui::Spinner::start("validating");

    for path in &scripts {
        let source = match load_script(path) {
            Ok(s) => s,
            Err(code) => return code,
        };
        let label = path.display().to_string();
        if let Err(code) = validate_source(&source, &label) {
            ui::error(&format!("{label}: invalid Ruso script"));
            return code;
        }
    }

    process::ExitCode::SUCCESS
}

fn cmd_compile(args: args::CompileArgs) -> process::ExitCode {
    let scripts = match self::discover::discover_scripts(Path::new(&args.script.script)) {
        Ok(scripts) => scripts,
        Err(err) => {
            ui::error(&err.to_string());
            return process::ExitCode::from(1);
        }
    };

    let _spinner = ui::Spinner::start("compiling");

    for path in &scripts {
        let program = match load_program(path) {
            Ok(p) => p,
            Err(err) => {
                ui::error(&format!("{}: {err}", path.display()));
                return process::ExitCode::from(1);
            }
        };

        let bytecode = match compile_program(&program) {
            Ok(bc) => bc,
            Err(CompileError::MissingFindingTitle) => {
                ui::error(&format!(
                    "{}: script has match/evidence but no `name` or `report` metadata",
                    path.display()
                ));
                return process::ExitCode::from(1);
            }
            Err(CompileError::DuplicateMitigation) => {
                ui::error(&format!(
                    "{}: `mitigation` may appear at most once (single free-text field)",
                    path.display()
                ));
                return process::ExitCode::from(1);
            }
        };
        let raw = encode_bytecode(&bytecode);
        let hex = bytes_to_hex(&raw);
        let out_path = bytecode_path_for_script(path);

        if let Err(err) = std::fs::write(&out_path, hex.as_bytes()) {
            ui::error(&format!("failed to write {}: {err}", out_path.display()));
            return process::ExitCode::from(1);
        }
    }

    process::ExitCode::SUCCESS
}

async fn cmd_exec(args: args::ExecArgs, verbose: bool) -> process::ExitCode {
    let bytecode_files = match resolve_bytecode_input(&args.bytecode, &args.registry).await {
        Ok(files) => files,
        Err(err) => {
            ui::error(&err);
            return process::ExitCode::from(1);
        }
    };

    let targets = match targets::discover_targets(&args.target) {
        Ok(targets) => targets,
        Err(err) => {
            ui::error(&err.to_string());
            return process::ExitCode::from(1);
        }
    };

    if let Err(err) = validate_report_options(args.report.as_deref()) {
        ui::error(&err);
        return process::ExitCode::from(1);
    }

    let base_config = match executor_config_from_exec(&args) {
        Ok(c) => c,
        Err(code) => return code,
    };

    let multi_target = targets.len() > 1;

    let mut scan_report = ScanRunReport::with_capacity(targets.len() * bytecode_files.len());

    // Decode each .rbc file once and share the resulting bytecode across
    // targets via Arc — same optimisation as `cmd_scan`.
    let mut prepared_bytecode: Vec<(String, Arc<BytecodeProgram>)> =
        Vec::with_capacity(bytecode_files.len());
    for bc_path in &bytecode_files {
        let bytes = match read_bytecode_file(bc_path) {
            Ok(b) => b,
            Err(err) => {
                ui::error(&format!("{}: {err}", bc_path.display()));
                return process::ExitCode::from(1);
            }
        };
        let program = match ruso_runtime::decode_bytecode(&bytes) {
            Ok(p) => p,
            Err(err) => {
                ui::error(&format!("{}: {err}", bc_path.display()));
                return process::ExitCode::from(1);
            }
        };
        let label =
            install_store::pretty_label(bc_path).unwrap_or_else(|| bc_path.display().to_string());
        prepared_bytecode.push((label, Arc::new(program)));
    }

    let prepared_scripts: Vec<PreparedScript> = prepared_bytecode
        .into_iter()
        .map(|(label, bytecode)| PreparedScript::Ready { label, bytecode })
        .collect();

    let scan_started = Instant::now();
    ScanPipeline {
        targets: &targets,
        prepared: &prepared_scripts,
        base_config: &base_config,
        concurrency: args.concurrency.max(1),
        host_throttle: HostThrottle::new(args.max_per_host),
        rate_limiter: RateLimiter::per_second(args.rps),
        verbose,
        multi_target,
        // exec runs no scheme probe; targets are used verbatim.
        resolver: None,
    }
    .run(&mut scan_report)
    .await;

    scan_report.finish();
    let scan_duration = scan_started.elapsed();

    if let Err(err) = emit_scan_report(&scan_report, args.report.as_deref(), verbose, scan_duration)
    {
        ui::error(&err);
        return process::ExitCode::from(1);
    }

    process::ExitCode::from(exit_code_from_report(&scan_report) as u8)
}

async fn cmd_scan(args: ScanArgs, verbose: bool) -> process::ExitCode {
    // Exactly one of --script / --family selects what to run.
    let input = match (&args.script, &args.family) {
        (Some(_), Some(_)) => {
            ui::error("--script and --family are mutually exclusive; pass only one");
            return process::ExitCode::from(1);
        }
        (None, None) => {
            ui::error("nothing to scan: pass --script <path|ref> or --family <name>");
            return process::ExitCode::from(1);
        }
        (Some(script), None) => match resolve_script_input(script, &args.registry).await {
            Ok(i) => i,
            Err(err) => {
                ui::error(&err);
                return process::ExitCode::from(1);
            }
        },
        (None, Some(family)) => {
            match cmd_registry::resolve_family_to_bytecodes(family, &args.registry).await {
                Ok(paths) => ScriptInput::Bytecodes(paths),
                Err(err) => {
                    ui::error(&err);
                    return process::ExitCode::from(1);
                }
            }
        }
    };

    let scan_targets = match targets::discover_targets(&args.target) {
        Ok(targets) => targets,
        Err(err) => {
            ui::error(&err.to_string());
            return process::ExitCode::from(1);
        }
    };

    if let Err(err) = validate_report_options(args.report.as_deref()) {
        ui::error(&err);
        return process::ExitCode::from(1);
    }

    let base_config = match executor_base_config(&args) {
        Ok(c) => c,
        Err(code) => return code,
    };

    let prepared_scripts: Vec<PreparedScript> = match input {
        // Compile each script once and wrap the bytecode in an Arc so
        // multiple (target × script) iterations share the same program (and
        // its compiled regex caches) via cheap ref-count clones rather than
        // deep copies.
        ScriptInput::Sources(scripts) => scripts
            .iter()
            .map(|script_path| {
                let label = script_path.display().to_string();
                match load_program(script_path) {
                    Ok(program) => match compile_program(&program) {
                        Ok(bytecode) => PreparedScript::Ready {
                            label,
                            bytecode: Arc::new(bytecode),
                        },
                        Err(CompileError::MissingFindingTitle) => PreparedScript::Failed {
                            label,
                            error: "missing `name` or `report` metadata (required when using match/evidence)".into(),
                        },
                        Err(CompileError::DuplicateMitigation) => PreparedScript::Failed {
                            label,
                            error: "`mitigation` may appear at most once (single free-text field)".into(),
                        },
                    },
                    Err(err) => PreparedScript::Failed {
                        label,
                        error: err.to_string(),
                    },
                }
            })
            .collect(),
        // Registry refs and `.rbc` paths bypass the compile step — they are
        // already-validated bytecode the publish path produced (or someone
        // ran `ruso compile` over locally). Same decode logic as cmd_exec.
        ScriptInput::Bytecodes(bytecode_files) => {
            let mut prepared = Vec::with_capacity(bytecode_files.len());
            for bc_path in &bytecode_files {
                let label = install_store::pretty_label(bc_path)
                    .unwrap_or_else(|| bc_path.display().to_string());
                let bytes = match read_bytecode_file(bc_path) {
                    Ok(b) => b,
                    Err(err) => {
                        prepared.push(PreparedScript::Failed { label, error: err });
                        continue;
                    }
                };
                match ruso_runtime::decode_bytecode(&bytes) {
                    Ok(program) => prepared.push(PreparedScript::Ready {
                        label,
                        bytecode: Arc::new(program),
                    }),
                    Err(err) => prepared.push(PreparedScript::Failed {
                        label,
                        error: err.to_string(),
                    }),
                }
            }
            prepared
        }
    };

    // Resolve the URL scheme for bare-host targets (https-first) before the
    // run. Skipped when no script makes HTTP requests — the carrier scheme is
    // irrelevant to TCP/UDP/DNS probes. Targets with an explicit scheme are
    // untouched.
    let needs_http = prepared_scripts.iter().any(|p| match p {
        PreparedScript::Ready { bytecode, .. } => bytecode
            .spec
            .probes
            .values()
            .any(|kind| matches!(kind, ruso_runtime::ProbeKind::Http(_))),
        PreparedScript::Failed { .. } => false,
    });
    // Bare-host scheme resolution is folded into the scan pipeline (resolved
    // lazily, once per target) so it overlaps with scanning instead of blocking
    // it as a separate up-front phase.
    let resolve_opts = scheme::ResolveOptions {
        verify_ssl: base_config.verify_ssl,
        needs_http,
        default_scheme: args.default_scheme,
        probe: !args.no_scheme_probe,
        proxy: args.proxy.as_deref(),
    };

    let multi_target = scan_targets.len() > 1;

    let mut scan_report = ScanRunReport::with_capacity(scan_targets.len() * prepared_scripts.len());

    let scan_started = Instant::now();
    ScanPipeline {
        targets: &scan_targets,
        prepared: &prepared_scripts,
        base_config: &base_config,
        concurrency: args.concurrency.max(1),
        host_throttle: HostThrottle::new(args.max_per_host),
        rate_limiter: RateLimiter::per_second(args.rps),
        verbose,
        multi_target,
        resolver: Some(resolve_opts),
    }
    .run(&mut scan_report)
    .await;

    scan_report.finish();
    let scan_duration = scan_started.elapsed();

    if let Err(err) = emit_scan_report(&scan_report, args.report.as_deref(), verbose, scan_duration)
    {
        ui::error(&err);
        return process::ExitCode::from(1);
    }

    process::ExitCode::from(exit_code_from_report(&scan_report) as u8)
}

enum PreparedScript {
    Ready {
        label: String,
        bytecode: Arc<BytecodeProgram>,
    },
    Failed {
        label: String,
        error: String,
    },
}

/// `.rbc` files are lowercase hex (from `compile`). Legacy raw `RUSO` bytes still accepted.
pub(crate) fn read_bytecode_file(path: &Path) -> Result<Vec<u8>, String> {
    let data = std::fs::read(path).map_err(|err| format!("failed to read: {err}"))?;
    if data.starts_with(MAGIC) {
        return Ok(data);
    }
    let text = std::str::from_utf8(&data)
        .map_err(|err| format!("invalid .rbc file (expected hex text): {err}"))?;
    hex_to_bytes(text).map_err(|err| err.to_string())
}

/// One streaming, pipelined scan run. Bundling the inputs into a struct keeps
/// the runner and its two call sites (`scan`, `exec`) free of a long positional
/// argument list.
struct ScanPipeline<'a> {
    targets: &'a [String],
    prepared: &'a [PreparedScript],
    base_config: &'a ruso_runtime::ExecutorConfig,
    concurrency: usize,
    host_throttle: HostThrottle,
    rate_limiter: RateLimiter,
    verbose: bool,
    multi_target: bool,
    /// Scheme resolution for bare-host targets (`scan`). `None` uses each
    /// target verbatim (`exec`).
    resolver: Option<scheme::ResolveOptions<'a>>,
}

impl ScanPipeline<'_> {
    /// Fan out (target × script) work over a bounded concurrency pool, feeding
    /// results into `scan_report`. Each target's scheme is resolved lazily and
    /// once (memoised), so resolution overlaps with scanning instead of running
    /// as a separate up-front phase. Findings stream live as they are found.
    async fn run(self, scan_report: &mut ScanRunReport) {
        use futures::stream::{self, StreamExt};
        use std::sync::atomic::Ordering;
        use std::sync::{Arc as SharedArc, Mutex};
        use tokio::sync::OnceCell;

        let ScanPipeline {
            targets,
            prepared,
            base_config,
            concurrency,
            host_throttle,
            rate_limiter,
            verbose,
            multi_target,
            resolver,
        } = self;

        // (target_idx, script_idx) work plan; results reattach to `completed`
        // by index so json/csv output stays deterministic regardless of
        // completion order.
        let mut jobs: Vec<(usize, usize)> = Vec::with_capacity(targets.len() * prepared.len());
        for ti in 0..targets.len() {
            for si in 0..prepared.len() {
                jobs.push((ti, si));
            }
        }
        let total = jobs.len();
        let mut completed: Vec<Option<ScanResultRecord>> = (0..total).map(|_| None).collect();

        // One scheme-resolution cell per target so its many script jobs probe it
        // exactly once (the first job resolves; the rest await the same cell).
        let cells: SharedArc<Vec<OnceCell<String>>> =
            SharedArc::new((0..targets.len()).map(|_| OnceCell::new()).collect());
        // Deferred resolution cert warnings + the URLs they cover, and the URLs
        // whose runs actually failed on a bad cert (for the post-scan hint).
        let warnings = SharedArc::new(Mutex::new(Vec::<String>::new()));
        let cert_warned = SharedArc::new(Mutex::new(std::collections::HashSet::<String>::new()));
        let cert_failed = SharedArc::new(Mutex::new(std::collections::HashSet::<String>::new()));

        let mut stream = stream::iter(jobs.into_iter().enumerate())
            .map(|(idx, (ti, si))| {
                let raw_target = targets[ti].clone();
                let prepared = &prepared[si];
                let host_throttle = host_throttle.clone();
                let rate_limiter = rate_limiter.clone();
                let cells = cells.clone();
                let warnings = warnings.clone();
                let cert_warned = cert_warned.clone();
                let cert_failed = cert_failed.clone();
                async move {
                    // Resolve this target's scheme once (memoised). `exec` has
                    // no resolver and uses the target verbatim.
                    let url = cells[ti]
                        .get_or_init(|| async {
                            match resolver {
                                Some(opts) => {
                                    let (url, warning) =
                                        scheme::resolve_one(&raw_target, &opts).await;
                                    if let Some(message) = warning {
                                        warnings.lock().unwrap().push(message);
                                        cert_warned.lock().unwrap().insert(url.clone());
                                    }
                                    url
                                }
                                None => raw_target.clone(),
                            }
                        })
                        .await
                        .clone();

                    // Order matters: take the per-host slot first, then the RPS
                    // token, so the limiter only spends budget on a run about to
                    // start, not one still queued behind a host's permit.
                    let config = executor_config_for_target(base_config, &url);
                    let host = throttle::host_key(&url);
                    let _host_permit = host_throttle.acquire(&host).await;
                    rate_limiter.acquire().await;
                    let (label, exec_result) = match prepared {
                        PreparedScript::Ready { label, bytecode } => {
                            let program = Arc::clone(bytecode);
                            // full_message() keeps the underlying cause (TLS cert
                            // rejection, connection reset, decode failure) the
                            // runtime error's Display would otherwise hide.
                            let exec_result = match run_program(program, config).await {
                                Ok(result) => Ok(result),
                                Err(err) => Err(err.full_message()),
                            };
                            (label.clone(), exec_result)
                        }
                        PreparedScript::Failed { label, error } => {
                            (label.clone(), Err(error.clone()))
                        }
                    };
                    if exec_result
                        .as_ref()
                        .err()
                        .is_some_and(|msg| msg.to_ascii_lowercase().contains("certificate"))
                    {
                        cert_failed.lock().unwrap().insert(url.clone());
                    }
                    let record = match &exec_result {
                        Ok(r) => ScanResultRecord::from_execution(url.clone(), label.clone(), r),
                        Err(msg) => {
                            ScanResultRecord::from_error(url.clone(), label.clone(), msg.clone())
                        }
                    };
                    (idx, record)
                }
            })
            .buffer_unordered(concurrency);

        // Progress spinner over the work (`⠋ scanning 12/48 (25%)`); dormant in
        // verbose / non-TTY. Live output (findings, verbose status rows) is
        // printed through `suspend` so it never collides with a spinner frame.
        let (spinner, counter) = ui::Spinner::with_progress("scanning", total);
        while let Some((idx, record)) = stream.next().await {
            // Findings and verbose status rows always stream to the terminal;
            // a `--report` file (if any) is written separately after the scan.
            spinner.suspend(|| {
                if verbose {
                    print_live_run(&record, multi_target);
                } else if record.detected {
                    for finding in &record.findings {
                        print_finding_line(&record.target, finding);
                    }
                }
            });
            completed[idx] = Some(record);
            counter.fetch_add(1, Ordering::Relaxed);
        }
        drop(spinner);

        // Now that the spinner is gone, emit the deferred resolution warnings.
        for message in warnings.lock().unwrap().drain(..) {
            ui::warn(&message);
        }

        for record in completed.into_iter().flatten() {
            scan_report.push_record(record);
        }

        // One-shot hint for a cert failure on a target the resolver did *not*
        // already warn about (e.g. an explicitly-schemed `https://` target).
        if base_config.verify_ssl {
            let failed = cert_failed.lock().unwrap();
            let warned = cert_warned.lock().unwrap();
            if failed.difference(&warned).next().is_some() {
                ui::warn(
                    "a target's TLS certificate did not verify — pass --insecure to scan it \
                     (only if you accept the MITM / finding-injection risk)",
                );
            }
        }
    }
}
