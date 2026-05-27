//! CLI: argument parsing, scan orchestration, and terminal output.

mod args;
mod cmd_registry;
mod credentials;
pub mod discover;
mod install_store;
pub mod registry;
mod report;
mod targets;
mod throttle;
mod ui;

use std::path::Path;
use std::process;
use std::sync::Arc;

use clap::Parser as _;

pub use args::{Cli, Command, OutputFormat, ScanArgs};

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
    ScanResultRecord, ScanRunReport, ScanSummary, emit_scan_report, exit_code_from_report,
    print_live_run, validate_report_options,
};
use self::throttle::{HostThrottle, RateLimiter};

/// Binary entry: parse argv, init logging, dispatch subcommands.
pub async fn run() -> process::ExitCode {
    let cli = Cli::parse();
    let verbose = cli.is_verbose();
    crate::logging::init(cli.log_filter(), verbose);

    match cli.command {
        Command::Validate(args) => cmd_validate(args, verbose),
        Command::Compile(args) => cmd_compile(args, verbose),
        Command::Exec(args) => cmd_exec(args, verbose).await,
        Command::Scan(args) => cmd_scan(args, verbose).await,
        Command::Login(args) => cmd_registry::cmd_login(args).await,
        Command::Logout(args) => cmd_registry::cmd_logout(args),
        Command::Whoami(args) => cmd_registry::cmd_whoami(args).await,
        Command::Publish(args) => cmd_registry::cmd_publish(args).await,
        Command::Install(args) => cmd_registry::cmd_install(args).await,
        Command::Search(args) => cmd_registry::cmd_search(args).await,
        Command::Pat(args) => match args.action {
            args::PatCommand::List(a) => cmd_registry::cmd_pat_list(a).await,
            args::PatCommand::Create(a) => cmd_registry::cmd_pat_create(a).await,
            args::PatCommand::Revoke(a) => cmd_registry::cmd_pat_revoke(a).await,
        },
    }
}

fn cmd_validate(args: args::ValidateArgs, verbose: bool) -> process::ExitCode {
    let scripts = match self::discover::discover_scripts(Path::new(&args.script.script)) {
        Ok(scripts) => scripts,
        Err(err) => {
            ui::error(&err.to_string());
            return process::ExitCode::from(1);
        }
    };

    let _spinner = (!verbose).then(ui::Spinner::start);

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

fn cmd_compile(args: args::CompileArgs, verbose: bool) -> process::ExitCode {
    let scripts = match self::discover::discover_scripts(Path::new(&args.script.script)) {
        Ok(scripts) => scripts,
        Err(err) => {
            ui::error(&err.to_string());
            return process::ExitCode::from(1);
        }
    };

    let _spinner = (!verbose).then(ui::Spinner::start);

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

    if let Err(err) = validate_report_options(args.output, args.report.as_deref()) {
        ui::error(&err);
        return process::ExitCode::from(1);
    }

    let base_config = match executor_config_from_exec(&args) {
        Ok(c) => c,
        Err(code) => return code,
    };

    let multi_target = targets.len() > 1;
    let script_labels: Vec<String> = bytecode_files
        .iter()
        .map(|p| p.display().to_string())
        .collect();

    let mut scan_report = ScanRunReport {
        targets: targets.clone(),
        scripts: script_labels.clone(),
        summary: ScanSummary {
            total_runs: 0,
            detected: 0,
            failed: 0,
            skipped: 0,
            clean: 0,
        },
        results: Vec::with_capacity(targets.len() * bytecode_files.len()),
    };

    // Decode each .bc file once and share the resulting bytecode across
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

    run_scan_pipeline(
        &targets,
        &prepared_scripts,
        &base_config,
        args.concurrency.max(1),
        HostThrottle::new(args.max_per_host),
        RateLimiter::per_second(args.rps),
        args.output,
        verbose,
        multi_target,
        &mut scan_report,
    )
    .await;

    scan_report.finish();

    if let Err(err) = emit_scan_report(&scan_report, args.output, args.report.as_deref(), verbose) {
        ui::error(&err);
        return process::ExitCode::from(1);
    }

    process::ExitCode::from(exit_code_from_report(&scan_report) as u8)
}

async fn cmd_scan(args: ScanArgs, verbose: bool) -> process::ExitCode {
    let input = match resolve_script_input(&args.script.script, &args.registry).await {
        Ok(i) => i,
        Err(err) => {
            ui::error(&err);
            return process::ExitCode::from(1);
        }
    };

    let scan_targets = match targets::discover_targets(&args.target) {
        Ok(targets) => targets,
        Err(err) => {
            ui::error(&err.to_string());
            return process::ExitCode::from(1);
        }
    };

    if let Err(err) = validate_report_options(args.output, args.report.as_deref()) {
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
                    },
                    Err(err) => PreparedScript::Failed {
                        label,
                        error: err.to_string(),
                    },
                }
            })
            .collect(),
        // Registry refs and `.bc` paths bypass the compile step — they are
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

    let script_labels: Vec<String> = prepared_scripts
        .iter()
        .map(|p| match p {
            PreparedScript::Ready { label, .. } => label.clone(),
            PreparedScript::Failed { label, .. } => label.clone(),
        })
        .collect();
    let multi_target = scan_targets.len() > 1;

    let mut scan_report = ScanRunReport {
        targets: scan_targets.clone(),
        scripts: script_labels.clone(),
        summary: ScanSummary {
            total_runs: 0,
            detected: 0,
            failed: 0,
            skipped: 0,
            clean: 0,
        },
        results: Vec::with_capacity(scan_targets.len() * prepared_scripts.len()),
    };

    run_scan_pipeline(
        &scan_targets,
        &prepared_scripts,
        &base_config,
        args.concurrency.max(1),
        HostThrottle::new(args.max_per_host),
        RateLimiter::per_second(args.rps),
        args.output,
        verbose,
        multi_target,
        &mut scan_report,
    )
    .await;

    scan_report.finish();

    if let Err(err) = emit_scan_report(&scan_report, args.output, args.report.as_deref(), verbose) {
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

/// `.bc` files are lowercase hex (from `compile`). Legacy raw `RUSO` bytes still accepted.
fn read_bytecode_file(path: &Path) -> Result<Vec<u8>, String> {
    let data = std::fs::read(path).map_err(|err| format!("failed to read: {err}"))?;
    if data.starts_with(MAGIC) {
        return Ok(data);
    }
    let text = std::str::from_utf8(&data)
        .map_err(|err| format!("invalid .bc file (expected hex text): {err}"))?;
    hex_to_bytes(text).map_err(|err| err.to_string())
}

/// Fan out (target × script) work over a bounded concurrency pool and feed
/// results back into `scan_report` in (target, script) order.
///
/// `buffer_unordered(N)` runs up to N futures concurrently and yields results
/// as they finish, so live output may interleave when N > 1. The final
/// `scan_report.results` list is re-sorted by the work index to keep file
/// output (json/csv) deterministic regardless of completion order.
#[allow(clippy::too_many_arguments)]
async fn run_scan_pipeline(
    targets: &[String],
    prepared: &[PreparedScript],
    base_config: &ruso_runtime::ExecutorConfig,
    concurrency: usize,
    host_throttle: HostThrottle,
    rate_limiter: RateLimiter,
    output: OutputFormat,
    verbose: bool,
    multi_target: bool,
    scan_report: &mut ScanRunReport,
) {
    use futures::stream::{self, StreamExt};

    // Build the full (target_idx, script_idx) work plan up-front so results
    // can be reattached to their slot for deterministic ordering.
    let mut jobs: Vec<(usize, usize)> = Vec::with_capacity(targets.len() * prepared.len());
    for (ti, _) in targets.iter().enumerate() {
        for (si, _) in prepared.iter().enumerate() {
            jobs.push((ti, si));
        }
    }

    let mut completed: Vec<Option<ScanResultRecord>> = (0..jobs.len()).map(|_| None).collect();

    let mut stream = stream::iter(jobs.into_iter().enumerate())
        .map(|(idx, (ti, si))| {
            let target = targets[ti].clone();
            let prepared = &prepared[si];
            let config = executor_config_for_target(base_config, &target);
            let host_throttle = host_throttle.clone();
            let rate_limiter = rate_limiter.clone();
            async move {
                // Order matters: take the per-host slot first, then the RPS
                // token. That way the rate limiter only consumes a slot for
                // a run that is actually about to start, instead of burning
                // budget on jobs still queued behind a host's permit.
                let host = throttle::host_key(&target);
                let _host_permit = host_throttle.acquire(&host).await;
                rate_limiter.acquire().await;
                let (label, exec_result) = match prepared {
                    PreparedScript::Ready { label, bytecode } => {
                        let program = Arc::clone(bytecode);
                        let scan_result = run_program(program, config).await;
                        let exec_result = match scan_result {
                            Ok(result) => Ok(result),
                            Err(err) => Err(err.to_string()),
                        };
                        (label.clone(), exec_result)
                    }
                    PreparedScript::Failed { label, error } => (label.clone(), Err(error.clone())),
                };
                let record = match &exec_result {
                    Ok(r) => ScanResultRecord::from_execution(target.clone(), label.clone(), r),
                    Err(msg) => {
                        ScanResultRecord::from_error(target.clone(), label.clone(), msg.clone())
                    }
                };
                (idx, record)
            }
        })
        .buffer_unordered(concurrency);

    while let Some((idx, record)) = stream.next().await {
        if output == OutputFormat::Human && verbose {
            print_live_run(&record, multi_target);
        }
        completed[idx] = Some(record);
    }

    // Push records back in their original (target, script) slot order. Each
    // record already carries the right `success`/`detected`/`error` shape;
    // `push_record` updates the summary counters in one place — earlier
    // revisions branched into a second `push_result` path that re-built the
    // record from an `Err` string, which double-counted some failures and
    // dropped `port_checks` from error records.
    for record in completed.into_iter().flatten() {
        scan_report.push_record(record);
    }
}
