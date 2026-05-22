//! CLI: argument parsing, scan orchestration, and terminal output.

mod args;
mod discover;
mod report;
mod targets;
mod ui;

use std::future::Future;
use std::path::Path;
use std::process;

use clap::Parser as _;

pub use args::{Cli, Command, OutputFormat, ScanArgs};

use ruso_runtime::{bytes_to_hex, hex_to_bytes, MAGIC};
use ruso_script::{
    compile_program, encode_bytecode, load_program, run_bytecode, run_bytes, BytecodeProgram,
    CompileError,
};

use self::args::{
    executor_base_config, executor_config_for_target, executor_config_from_exec, load_script,
    validate_source,
};
use self::discover::{bytecode_path_for_script, discover_bytecode, discover_scripts};
use self::report::{
    emit_scan_report, exit_code_from_report, print_live_run, validate_report_options,
    ScanResultRecord, ScanRunReport, ScanSummary,
};

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
    }
}

fn cmd_validate(args: args::ValidateArgs, verbose: bool) -> process::ExitCode {
    let scripts = match discover_scripts(&args.script.script) {
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
    let scripts = match discover_scripts(&args.script.script) {
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
    let bytecode_files = match discover_bytecode(&args.bytecode) {
        Ok(files) => files,
        Err(err) => {
            ui::error(&err.to_string());
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

    for target in &targets {
        let config = executor_config_for_target(&base_config, target);
        for bc_path in &bytecode_files {
            let bytes = match read_bytecode_file(bc_path) {
                Ok(b) => b,
                Err(err) => {
                    ui::error(&format!("{}: {err}", bc_path.display()));
                    return process::ExitCode::from(1);
                }
            };

            let label = bc_path.display().to_string();
            let cfg = config.clone();
            let scan_result = with_spinner(verbose, || run_bytes(&bytes, cfg)).await;
            let exec_result = match scan_result {
                Ok(result) => Ok(result),
                Err(err) => Err(err.to_string()),
            };

            if args.output == OutputFormat::Human && verbose {
                let record = match &exec_result {
                    Ok(r) => ScanResultRecord::from_execution(target.clone(), label.clone(), r),
                    Err(msg) => ScanResultRecord::from_error(target.clone(), label.clone(), msg.clone()),
                };
                print_live_run(&record, multi_target);
            }

            scan_report.push_result(target.clone(), label, exec_result);
        }
    }

    scan_report.finish();

    if let Err(err) = emit_scan_report(
        &scan_report,
        args.output,
        args.report.as_deref(),
        verbose,
    ) {
        ui::error(&err);
        return process::ExitCode::from(1);
    }

    process::ExitCode::from(exit_code_from_report(&scan_report) as u8)
}

async fn with_spinner<F, Fut, T>(verbose: bool, work: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    if verbose {
        work().await
    } else {
        let _spinner = ui::Spinner::start();
        work().await
    }
}

async fn cmd_scan(args: ScanArgs, verbose: bool) -> process::ExitCode {
    let scripts = match discover_scripts(&args.script.script) {
        Ok(scripts) => scripts,
        Err(err) => {
            ui::error(&err.to_string());
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

    let script_labels: Vec<String> = scripts.iter().map(|p| p.display().to_string()).collect();
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
        results: Vec::with_capacity(scan_targets.len() * scripts.len()),
    };

    let prepared_scripts: Vec<PreparedScript> = scripts
        .iter()
        .map(|script_path| {
            let label = script_path.display().to_string();
            match load_program(script_path) {
                Ok(program) => match compile_program(&program) {
                    Ok(bytecode) => PreparedScript::Ready { label, bytecode },
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
        .collect();

    for target in &scan_targets {
        let config = executor_config_for_target(&base_config, target);
        for prepared in &prepared_scripts {
            let (label, exec_result) = match prepared {
                PreparedScript::Ready { label, bytecode } => {
                    let cfg = config.clone();
                    let scan_result =
                        with_spinner(verbose, || run_bytecode(bytecode, cfg)).await;
                    let exec_result = match scan_result {
                        Ok(result) => Ok(result),
                        Err(err) => Err(err.to_string()),
                    };
                    (label.clone(), exec_result)
                }
                PreparedScript::Failed { label, error } => (label.clone(), Err(error.clone())),
            };

            if args.output == OutputFormat::Human && verbose {
                let record = match &exec_result {
                    Ok(r) => ScanResultRecord::from_execution(target.clone(), label.clone(), r),
                    Err(msg) => ScanResultRecord::from_error(target.clone(), label.clone(), msg.clone()),
                };
                print_live_run(&record, multi_target);
            }

            scan_report.push_result(target.clone(), label, exec_result);
        }
    }

    scan_report.finish();

    if let Err(err) = emit_scan_report(
        &scan_report,
        args.output,
        args.report.as_deref(),
        verbose,
    ) {
        ui::error(&err);
        return process::ExitCode::from(1);
    }

    process::ExitCode::from(exit_code_from_report(&scan_report) as u8)
}

enum PreparedScript {
    Ready {
        label: String,
        bytecode: BytecodeProgram,
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
