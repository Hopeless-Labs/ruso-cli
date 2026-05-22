//! CLI: argument parsing, scan orchestration, and terminal output.

mod args;
mod discover;
mod report;
mod targets;
mod ui;

use std::future::Future;
use std::path::PathBuf;
use std::process;

use clap::Parser as _;

pub use args::{Cli, Command, OutputFormat, ParseArgs, ScanArgs};

use ruso_runtime::{
    bytes_to_hex, bytes_to_hex_dump, encode_bytecode, format_human, load_bytecode_input,
    ExecutionResult, RuntimeError,
};
use ruso_script::{
    compile_program, load_program, run as execute_program, run_bytes,
};

use self::args::{
    executor_base_config, executor_config_for_target, load_script, parse_script, print_parse_result,
};
use self::discover::discover_scripts;
use self::report::{
    ScanRunReport, ScanSummary, emit_scan_report, exit_code_from_report, print_live_run,
    validate_report_options, ScanResultRecord,
};

/// Binary entry: parse argv, init logging, dispatch subcommands.
pub async fn run() -> process::ExitCode {
    let cli = Cli::parse();
    let verbose = cli.is_verbose();
    crate::logging::init(cli.log_filter(), verbose);

    match cli.command {
        Command::Parse(args) => cmd_parse(args, verbose),
        Command::Compile(args) => cmd_compile(args, verbose),
        Command::Exec(args) => cmd_exec(args, verbose).await,
        Command::Scan(args) => cmd_scan(args, verbose).await,
    }
}

fn cmd_compile(args: args::CompileArgs, verbose: bool) -> process::ExitCode {
    use args::CompileFormat;

    let path = &args.script;
    let _spinner = (!verbose).then(ui::Spinner::start);

    let program = match load_program(path) {
        Ok(p) => p,
        Err(err) => {
            ui::error(&err.to_string());
            return process::ExitCode::from(1);
        }
    };

    drop(_spinner);

    let bytecode = compile_program(&program);
    let raw = encode_bytecode(&bytecode);

    if let Some(out_path) = &args.write {
        if let Err(err) = std::fs::write(out_path, &raw) {
            ui::error(&format!("failed to write {}: {err}", out_path.display()));
            return process::ExitCode::from(1);
        }
        eprintln!("bytecode written: {} ({} bytes)", out_path.display(), raw.len());
    }

    match args.format {
        CompileFormat::Hex => print!("{}", bytes_to_hex(&raw)),
        CompileFormat::HexDump => print!("{}", bytes_to_hex_dump(&raw)),
        CompileFormat::Disasm => print!("{}", format_human(&bytecode)),
    }

    process::ExitCode::SUCCESS
}

async fn cmd_exec(args: args::ExecArgs, verbose: bool) -> process::ExitCode {
    let bytes = match load_bytecode_input(&args.bytecode) {
        Ok(b) => b,
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

    let base_config = match args::executor_config_from_exec(&args) {
        Ok(c) => c,
        Err(code) => return code,
    };

    let multi_target = targets.len() > 1;
    let mut scan_report = ScanRunReport {
        targets: targets.clone(),
        scripts: vec!["<bytecode>".into()],
        summary: ScanSummary {
            total_runs: 0,
            detected: 0,
            failed: 0,
            clean: 0,
        },
        results: Vec::with_capacity(targets.len()),
    };

    for target in &targets {
        let config = executor_config_for_target(&base_config, target);
        let scan_result = with_spinner(verbose, || run_bytes(&bytes, config)).await;
        let exec_result = match scan_result {
            Ok(result) => Ok(result),
            Err(err) => Err(err.to_string()),
        };

        if args.output == OutputFormat::Human && verbose {
            let record = match &exec_result {
                Ok(r) => ScanResultRecord::from_execution(
                    target.clone(),
                    "<bytecode>".into(),
                    r,
                ),
                Err(msg) => ScanResultRecord::from_error(
                    target.clone(),
                    "<bytecode>".into(),
                    msg.clone(),
                ),
            };
            print_live_run(&record, multi_target);
        }

        scan_report.push_result(target.clone(), "<bytecode>".into(), exec_result);
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

fn cmd_parse(args: ParseArgs, verbose: bool) -> process::ExitCode {
    let path = &args.script;
    let _spinner = (!verbose).then(ui::Spinner::start);

    let source = match load_script(path) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let program = match parse_script(&source) {
        Ok(p) => p,
        Err(code) => return code,
    };

    drop(_spinner);

    if let Err(code) = print_parse_result(&program, args.format) {
        return code;
    }
    process::ExitCode::SUCCESS
}

async fn cmd_scan(args: ScanArgs, verbose: bool) -> process::ExitCode {
    let scripts = match discover_scripts(&args.script) {
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
            clean: 0,
        },
        results: Vec::with_capacity(scan_targets.len() * scripts.len()),
    };

    for target in &scan_targets {
        let config = executor_config_for_target(&base_config, target);
        for script_path in &scripts {
            let path = script_path.clone();
            let cfg = config.clone();
            let scan_result = with_spinner(verbose, || execute_script(&path, cfg)).await;

            let exec_result = match scan_result {
                Ok(result) => Ok(result),
                Err(err) => Err(err.to_string()),
            };

            if args.output == OutputFormat::Human && verbose {
                let record = match &exec_result {
                    Ok(r) => ScanResultRecord::from_execution(
                        target.clone(),
                        script_path.display().to_string(),
                        r,
                    ),
                    Err(msg) => ScanResultRecord::from_error(
                        target.clone(),
                        script_path.display().to_string(),
                        msg.clone(),
                    ),
                };
                print_live_run(&record, multi_target);
            }

            scan_report.push_result(
                target.clone(),
                script_path.display().to_string(),
                exec_result,
            );
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

async fn execute_script(
    script_path: &PathBuf,
    config: ruso_runtime::ExecutorConfig,
) -> Result<ExecutionResult, RuntimeError> {
    let program = load_program(script_path).map_err(|err| RuntimeError::Other(err.to_string()))?;
    execute_program(&program, config).await
}
