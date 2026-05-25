//! Structured scan reports: human on stdout, json/csv written to a file.

use std::fs::File;
use std::path::{Path, PathBuf};

use serde::Serialize;

use ruso_runtime::{ExecutionResult, PortCheck};

use crate::cli::args::OutputFormat;

#[derive(Debug, Clone, Serialize)]
pub struct ScanRunReport {
    pub targets: Vec<String>,
    pub scripts: Vec<String>,
    pub summary: ScanSummary,
    pub results: Vec<ScanResultRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanSummary {
    pub total_runs: usize,
    pub detected: usize,
    pub failed: usize,
    pub skipped: usize,
    pub clean: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanResultRecord {
    pub target: String,
    pub script: String,
    pub success: bool,
    pub detected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<FindingRecord>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub skipped: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub port_checks: Vec<PortCheckRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortCheckRecord {
    pub host: String,
    pub port: u16,
    pub open: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingRecord {
    pub name: String,
    pub severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cve: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cwe: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cvss: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cvss_score: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mitigation: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
}

impl ScanRunReport {
    pub fn push_result(
        &mut self,
        target: String,
        script: String,
        result: Result<ExecutionResult, String>,
    ) {
        let record = match result {
            Ok(exec) => ScanResultRecord::from_execution(target, script, &exec),
            Err(message) => ScanResultRecord::from_error(target, script, message),
        };
        if record.skipped {
            self.summary.skipped += 1;
        } else if record.detected {
            self.summary.detected += 1;
        } else if !record.success && record.error.is_some() {
            self.summary.failed += 1;
        } else {
            self.summary.clean += 1;
        }
        self.results.push(record);
    }

    pub fn finish(&mut self) {
        self.summary.total_runs = self.results.len();
    }
}

impl ScanResultRecord {
    pub fn from_execution(target: String, script: String, result: &ExecutionResult) -> Self {
        let findings = result
            .report
            .findings
            .iter()
            .map(|f| FindingRecord {
                name: f.name.clone(),
                severity: f.severity.as_str().to_string(),
                description: f.description.clone(),
                impact: f.impact.clone(),
                author: f.author.clone(),
                cve: f.cve.clone(),
                cwe: f.cwe.clone(),
                references: f.references.clone(),
                cvss: f.cvss.clone(),
                cvss_score: f.cvss_score.clone(),
                mitigation: f.mitigation.clone(),
                evidence: f.evidence.clone(),
            })
            .collect();

        Self {
            target,
            script,
            success: result.success,
            detected: result.detected,
            check: result.metadata.name.clone(),
            error: result.skip_reason.clone(),
            findings,
            skipped: result.skipped,
            port_checks: port_checks_to_records(&result.port_checks),
        }
    }

    pub fn from_error(target: String, script: String, message: String) -> Self {
        Self {
            target,
            script,
            success: false,
            detected: false,
            check: None,
            error: Some(message),
            findings: Vec::new(),
            skipped: false,
            port_checks: Vec::new(),
        }
    }
}

fn port_checks_to_records(checks: &[PortCheck]) -> Vec<PortCheckRecord> {
    checks
        .iter()
        .map(|c| PortCheckRecord {
            host: c.host.clone(),
            port: c.port,
            open: c.open,
        })
        .collect()
}

/// Validate `--report` / `--output` combination before scanning.
pub fn validate_report_options(
    format: OutputFormat,
    report_path: Option<&Path>,
) -> Result<(), String> {
    match format {
        OutputFormat::Human => Ok(()),
        OutputFormat::Json | OutputFormat::Csv => {
            let Some(path) = report_path else {
                return Err(format!(
                    "--output {} requires --report <path> (report is written to a file, not stdout)",
                    format_label(format)
                ));
            };
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                let expected = match format {
                    OutputFormat::Json => "json",
                    OutputFormat::Csv => "csv",
                    OutputFormat::Human => unreachable!(),
                };
                if ext.eq_ignore_ascii_case(expected) {
                    return Ok(());
                }
                return Err(format!(
                    "report file extension .{ext} does not match --output {} (expected .{expected})",
                    format_label(format)
                ));
            }
            Ok(())
        }
    }
}

fn format_label(format: OutputFormat) -> &'static str {
    match format {
        OutputFormat::Human => "human",
        OutputFormat::Json => "json",
        OutputFormat::Csv => "csv",
    }
}

/// Human summary/findings on stdout; json/csv written to `--report` path.
pub fn emit_scan_report(
    report: &ScanRunReport,
    format: OutputFormat,
    report_path: Option<&Path>,
    verbose: bool,
) -> Result<(), String> {
    match format {
        OutputFormat::Human => print_human(report, verbose),
        OutputFormat::Json => {
            let path = report_path.ok_or_else(|| "--report path is required".to_string())?;
            write_json_file(report, path)?;
            eprintln!("report saved: {}", path.display());
            Ok(())
        }
        OutputFormat::Csv => {
            let path = report_path.ok_or_else(|| "--report path is required".to_string())?;
            write_csv_file(report, path)?;
            eprintln!("report saved: {}", path.display());
            Ok(())
        }
    }
}

fn write_json_file(report: &ScanRunReport, path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|err| {
                format!("create report directory {}: {err}", parent.display())
            })?;
        }
    let json = serde_json::to_string_pretty(report).map_err(|err| format!("encode json: {err}"))?;
    std::fs::write(path, json).map_err(|err| format!("write report {}: {err}", path.display()))
}

fn write_csv_file(report: &ScanRunReport, path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|err| {
                format!("create report directory {}: {err}", parent.display())
            })?;
        }
    let file = File::create(path).map_err(|err| format!("create report {}: {err}", path.display()))?;
    let mut writer = csv::Writer::from_writer(file);
    writer
        .write_record([
            "target",
            "script",
            "success",
            "detected",
            "check",
            "severity",
            "finding_name",
            "description",
            "impact",
            "author",
            "cve",
            "cwe",
            "references",
            "cvss",
            "cvss_score",
            "mitigation",
            "evidence",
            "error",
        ])
        .map_err(|err| err.to_string())?;

    for row in &report.results {
        if row.findings.is_empty() {
            write_csv_row(&mut writer, row, None)?;
        } else {
            for finding in &row.findings {
                write_csv_row(&mut writer, row, Some(finding))?;
            }
        }
    }

    writer
        .flush()
        .map_err(|err| format!("flush report {}: {err}", path.display()))?;
    Ok(())
}

fn write_csv_row(
    writer: &mut csv::Writer<File>,
    row: &ScanResultRecord,
    finding: Option<&FindingRecord>,
) -> Result<(), String> {
    let evidence = finding
        .map(|f| f.evidence.join(" | "))
        .unwrap_or_default();
    let cve = finding
        .map(|f| f.cve.join(" | "))
        .unwrap_or_default();
    let cwe = finding
        .map(|f| f.cwe.join(" | "))
        .unwrap_or_default();
    let references = finding
        .map(|f| f.references.join(" | "))
        .unwrap_or_default();
    let cvss = finding
        .map(|f| f.cvss.join(" | "))
        .unwrap_or_default();
    let cvss_score = finding
        .map(|f| f.cvss_score.join(" | "))
        .unwrap_or_default();
    let mitigation = finding
        .map(|f| f.mitigation.join(" | "))
        .unwrap_or_default();
    writer
        .write_record([
            row.target.as_str(),
            row.script.as_str(),
            if row.success { "true" } else { "false" },
            if row.detected { "true" } else { "false" },
            row.check.as_deref().unwrap_or(""),
            finding.map(|f| f.severity.as_str()).unwrap_or(""),
            finding.map(|f| f.name.as_str()).unwrap_or(""),
            finding.and_then(|f| f.description.as_deref()).unwrap_or(""),
            finding.and_then(|f| f.impact.as_deref()).unwrap_or(""),
            finding.and_then(|f| f.author.as_deref()).unwrap_or(""),
            cve.as_str(),
            cwe.as_str(),
            references.as_str(),
            cvss.as_str(),
            cvss_score.as_str(),
            mitigation.as_str(),
            evidence.as_str(),
            row.error.as_deref().unwrap_or(""),
        ])
        .map_err(|err| err.to_string())
}

/// Incremental line while scanning (`-v` + human) on stdout.
pub fn print_live_run(record: &ScanResultRecord, multi_target: bool) {
    if multi_target {
        print!("{} ", record.target);
    }
    print!("{}: ", script_label(&record.script));
    if record.skipped {
        let msg = record.error.as_deref().unwrap_or("port closed");
        println!("skipped ({msg})");
        return;
    }
    if let Some(err) = &record.error {
        println!("error ({err})");
        return;
    }
    if record.detected {
        println!("detected");
        for finding in &record.findings {
            print_finding_human(finding);
        }
    } else {
        println!("no");
    }
}

fn print_human(report: &ScanRunReport, verbose: bool) -> Result<(), String> {
    let multi = report.summary.total_runs > 1;

    if !verbose {
        for record in &report.results {
            if !record.detected {
                continue;
            }
            if multi {
                print!("{} ", record.target);
            }
            println!("{}: detected", script_label(&record.script));
            for finding in &record.findings {
                print_finding_human(finding);
            }
        }
    }

    if multi && (report.summary.detected > 0 || report.summary.failed > 0 || verbose) {
        println!();
        println!(
            "scan summary: {} run(s) ({} target(s) × {} script(s))",
            report.summary.total_runs,
            report.targets.len(),
            report.scripts.len()
        );
        println!("  detected: {}", report.summary.detected);
        println!("  failed:   {}", report.summary.failed);
        if report.summary.skipped > 0 {
            println!("  skipped:  {}", report.summary.skipped);
        }
        if verbose {
            println!("  clean:    {}", report.summary.clean);
        }
    }

    Ok(())
}

fn script_label(script: &str) -> String {
    PathBuf::from(script)
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_string)
        .unwrap_or_else(|| script.to_string())
}

fn print_finding_human(finding: &FindingRecord) {
    println!("[{}] {}", finding.severity, finding.name);
    if let Some(description) = &finding.description {
        println!("  description: {description}");
    }
    if let Some(impact) = &finding.impact {
        println!("  impact: {impact}");
    }
    if let Some(author) = &finding.author {
        println!("  author: {author}");
    }
    for cve in &finding.cve {
        println!("  cve: {cve}");
    }
    for cwe in &finding.cwe {
        println!("  cwe: {cwe}");
    }
    for reference in &finding.references {
        println!("  references: {reference}");
    }
    for cvss in &finding.cvss {
        println!("  cvss: {cvss}");
    }
    for score in &finding.cvss_score {
        println!("  cvss_score: {score}");
    }
    for mitigation in &finding.mitigation {
        println!("  mitigation: {mitigation}");
    }
    for evidence in &finding.evidence {
        println!("  evidence: {}", truncate_evidence(evidence, 200));
    }
}

fn truncate_evidence(text: &str, max_len: usize) -> String {
    crate::util::truncate_str(text, max_len)
}

pub fn exit_code_from_report(report: &ScanRunReport) -> i32 {
    if report.summary.failed > 0 {
        1
    } else {
        0
    }
}
