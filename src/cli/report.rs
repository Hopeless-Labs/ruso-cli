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
    /// Genuine error (parse/network/runtime failure). Distinct from
    /// `skip_reason`, which records a planned skip such as "port closed".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Why a run was skipped (e.g. `port 80 closed`). `None` for runs
    /// that actually executed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitigation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
}

impl ScanRunReport {
    /// Append an already-built [`ScanResultRecord`] and update the summary
    /// counters. The concurrent scan pipeline uses this to feed back records
    /// it built while running futures in parallel, where the original
    /// `ExecutionResult` has already been consumed.
    ///
    /// Buckets are exclusive and resolved in priority order:
    /// 1. `skipped` — run did not execute (port closed)
    /// 2. `detected` — finding emitted
    /// 3. `failed` — `!success` for any reason (Fail opcode, IO error, …)
    /// 4. `clean`  — ran successfully with no finding
    ///
    /// Earlier revisions required both `!success` *and* `error.is_some()` to
    /// land in "failed", which silently bucketed a Fail-opcode result with
    /// no error message into "clean".
    pub fn push_record(&mut self, record: ScanResultRecord) {
        if record.skipped {
            self.summary.skipped += 1;
        } else if record.detected {
            self.summary.detected += 1;
        } else if !record.success {
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
        // `version`, `family`, and `tags` are script-level metadata the runtime
        // Finding doesn't carry, but the full CheckMetadata rides on the
        // ExecutionResult — fold them in so the report holds every metadata
        // field. There is one finding per script, so attaching script-level
        // metadata to it is unambiguous.
        let meta = &result.metadata;
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
                version: meta.version.clone(),
                family: meta.family.clone(),
                tags: meta.tags.clone(),
                evidence: f.evidence.clone(),
            })
            .collect();

        Self {
            target,
            script,
            success: result.success,
            detected: result.detected,
            check: result.metadata.name.clone(),
            // A skipped run is not an error — keep the two channels separate
            // so consumers can tell "did the run fail?" from "was the run
            // intentionally skipped?".
            error: None,
            skip_reason: if result.skipped {
                result.skip_reason.clone()
            } else {
                None
            },
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
            skip_reason: None,
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
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("create report directory {}: {err}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(report).map_err(|err| format!("encode json: {err}"))?;
    std::fs::write(path, json).map_err(|err| format!("write report {}: {err}", path.display()))
}

fn write_csv_file(report: &ScanRunReport, path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("create report directory {}: {err}", parent.display()))?;
    }
    let file =
        File::create(path).map_err(|err| format!("create report {}: {err}", path.display()))?;
    let mut writer = csv::Writer::from_writer(file);
    writer
        .write_record([
            "target",
            "script",
            "success",
            "detected",
            "skipped",
            "skip_reason",
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
            "version",
            "family",
            "tags",
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
    let evidence = finding.map(|f| f.evidence.join(" | ")).unwrap_or_default();
    let cve = finding.map(|f| f.cve.join(" | ")).unwrap_or_default();
    let cwe = finding.map(|f| f.cwe.join(" | ")).unwrap_or_default();
    let references = finding
        .map(|f| f.references.join(" | "))
        .unwrap_or_default();
    let cvss = finding.map(|f| f.cvss.join(" | ")).unwrap_or_default();
    let cvss_score = finding
        .map(|f| f.cvss_score.join(" | "))
        .unwrap_or_default();
    let mitigation = finding
        .and_then(|f| f.mitigation.clone())
        .unwrap_or_default();
    let version = finding.and_then(|f| f.version.clone()).unwrap_or_default();
    let family = finding.and_then(|f| f.family.clone()).unwrap_or_default();
    let tags = finding.map(|f| f.tags.join(" | ")).unwrap_or_default();
    writer
        .write_record([
            row.target.as_str(),
            row.script.as_str(),
            if row.success { "true" } else { "false" },
            if row.detected { "true" } else { "false" },
            if row.skipped { "true" } else { "false" },
            row.skip_reason.as_deref().unwrap_or(""),
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
            version.as_str(),
            family.as_str(),
            tags.as_str(),
            evidence.as_str(),
            row.error.as_deref().unwrap_or(""),
        ])
        .map_err(|err| err.to_string())
}

/// Incremental line while scanning (`-v` + human) on stdout.
pub fn print_live_run(record: &ScanResultRecord, _multi_target: bool) {
    let label = script_label(&record.script);
    let target = display_target(&record.target);
    if record.skipped {
        let msg = record.skip_reason.as_deref().unwrap_or("port closed");
        println!("[SKIP]  {target} {label} ({msg})");
    } else if let Some(err) = &record.error {
        println!("[ERROR] {target} {label} ({err})");
    } else if record.detected {
        for finding in &record.findings {
            print_finding_line(&record.target, finding);
        }
    } else {
        println!("[OK]    {target} {label}");
    }
}

fn print_human(report: &ScanRunReport, verbose: bool) -> Result<(), String> {
    let multi = report.summary.total_runs > 1;

    if !verbose {
        // One line per finding: `[SEVERITY] target title`. Only detected runs
        // carry findings, so non-detected runs stay silent here. Full metadata
        // is in the --report file.
        for record in &report.results {
            for finding in &record.findings {
                print_finding_line(&record.target, finding);
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
    // Registry refs (`ns/name@version`) and other already-friendly labels
    // shouldn't get path-style basename trimming — `file_name()` on
    // `teodhor87/log4shell@0.2.0` would drop the namespace.
    if script.contains('@') {
        return script.to_string();
    }
    PathBuf::from(script)
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_string)
        .unwrap_or_else(|| script.to_string())
}

/// One readable line per finding: `[SEVERITY] target title`. The full
/// metadata (description, cve/cwe, cvss, mitigation, evidence, version,
/// family, tags, …) is written to the `--report` json/csv file, not the
/// console log.
fn print_finding_line(target: &str, finding: &FindingRecord) {
    println!(
        "[{}] {} {}",
        finding.severity.to_uppercase(),
        display_target(target),
        finding.name
    );
}

/// Strip the `http(s)://` carrier scheme for display. `--target` may be a URL
/// or a bare host; a TCP/UDP/DNS scan isn't HTTP, so showing `http://host` for
/// a Redis finding reads wrong. The report keeps the full original target —
/// only the console log is trimmed.
fn display_target(target: &str) -> &str {
    target
        .strip_prefix("https://")
        .or_else(|| target.strip_prefix("http://"))
        .unwrap_or(target)
}

pub fn exit_code_from_report(report: &ScanRunReport) -> i32 {
    if report.summary.failed > 0 { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_report() -> ScanRunReport {
        ScanRunReport {
            targets: vec!["t".into()],
            scripts: vec!["s".into()],
            summary: ScanSummary {
                total_runs: 0,
                detected: 0,
                failed: 0,
                skipped: 0,
                clean: 0,
            },
            results: Vec::new(),
        }
    }

    fn record(target: &str, script: &str) -> ScanResultRecord {
        ScanResultRecord {
            target: target.into(),
            script: script.into(),
            success: true,
            detected: false,
            check: None,
            error: None,
            skip_reason: None,
            findings: Vec::new(),
            skipped: false,
            port_checks: Vec::new(),
        }
    }

    #[test]
    fn classifies_clean_run() {
        let mut report = empty_report();
        report.push_record(record("t", "s"));
        assert_eq!(report.summary.clean, 1);
        assert_eq!(report.summary.failed, 0);
    }

    #[test]
    fn classifies_failed_when_success_false_without_error_string() {
        // Regression for M3: a Fail-opcode result has `success=false` but
        // no `error` string. It must land in `failed`, not `clean`.
        let mut report = empty_report();
        let mut r = record("t", "s");
        r.success = false;
        report.push_record(r);
        assert_eq!(report.summary.failed, 1);
        assert_eq!(report.summary.clean, 0);
    }

    #[test]
    fn classifies_skipped_runs_correctly() {
        let mut report = empty_report();
        let mut r = record("t", "s");
        r.skipped = true;
        r.skip_reason = Some("port 80 closed".into());
        report.push_record(r);
        assert_eq!(report.summary.skipped, 1);
        assert_eq!(report.summary.failed, 0);
        assert_eq!(report.summary.clean, 0);
    }

    #[test]
    fn classifies_detected_runs_correctly() {
        let mut report = empty_report();
        let mut r = record("t", "s");
        r.detected = true;
        report.push_record(r);
        assert_eq!(report.summary.detected, 1);
    }

    #[test]
    fn skip_reason_is_distinct_from_error() {
        // Regression for M5: skipped records used to put their reason into
        // `error`. They are now separate channels.
        let mut report = empty_report();
        let mut r = record("t", "s");
        r.skipped = true;
        r.skip_reason = Some("port closed".into());
        report.push_record(r);
        let stored = &report.results[0];
        assert!(stored.error.is_none());
        assert_eq!(stored.skip_reason.as_deref(), Some("port closed"));
    }
}
