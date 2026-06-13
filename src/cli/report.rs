//! Structured scan reports: human on stdout, json/csv written to a file.
//!
//! The serialized report (json/csv) is **grouped by target** and
//! findings-focused: each target carries its own summary counts and the
//! findings detected on it (every finding tagged with the `script` that
//! produced it). Clean/failed/skipped runs are reflected only in the counts.
//! The internal `results` (per-run records) drive the live console output and
//! the human summary table and are not serialized.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;

use ruso_runtime::{ExecutionResult, PortCheck};

use crate::cli::style;

/// Report file format, chosen by the `--report` file extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    /// `.json`
    Json,
    /// `.csv`
    Csv,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanRunReport {
    pub summary: ScanSummary,
    /// Findings grouped by target (the serialized body).
    pub targets: Vec<TargetReport>,
    /// Per-run records — internal only (live output, human table, grouping).
    #[serde(skip)]
    results: Vec<ScanResultRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanSummary {
    pub total_runs: usize,
    pub detected: usize,
    pub failed: usize,
    pub skipped: usize,
    pub clean: usize,
}

/// One target's section of the report: its outcome counts and the findings
/// detected against it.
#[derive(Debug, Clone, Serialize)]
pub struct TargetReport {
    pub target: String,
    pub summary: TargetSummary,
    pub findings: Vec<FindingRecord>,
}

/// Per-target outcome counts (mirror [`ScanSummary`] minus `total_runs`).
#[derive(Debug, Clone, Serialize)]
pub struct TargetSummary {
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
    /// The script (file path or registry ref) that produced this finding.
    pub script: String,
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
    /// An empty report sized for `capacity` per-run records.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            summary: ScanSummary {
                total_runs: 0,
                detected: 0,
                failed: 0,
                skipped: 0,
                clean: 0,
            },
            targets: Vec::new(),
            results: Vec::with_capacity(capacity),
        }
    }

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

    /// Finalise: set `total_runs` and build the per-target sections from the
    /// collected per-run records, preserving first-seen target order. Each
    /// target's findings are the findings of its detected runs (already tagged
    /// with their script); clean/failed/skipped runs contribute only counts.
    pub fn finish(&mut self) {
        self.summary.total_runs = self.results.len();

        let mut order: Vec<String> = Vec::new();
        let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut targets: Vec<TargetReport> = Vec::new();

        for record in &self.results {
            let idx = *index.entry(record.target.clone()).or_insert_with(|| {
                order.push(record.target.clone());
                targets.push(TargetReport {
                    target: record.target.clone(),
                    summary: TargetSummary {
                        detected: 0,
                        failed: 0,
                        skipped: 0,
                        clean: 0,
                    },
                    findings: Vec::new(),
                });
                targets.len() - 1
            });
            let t = &mut targets[idx];
            if record.skipped {
                t.summary.skipped += 1;
            } else if record.detected {
                t.summary.detected += 1;
            } else if !record.success {
                t.summary.failed += 1;
            } else {
                t.summary.clean += 1;
            }
            t.findings.extend(record.findings.iter().cloned());
        }

        self.targets = targets;
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
                script: script.clone(),
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

/// The report format implied by a `--report` path's extension, or an error
/// if the extension isn't `.json` / `.csv`.
pub fn report_format_from_path(path: &Path) -> Result<ReportFormat, String> {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        Some("json") => Ok(ReportFormat::Json),
        Some("csv") => Ok(ReportFormat::Csv),
        _ => Err(format!(
            "unsupported --report file `{}`: use a .json or .csv extension",
            path.display()
        )),
    }
}

/// Validate the `--report` path (if any) before scanning, so a bad extension
/// fails fast rather than after a full run.
pub fn validate_report_options(report_path: Option<&Path>) -> Result<(), String> {
    match report_path {
        Some(path) => report_format_from_path(path).map(|_| ()),
        None => Ok(()),
    }
}

/// Human summary/findings always print to stdout; when `--report <path>` is
/// given, a json/csv file is additionally written (format from the extension).
pub fn emit_scan_report(
    report: &ScanRunReport,
    report_path: Option<&Path>,
    verbose: bool,
    duration: Duration,
) -> Result<(), String> {
    print_human(report, verbose, duration)?;

    if let Some(path) = report_path {
        match report_format_from_path(path)? {
            ReportFormat::Json => write_json_file(report, path)?,
            ReportFormat::Csv => write_csv_file(report, path)?,
        }
        eprintln!("report saved: {}", path.display());
    }
    Ok(())
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
        ])
        .map_err(|err| err.to_string())?;

    // One row per finding, grouped by target (targets are in first-seen order).
    for target in &report.targets {
        for finding in &target.findings {
            write_csv_row(&mut writer, &target.target, finding)?;
        }
    }

    writer
        .flush()
        .map_err(|err| format!("flush report {}: {err}", path.display()))?;
    Ok(())
}

fn write_csv_row(
    writer: &mut csv::Writer<File>,
    target: &str,
    finding: &FindingRecord,
) -> Result<(), String> {
    let evidence = finding.evidence.join(" | ");
    let cve = finding.cve.join(" | ");
    let cwe = finding.cwe.join(" | ");
    let references = finding.references.join(" | ");
    let cvss = finding.cvss.join(" | ");
    let cvss_score = finding.cvss_score.join(" | ");
    let mitigation = finding.mitigation.clone().unwrap_or_default();
    let version = finding.version.clone().unwrap_or_default();
    let family = finding.family.clone().unwrap_or_default();
    let tags = finding.tags.join(" | ");
    writer
        .write_record([
            target,
            finding.script.as_str(),
            finding.severity.as_str(),
            finding.name.as_str(),
            finding.description.as_deref().unwrap_or(""),
            finding.impact.as_deref().unwrap_or(""),
            finding.author.as_deref().unwrap_or(""),
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
        ])
        .map_err(|err| err.to_string())
}

/// Incremental line while scanning (`-v` + human) on stdout.
pub fn print_live_run(record: &ScanResultRecord, _multi_target: bool) {
    let label = script_label(&record.script);
    let target = display_target(&record.target);
    if record.skipped {
        let msg = record.skip_reason.as_deref().unwrap_or("port closed");
        print_status_line("SKIP", target, &label, Some(msg));
    } else if let Some(err) = &record.error {
        print_status_line("ERROR", target, &label, Some(err));
    } else if record.detected {
        for finding in &record.findings {
            print_finding_line(&record.target, finding);
        }
    } else {
        print_status_line("OK", target, &label, None);
    }
}

/// One `[OK]/[SKIP]/[ERROR]` status row (verbose mode): coloured tag, bold
/// target, dimmed script label, and an optional dimmed `(reason)`.
fn print_status_line(status: &str, target: &str, label: &str, note: Option<&str>) {
    let c = style::colors_enabled();
    let mut line = format!(
        "{} {}  {}",
        style::status_tag(c, status),
        style::target(c, target),
        style::dim(c, label),
    );
    if let Some(note) = note {
        line.push(' ');
        line.push_str(&style::dim(c, &format!("({note})")));
    }
    println!("{line}");
}

fn print_human(report: &ScanRunReport, verbose: bool, duration: Duration) -> Result<(), String> {
    let multi = report.summary.total_runs > 1;

    // Findings (and verbose status rows) are streamed live during the scan via
    // `print_finding_line` / `print_live_run`, so nothing per-run is printed
    // here — only the closing summary table.
    if multi && (report.summary.detected > 0 || report.summary.failed > 0 || verbose) {
        print_summary_table(report, duration);
    }

    Ok(())
}

/// English plural suffix for a count (`1 target`, `48 targets`).
fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// Per-target run counts in the order targets were first seen.
/// `counts` is `[detected, failed, skipped, clean]`, aligned with the table
/// columns and their colourisers.
struct TargetTally {
    target: String,
    counts: [usize; 4],
}

/// Which `counts` bucket a record falls in — mirrors `ScanRunReport::push_record`.
fn bucket_index(r: &ScanResultRecord) -> usize {
    if r.skipped {
        2 // skipped
    } else if r.detected {
        0 // detected
    } else if !r.success {
        1 // failed
    } else {
        3 // clean
    }
}

/// Aggregate every run into per-target tallies, preserving first-seen order.
fn tally_by_target(report: &ScanRunReport) -> Vec<TargetTally> {
    let mut order: Vec<String> = Vec::new();
    let mut counts: std::collections::HashMap<String, [usize; 4]> =
        std::collections::HashMap::new();
    for r in &report.results {
        let key = display_target(&r.target).to_string();
        if !counts.contains_key(&key) {
            order.push(key.clone());
            counts.insert(key.clone(), [0; 4]);
        }
        counts.get_mut(&key).unwrap()[bucket_index(r)] += 1;
    }
    order
        .into_iter()
        .map(|target| {
            let counts = counts[&target];
            TargetTally { target, counts }
        })
        .collect()
}

/// Human-friendly elapsed time: `840ms`, `1.2s`, `2m03s`.
fn format_duration(d: Duration) -> String {
    if d.as_millis() < 1000 {
        format!("{}ms", d.as_millis())
    } else if d.as_secs() < 60 {
        format!("{:.1}s", d.as_secs_f64())
    } else {
        let secs = d.as_secs();
        format!("{}m{:02}s", secs / 60, secs % 60)
    }
}

/// Render the multi-run outcome as a per-target table, e.g.
///
/// ```text
/// ┌─────────────┬──────────┬────────┬─────────┬───────┐
/// │ target      │ detected │ failed │ skipped │ clean │
/// ├─────────────┼──────────┼────────┼─────────┼───────┤
/// │ target.test │        0 │     48 │       0 │     0 │
/// │ example.com │        2 │      1 │       0 │    45 │
/// └─────────────┴──────────┴────────┴─────────┴───────┘
/// scan duration 1.2s · 96 runs across 2 targets
/// ```
///
/// Each count is coloured by bucket when non-zero (detected/failed red,
/// skipped yellow, clean green) and dimmed at zero, so the eye lands on what
/// actually happened.
fn print_summary_table(report: &ScanRunReport, duration: Duration) {
    let c = style::colors_enabled();
    let tallies = tally_by_target(report);

    const HEAD: [&str; 4] = ["detected", "failed", "skipped", "clean"];
    // A `style` colouriser: `(enabled, text) -> painted`. One per column,
    // applied to a count cell when it is non-zero.
    type Colouriser = fn(bool, &str) -> String;
    const PAINT: [Colouriser; 4] = [style::alert, style::alert, style::caution, style::good];

    // Column widths: target column fits its widest value (or the header), each
    // numeric column fits its header or widest count.
    let target_w = tallies
        .iter()
        .map(|t| t.target.chars().count())
        .chain(std::iter::once("target".len()))
        .max()
        .unwrap_or(6);
    let num_w: [usize; 4] = std::array::from_fn(|i| {
        let widest = tallies
            .iter()
            .map(|t| t.counts[i].to_string().len())
            .max()
            .unwrap_or(1);
        HEAD[i].len().max(widest)
    });

    // Horizontal rule with a segment per column (content width + 1 pad each side).
    let rule = |left: char, mid: char, right: char| {
        let mut s = String::from(left);
        s.push_str(&"─".repeat(target_w + 2));
        for w in num_w {
            s.push(mid);
            s.push_str(&"─".repeat(w + 2));
        }
        s.push(right);
        s
    };

    // A full row from an already-painted target cell and four count cells.
    let row_line = |target_cell: String, count_cells: [String; 4]| {
        let mut s = format!("│ {target_cell} ");
        for cell in count_cells {
            s.push_str(&format!("│ {cell} "));
        }
        s.push('│');
        s
    };

    println!();
    println!("{}", rule('┌', '┬', '┐'));
    // Header row — pad plain text to the column width, then bold it.
    let head_target = style::heading(c, &format!("{:<target_w$}", "target"));
    let head_counts: [String; 4] =
        std::array::from_fn(|i| style::heading(c, &format!("{:>w$}", HEAD[i], w = num_w[i])));
    println!("{}", row_line(head_target, head_counts));
    println!("{}", rule('├', '┼', '┤'));

    for t in &tallies {
        let target_cell = style::target(c, &format!("{:<target_w$}", t.target));
        let count_cells: [String; 4] = std::array::from_fn(|i| {
            let n = t.counts[i];
            let cell = format!("{n:>w$}", w = num_w[i]);
            if n > 0 {
                PAINT[i](c, &cell)
            } else {
                style::dim(c, &cell)
            }
        });
        println!("{}", row_line(target_cell, count_cells));
    }
    println!("{}", rule('└', '┴', '┘'));

    let targets = tallies.len();
    let total = report.summary.total_runs;
    println!(
        "{}",
        style::dim(
            c,
            &format!(
                "scan duration {} · {total} run{} across {targets} target{}",
                format_duration(duration),
                plural(total),
                plural(targets),
            )
        )
    );
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

/// One readable line per finding: a colour-coded `[SEVERITY]` tag, the bold
/// target, then the finding title. The full metadata (description, cve/cwe,
/// cvss, mitigation, evidence, version, family, tags, …) is written to the
/// `--report` json/csv file, not the console log.
pub fn print_finding_line(target: &str, finding: &FindingRecord) {
    let c = style::colors_enabled();
    println!(
        "{} {}  {}",
        style::severity_tag(c, &finding.severity),
        style::target(c, display_target(target)),
        finding.name,
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
        ScanRunReport::with_capacity(0)
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

    fn finding(script: &str, name: &str) -> FindingRecord {
        FindingRecord {
            script: script.into(),
            name: name.into(),
            severity: "high".into(),
            description: None,
            impact: None,
            author: None,
            cve: Vec::new(),
            cwe: Vec::new(),
            references: Vec::new(),
            cvss: Vec::new(),
            cvss_score: Vec::new(),
            mitigation: None,
            version: None,
            family: None,
            tags: Vec::new(),
            evidence: Vec::new(),
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
    fn finish_groups_findings_by_target_with_script_on_finding() {
        let mut report = empty_report();
        // Target A: one detected run (carrying a finding) + one clean run.
        let mut a1 = record("https://a", "s1.rsl");
        a1.detected = true;
        a1.findings = vec![finding("s1.rsl", "Finding A")];
        report.push_record(a1);
        report.push_record(record("https://a", "s2.rsl")); // clean
        // Target B: one failed run, no finding.
        let mut b1 = record("https://b", "s3.rsl");
        b1.success = false;
        report.push_record(b1);

        report.finish();

        assert_eq!(report.summary.total_runs, 3);
        assert_eq!(report.targets.len(), 2);

        // First-seen order preserved: A before B.
        let a = &report.targets[0];
        assert_eq!(a.target, "https://a");
        assert_eq!(a.summary.detected, 1);
        assert_eq!(a.summary.clean, 1);
        assert_eq!(a.findings.len(), 1);
        // The script that produced the finding rides on the finding itself.
        assert_eq!(a.findings[0].script, "s1.rsl");

        let b = &report.targets[1];
        assert_eq!(b.target, "https://b");
        assert_eq!(b.summary.failed, 1);
        assert!(b.findings.is_empty());
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
    fn tally_groups_runs_per_target_in_first_seen_order() {
        let mut report = empty_report();
        // host-b first, then host-a, to prove order is preserved.
        let mut detected = record("https://host-b", "s1");
        detected.detected = true;
        report.results.push(detected);
        report.results.push(record("https://host-a", "s2")); // clean
        let mut failed = record("https://host-b", "s3");
        failed.success = false;
        report.results.push(failed);

        let tallies = tally_by_target(&report);
        assert_eq!(tallies.len(), 2);
        // display_target strips the scheme; host-b seen first.
        assert_eq!(tallies[0].target, "host-b");
        assert_eq!(tallies[0].counts, [1, 1, 0, 0]); // detected, failed
        assert_eq!(tallies[1].target, "host-a");
        assert_eq!(tallies[1].counts, [0, 0, 0, 1]); // clean
    }

    #[test]
    fn duration_formats_by_magnitude() {
        assert_eq!(format_duration(Duration::from_millis(840)), "840ms");
        assert_eq!(format_duration(Duration::from_millis(1230)), "1.2s");
        assert_eq!(format_duration(Duration::from_secs(123)), "2m03s");
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
