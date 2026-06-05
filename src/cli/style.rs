//! ANSI colour + emphasis for the human scan output.
//!
//! Colour is emitted only when stdout is a terminal and `NO_COLOR` is unset
//! (see <https://no-color.org/>); piped or redirected output stays plain so
//! logs, `grep`, and the `--report` pipeline never see escape codes. Every
//! formatting helper also takes an explicit `enabled` flag so the rendering is
//! unit-testable without a real TTY.

use std::io::IsTerminal;
use std::sync::OnceLock;

const RESET: &str = "\x1b[0m";

/// Visible width every leading `[TAG]` is padded to, so the target column
/// lines up across findings (`[CRITICAL]`) and status rows (`[OK]`).
const TAG_WIDTH: usize = 10;

/// Colour iff the given stream is a terminal and `NO_COLOR` is unset.
fn detect(stream_is_terminal: bool) -> bool {
    // Any presence of NO_COLOR disables colour, regardless of its value.
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    stream_is_terminal
}

/// Whether colour should be emitted on **stdout** (scan findings/status),
/// decided once from the environment.
pub fn colors_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| detect(std::io::stdout().is_terminal()))
}

/// Whether colour should be emitted on **stderr** (warnings, errors), decided
/// once from the environment. Separate from [`colors_enabled`] because stdout
/// and stderr can be redirected independently.
pub fn colors_enabled_stderr() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| detect(std::io::stderr().is_terminal()))
}

/// Wrap `text` in an SGR sequence when `enabled`, otherwise return it as-is.
fn paint(enabled: bool, code: &str, text: &str) -> String {
    if enabled {
        format!("\x1b[{code}m{text}{RESET}")
    } else {
        text.to_string()
    }
}

/// Left-pad the *plain* `[TAG]` to [`TAG_WIDTH`] before colouring, so the
/// invisible escape bytes never throw the column alignment off.
fn tag(label: &str) -> String {
    format!("{label:<TAG_WIDTH$}")
}

/// SGR code for a severity word (case-insensitive).
fn severity_code(severity: &str) -> &'static str {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => "1;95", // bold bright magenta
        "high" => "1;31",     // bold red
        "medium" => "33",     // yellow
        "low" => "36",        // cyan
        "info" => "90",       // grey
        _ => "0",
    }
}

/// `[SEVERITY]` tag, colour-coded by level and padded to the tag column.
pub fn severity_tag(enabled: bool, severity: &str) -> String {
    let label = tag(&format!("[{}]", severity.to_uppercase()));
    paint(enabled, severity_code(severity), &label)
}

/// `[OK]` / `[SKIP]` / `[ERROR]` status tag, colour-coded and padded.
pub fn status_tag(enabled: bool, status: &str) -> String {
    let code = match status {
        "OK" => "32",    // green
        "SKIP" => "33",  // yellow
        "ERROR" => "31", // red
        _ => "0",
    };
    let label = tag(&format!("[{status}]"));
    paint(enabled, code, &label)
}

/// Emphasise the scan target (bold).
pub fn target(enabled: bool, text: &str) -> String {
    paint(enabled, "1", text)
}

/// De-emphasise secondary text — script label, skip/error reason.
pub fn dim(enabled: bool, text: &str) -> String {
    paint(enabled, "2", text)
}

/// Bold a heading (the multi-run summary title).
pub fn heading(enabled: bool, text: &str) -> String {
    paint(enabled, "1", text)
}

/// Red highlight for a non-zero detected/failed count in the summary.
pub fn alert(enabled: bool, text: &str) -> String {
    paint(enabled, "31", text)
}

/// Yellow highlight (e.g. a non-zero skipped count).
pub fn caution(enabled: bool, text: &str) -> String {
    paint(enabled, "33", text)
}

/// Green highlight (e.g. a non-zero clean count).
pub fn good(enabled: bool, text: &str) -> String {
    paint(enabled, "32", text)
}

/// `[WARNING]` tag for stderr advisories (bold yellow).
pub fn warn_tag(enabled: bool) -> String {
    paint(enabled, "1;33", "[WARNING]")
}

/// `[ERROR]` tag for stderr failures (bold red).
pub fn error_tag(enabled: bool) -> String {
    paint(enabled, "1;31", "[ERROR]")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_when_disabled_and_padded() {
        let s = severity_tag(false, "high");
        assert_eq!(s, "[HIGH]    "); // padded to TAG_WIDTH, no escapes
        assert!(!s.contains('\x1b'));
    }

    #[test]
    fn coloured_when_enabled() {
        let s = severity_tag(true, "critical");
        assert!(s.starts_with("\x1b[1;95m"), "got {s:?}");
        assert!(s.ends_with(RESET));
        assert!(s.contains("[CRITICAL]"));
    }

    #[test]
    fn tags_share_one_column_width() {
        // With colour off the visible length is exactly TAG_WIDTH, so finding
        // rows and status rows align under one target column.
        assert_eq!(status_tag(false, "OK").len(), TAG_WIDTH);
        assert_eq!(status_tag(false, "ERROR").len(), TAG_WIDTH);
        assert_eq!(severity_tag(false, "low").len(), TAG_WIDTH);
        assert_eq!(severity_tag(false, "critical").len(), TAG_WIDTH);
    }

    #[test]
    fn unknown_severity_is_uncoloured() {
        assert_eq!(severity_code("weird"), "0");
        // still padded and bracketed, just no colour
        assert_eq!(severity_tag(false, "weird"), "[WEIRD]   ");
    }
}
