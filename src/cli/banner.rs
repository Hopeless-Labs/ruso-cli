//! Startup banner: the "ruso" wordmark (figlet ANSI Shadow) plus the project
//! links, shown once at the top of every interactive invocation.
//!
//! It is decoration, not data, so it goes to **stderr** and only when stderr is
//! a terminal — piped/CI runs and the report on stdout stay clean. Colour
//! follows the usual stderr TTY / `NO_COLOR` rule. The wordmark is drawn in the
//! ruso brand orange as a vertical 24-bit gradient.

use std::io::IsTerminal;

use crate::cli::style;

/// The "ruso" wordmark in the figlet ANSI Shadow font.
const ART: [&str; 6] = [
    "██████╗ ██╗   ██╗███████╗ ██████╗ ",
    "██╔══██╗██║   ██║██╔════╝██╔═══██╗",
    "██████╔╝██║   ██║███████╗██║   ██║",
    "██╔══██╗██║   ██║╚════██║██║   ██║",
    "██║  ██║╚██████╔╝███████║╚██████╔╝",
    "╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ",
];

const GITHUB_URL: &str = "https://github.com/Hopeless-Labs/ruso-cli";

/// Gradient endpoints — ruso orange, top (Tailwind orange-400) fading into a
/// deeper bottom (orange-700).
const GRAD_TOP: (u8, u8, u8) = (251, 146, 60);
const GRAD_BOTTOM: (u8, u8, u8) = (194, 65, 12);

fn lerp(a: u8, b: u8, t: f32) -> u8 {
    (f32::from(a) + (f32::from(b) - f32::from(a)) * t).round() as u8
}

/// Colour for art row `i` of `n`, interpolated top→bottom.
fn gradient(i: usize, n: usize) -> (u8, u8, u8) {
    let t = if n > 1 {
        i as f32 / (n - 1) as f32
    } else {
        0.0
    };
    (
        lerp(GRAD_TOP.0, GRAD_BOTTOM.0, t),
        lerp(GRAD_TOP.1, GRAD_BOTTOM.1, t),
        lerp(GRAD_TOP.2, GRAD_BOTTOM.2, t),
    )
}

/// Print the banner to stderr when it is a TTY. `registry_url` is the effective
/// registry base for this run.
pub fn print(registry_url: &str) {
    if !std::io::stderr().is_terminal() {
        return;
    }
    let c = style::colors_enabled_stderr();
    eprintln!();
    for (i, line) in ART.iter().enumerate() {
        eprintln!("{}", style::rgb_bold(c, gradient(i, ART.len()), line));
    }
    // Label/value lines, labels padded so the values line up.
    let info = |label: &str, value: String| {
        eprintln!("  {} {value}", style::dim(c, &format!("{label:<8}")));
    };
    info(
        "version",
        style::rgb_bold(c, style::ACCENT, env!("CARGO_PKG_VERSION")),
    );
    info("github", style::rgb_link(c, style::ACCENT, GITHUB_URL));
    info("registry", style::rgb_link(c, style::ACCENT, registry_url));
    eprintln!();
}
