//! Simple user-facing stderr output (spinner and errors).

use std::io::{IsTerminal, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use crate::cli::style;

const FRAMES: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/// Terminal spinner; cleared automatically on drop.
///
/// Dormant (no thread, no output) when stderr is not a terminal, so piped/CI
/// runs never get spinner escape codes in their logs. An optional progress
/// counter renders `⠋ <label> <done>/<total>` and is advanced via the handle
/// returned by [`Spinner::with_progress`].
pub struct Spinner {
    done: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Spinner {
    /// A plain labelled spinner: `⠋ <label>`.
    pub fn start(label: impl Into<String>) -> Self {
        Self::spawn(label.into(), None)
    }

    /// A spinner with a live `done/total` counter. Returns the spinner plus the
    /// shared counter the caller bumps as work completes.
    pub fn with_progress(label: impl Into<String>, total: usize) -> (Self, Arc<AtomicUsize>) {
        let progress = Arc::new(AtomicUsize::new(0));
        let spinner = Self::spawn(label.into(), Some((progress.clone(), total)));
        (spinner, progress)
    }

    fn spawn(label: String, progress: Option<(Arc<AtomicUsize>, usize)>) -> Self {
        let done = Arc::new(AtomicBool::new(false));
        // Only animate on a real terminal; otherwise hand back a dormant guard.
        if !std::io::stderr().is_terminal() {
            done.store(true, Ordering::Relaxed);
            return Self { done, handle: None };
        }
        let done_thread = done.clone();
        let c = style::colors_enabled_stderr();

        let handle = thread::spawn(move || {
            let mut frame = 0usize;
            while !done_thread.load(Ordering::Relaxed) {
                let ch = FRAMES[frame % FRAMES.len()].to_string();
                let spin = style::rgb_bold(c, style::ACCENT, &ch);
                let line = match &progress {
                    Some((p, total)) => format!(
                        "\r{spin} {} {}/{total}",
                        style::dim(c, &label),
                        p.load(Ordering::Relaxed).min(*total),
                    ),
                    None => format!("\r{spin} {}", style::dim(c, &label)),
                };
                // Lock stderr per frame, not for the spinner's whole lifetime.
                // Holding the lock across the sleep would deadlock the main
                // thread the moment it tries to emit an error (ui::error /
                // tracing) while the spinner is still running — which is
                // exactly what every failed scan/validate/compile does.
                {
                    let mut stderr = std::io::stderr().lock();
                    // `\x1b[K` clears to end of line so a shrinking counter
                    // (e.g. 9/9 → 10/48) never leaves stale digits behind.
                    let _ = write!(stderr, "{line}\x1b[K");
                    let _ = stderr.flush();
                }
                frame += 1;
                thread::sleep(Duration::from_millis(80));
            }
        });

        Self {
            done,
            handle: Some(handle),
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
            // Only the live spinner wrote anything, so only it needs to wipe
            // the line; a dormant (non-TTY) guard leaves stderr untouched.
            let mut stderr = std::io::stderr().lock();
            let _ = write!(stderr, "\r\x1b[2K");
            let _ = stderr.flush();
        }
    }
}

pub fn error(message: &str) {
    let c = style::colors_enabled_stderr();
    eprintln!("{} {message}", style::error_tag(c));
}

/// User-facing warning, always printed to stderr regardless of log verbosity
/// (unlike `tracing::warn!`, which the default `ruso=off` filter suppresses).
pub fn warn(message: &str) {
    let c = style::colors_enabled_stderr();
    eprintln!("{} {message}", style::warn_tag(c));
}
