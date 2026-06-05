//! Simple user-facing stderr output (spinner and errors).

use std::future::Future;
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::cli::style;

const FRAMES: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/// Set once from the top-level `--verbose` flag. Spinners stay dormant when
/// verbose, because the debug-log stream on stderr would garble them — the
/// per-run log lines are the progress indicator in that mode.
static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Record the verbosity so every spinner can self-gate on it. Call once at
/// startup.
pub fn init(verbose: bool) {
    VERBOSE.store(verbose, Ordering::Relaxed);
}

/// Spinners animate only on an interactive, non-verbose stderr.
fn spinners_suppressed() -> bool {
    VERBOSE.load(Ordering::Relaxed) || !std::io::stderr().is_terminal()
}

/// Run `fut` under a labelled spinner, clearing the spinner before returning so
/// the caller's own output never collides with the spinner line. Used by the
/// registry commands to show activity during a network call.
pub async fn with_spinner<F: Future>(label: impl Into<String>, fut: F) -> F::Output {
    let spinner = Spinner::start(label);
    let out = fut.await;
    drop(spinner);
    out
}

/// Terminal spinner; cleared automatically on drop.
///
/// Dormant (no thread, no output) when stderr is not a terminal, so piped/CI
/// runs never get spinner escape codes in their logs. An optional progress
/// counter renders `⠋ <label> <done>/<total>` and is advanced via the handle
/// returned by [`Spinner::with_progress`].
pub struct Spinner {
    done: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    /// Serialises the animation thread's writes against [`Spinner::suspend`],
    /// so a line printed mid-scan never collides with a spinner frame.
    render: Arc<Mutex<()>>,
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
        let render = Arc::new(Mutex::new(()));
        // Animate only on an interactive, non-verbose stderr; otherwise hand
        // back a dormant guard (no thread, no output).
        if spinners_suppressed() {
            done.store(true, Ordering::Relaxed);
            return Self {
                done,
                handle: None,
                render,
            };
        }
        let done_thread = done.clone();
        let render_thread = render.clone();
        let c = style::colors_enabled_stderr();

        let handle = thread::spawn(move || {
            let mut frame = 0usize;
            while !done_thread.load(Ordering::Relaxed) {
                let ch = FRAMES[frame % FRAMES.len()].to_string();
                let spin = style::rgb_bold(c, style::ACCENT, &ch);
                let line = match &progress {
                    Some((p, total)) => {
                        let done = p.load(Ordering::Relaxed).min(*total);
                        let pct = (done * 100).checked_div(*total).unwrap_or(100);
                        format!("\r{spin} {} {done}/{total} ({pct}%)", style::dim(c, &label))
                    }
                    None => format!("\r{spin} {}", style::dim(c, &label)),
                };
                // Hold the render lock + stderr only per frame, not across the
                // sleep: holding either across the sleep would block any
                // `suspend`/error print (and could deadlock) for up to a frame.
                {
                    let _render = render_thread.lock().unwrap();
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
            render,
        }
    }

    /// Run `f` with the spinner paused and its line cleared, so output printed
    /// inside `f` lands on a clean line; the animation resumes afterwards. On a
    /// dormant spinner it just runs `f`.
    pub fn suspend<R>(&self, f: impl FnOnce() -> R) -> R {
        if self.handle.is_none() {
            return f();
        }
        let _render = self.render.lock().unwrap();
        {
            let mut stderr = std::io::stderr().lock();
            let _ = write!(stderr, "\r\x1b[2K");
            let _ = stderr.flush();
        }
        f()
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
