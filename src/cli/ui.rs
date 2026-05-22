//! Simple user-facing stderr output (spinner and errors).

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const FRAMES: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/// Terminal spinner; cleared automatically on drop.
pub struct Spinner {
    done: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Spinner {
    pub fn start() -> Self {
        let done = Arc::new(AtomicBool::new(false));
        let done_thread = done.clone();

        let handle = thread::spawn(move || {
            let mut frame = 0usize;
            let mut stderr = std::io::stderr().lock();
            while !done_thread.load(Ordering::Relaxed) {
                let ch = FRAMES[frame % FRAMES.len()];
                let _ = write!(stderr, "\r{ch} ");
                let _ = stderr.flush();
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
        }
        let mut stderr = std::io::stderr().lock();
        let _ = write!(stderr, "\r\x1b[2K");
        let _ = stderr.flush();
    }
}

pub fn error(message: &str) {
    eprintln!("error: {message}");
}
