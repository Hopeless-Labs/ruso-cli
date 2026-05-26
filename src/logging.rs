//! Tracing setup for the `ruso` binary and optional embedders.

use tracing_subscriber::EnvFilter;

/// Initialize the global tracing subscriber.
///
/// Uses `RUST_LOG` when set; otherwise uses `default_filter`.
/// Detailed spans and targets appear only when `verbose` is true.
pub fn init(default_filter: &str, verbose: bool) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));

    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);

    if verbose {
        builder
            .with_target(true)
            .with_level(true)
            .with_thread_ids(false)
            .with_file(false)
            .with_line_number(false)
            .compact()
            .init();
    } else {
        builder
            .with_target(false)
            .with_level(false)
            .with_ansi(true)
            .without_time()
            .init();
    }
}
