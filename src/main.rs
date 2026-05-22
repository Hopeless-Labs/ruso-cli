mod cli;
mod logging;
mod util;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    cli::run().await
}
