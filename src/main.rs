// `PreparedScript::Ready` carries a `BytecodeProgram` which is large by
// design (probes + pools + instructions). The `Failed` variant is a string;
// the size asymmetry between Ok/Err is intentional.
#![allow(clippy::large_enum_variant)]

mod cli;
mod logging;
mod util;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    cli::run().await
}
