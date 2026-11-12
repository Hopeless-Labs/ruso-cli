# ruso-cli

> [!IMPORTANT]
> **This repository has moved.** `ruso-cli` is now a crate in the Ruso workspace at
> **[Hopeless-Labs/ruso](https://github.com/Hopeless-Labs/ruso)**, together with
> the other two crates it was always built against. This repository is archived
> and read-only; it is kept only as a record of the history up to the move.
>
> - Source: [`crates/ruso-cli/`](https://github.com/Hopeless-Labs/ruso/tree/main/crates/ruso-cli)
> - Install the CLI: `cargo install --git https://github.com/Hopeless-Labs/ruso.git ruso-cli`
> - Depend on a library: `{ git = "https://github.com/Hopeless-Labs/ruso.git", branch = "main" }`
> - Documentation: <https://docs.ruso.hopeless-labs.com>

[![Rust CI](https://github.com/Hopeless-Labs/ruso-cli/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/Hopeless-Labs/ruso-cli/actions/workflows/rust.yml)

> [!NOTE]
> **Development status:** under active development. The RSL, compiler output, and
> grammar may change without notice. Not recommended for production use yet.

`ruso` — the command-line vulnerability scanner of the
[Ruso](https://github.com/Hopeless-Labs) ecosystem. Point it at a target and scan
against a library of shareable checks written in the **Ruso Scripting Language
(RSL)** — or write your own.

📖 **Full documentation:** <https://docs.ruso.hopeless-labs.com>

## Install

```bash
cargo install --git https://github.com/Hopeless-Labs/ruso.git ruso-cli
```

## Quick start

> Scan only systems you own or are explicitly authorized to test.

```bash
# Scan a target against an entire family of community checks — nothing to write.
ruso scan --family web --target https://target.example.com

# Find a specific check in the registry…
ruso search log4j --tag rce

# …and run it by reference (fetched + cached on first use).
ruso scan --script someuser/log4shell --target https://target.example.com -v
```

Prefer to run your own check? Write a `.rsl` file and scan it directly:

```bash
ruso validate --script check.rsl                              # syntax only, no network
ruso scan     --script check.rsl --target https://target.example.com
```

## Commands at a glance

| | |
|---|---|
| `scan` | Compile + run a check (or `--family`) against targets |
| `validate` / `compile` / `exec` | Check syntax · compile to `.rbc` · run compiled bytecode |
| `search` / `info` / `install` | Discover and fetch published checks |
| `publish` / `yank` / `edit` | Share and manage your own checks |
| `login` / `logout` / `whoami` / `pat` | Registry authentication |

Full flags, examples, and the language reference are in
**[The Ruso Book](https://docs.ruso.hopeless-labs.com)**.

## Build from source

```bash
git clone https://github.com/Hopeless-Labs/ruso.git
cd ruso && cargo build --release   # binary at ./target/release/ruso
```

`ruso-runtime` and `ruso-script` are in that same checkout under `crates/`, so a
change to either is picked up by the CLI with nothing to configure.

## License

Apache License 2.0. See [LICENSE](LICENSE).
