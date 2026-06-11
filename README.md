# Ruso-cli

[![Rust CI](https://github.com/Hopeless-Labs/ruso-cli/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/Hopeless-Labs/ruso-cli/actions/workflows/rust.yml)

Command-line tool for Ruso checks (`ruso` binary). Write a vulnerability check in the Ruso Scripting Language (`.rsl`), point it at a target, and scan — all from one command. Runs `.rsl` scripts locally, *and* talks to a [`ruso-backend`](https://github.com/Hopeless-Labs/ruso-backend) registry instance for publishing, installing, and searching shared checks.

## Quick start

```bash
# One command: compile + run a check against a target.
ruso scan --script check.rsl --target https://httpbin.org -v

# Prefer it step by step?
ruso validate --script check.rsl                              # syntax only, no network
ruso compile  --script check.rsl                              # → check.rbc
ruso exec     --bytecode check.rbc --target https://httpbin.org
```

That's it — no config, no setup. Grab a ready-made check from [ruso-script/examples](https://github.com/Hopeless-Labs/ruso-script/tree/main/examples) and scan in seconds.

> **Development status:** This project is under active development. APIs, bytecode format, and CLI behavior may change without notice. Not recommended for production use yet.

## Commands

### Local

| Command | Description |
|---------|-------------|
| `scan` | Run `.rsl` scripts against targets (compile + run in one step). `--script <path\|ref>` or `--family <name>` to run a whole category |
| `validate` | Validate `.rsl` syntax (no network) |
| `compile` | Compile to `<name>.rbc` (hex text, no terminal output) |
| `exec` | Run `.rbc` bytecode against targets |

### Registry (talks to `ruso-backend`)

| Command | Description |
|---------|-------------|
| `login` | Save a PAT or session token for the active registry |
| `logout` | Delete the stored credential |
| `whoami` | Show the user the stored credential belongs to |
| `publish` | Upload a `.rsl` script to the registry |
| `install` | Download `<namespace>/<name>[@<range>]` into the local cache |
| `search` | Search published scripts (free-text + tag/severity/cve/namespace/family filters) |
| `info` | Show registry metadata for a script (versions, install snippet, tags) |
| `yank` / `unyank` | Pull / restore a published version (owner-only, idempotent) |
| `edit` | Update description / visibility of a script you own |
| `pat list/create/revoke` | Manage PATs from the terminal — full lifecycle without the web UI |

Plus: `ruso scan --script <namespace>/<name>[@<range>]` resolves a registry reference through the local cache, fetching from the registry on miss. Same for `ruso exec --bytecode <namespace>/<name>[@<range>]`. Filesystem paths always win over ref pattern matching, so a local file/directory named like a slug still works.

See **[docs/CLI.md](docs/CLI.md)** for flags and examples.

## Using a registry

```bash
# 1. Log in (PAT or session token from the backend's web flow).
#    Reads token from stdin if --token is omitted.
echo "ruso_pat_…" | ruso login

# 2. Publish a script. Namespace defaults to your username.
ruso publish ./mycheck.rsl --visibility public

# 3. Find shared scripts.
ruso search "log4j" --tag rce

# 4. Install + scan a registry-hosted check (cached at
#    ~/.ruso/scripts/<ns>/<name>/<version>.rbc).
ruso install someuser/log4shell@^0.2
ruso scan --script someuser/log4shell --target https://target.example.com -v
```

### Pointing at a different registry

Registry URL precedence: `--registry <url>` > `$RUSO_REGISTRY_URL` > built-in default (`https://ruso.hopeless-labs.com`, the hosted registry; use `http://127.0.0.1:8080` for a local `ruso-backend`).

Credentials are stored per registry URL in `$XDG_CONFIG_HOME/ruso/credentials.json` (mode 0600 on Unix), so the same machine can be logged into a local backend *and* a hosted one at the same time.

## Build

```bash
cargo build --release
```

## Dependencies

```toml
ruso-runtime = { git = "https://github.com/Hopeless-Labs/ruso-runtime.git", branch = "main" }
ruso-script  = { git = "https://github.com/Hopeless-Labs/ruso-script.git", branch = "main" }
```

## Local development

To work against local checkouts of `ruso-runtime` and `ruso-script`, clone them as siblings of this repo:

```
parent/
├── ruso-cli/
├── ruso-runtime/
└── ruso-script/
```

The `paths` override in [`.cargo/config.toml`](.cargo/config.toml) picks them up automatically. When the sibling directories are absent, cargo falls back to the git dependencies above.

## License

Apache License 2.0. See [LICENSE](LICENSE).
