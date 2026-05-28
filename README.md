# ruso-cli

[![Rust CI](https://github.com/Hopeless-Labs/ruso-cli/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/Hopeless-Labs/ruso-cli/actions/workflows/rust.yml)

> **Development status:** This project is under active development. APIs, bytecode format, and CLI behavior may change without notice. Not recommended for production use yet.

Command-line tool for Ruso checks (`ruso` binary). Runs `.ruso` scripts locally, *and* talks to a [`ruso-backend`](https://github.com/Hopeless-Labs/ruso-backend) registry instance for publishing, installing, and searching shared checks.

## Commands

### Local

| Command | Description |
|---------|-------------|
| `scan` | Run `.ruso` scripts against targets (compile + run in one step). `--script <path\|ref>` or `--family <name>` to run a whole category |
| `validate` | Validate `.ruso` syntax (no network) |
| `compile` | Compile to `<name>.bc` (hex text, no terminal output) |
| `exec` | Run `.bc` bytecode against targets |

### Registry (talks to `ruso-backend`)

| Command | Description |
|---------|-------------|
| `login` | Save a PAT or session token for the active registry |
| `logout` | Delete the stored credential |
| `whoami` | Show the user the stored credential belongs to |
| `publish` | Upload a `.ruso` script to the registry |
| `install` | Download `<namespace>/<name>[@<range>]` into the local cache |
| `search` | Search published scripts (free-text + tag/severity/cve/namespace/family filters) |
| `info` | Show registry metadata for a script (versions, install snippet, tags) |
| `yank` / `unyank` | Pull / restore a published version (owner-only, idempotent) |
| `edit` | Update description / visibility of a script you own |
| `pat list/create/revoke` | Manage PATs from the terminal — full lifecycle without the web UI |

Plus: `ruso scan --script <namespace>/<name>[@<range>]` resolves a registry reference through the local cache, fetching from the registry on miss. Same for `ruso exec --bytecode <namespace>/<name>[@<range>]`. Filesystem paths always win over ref pattern matching, so a local file/directory named like a slug still works.

See **[docs/CLI.md](docs/CLI.md)** for flags and examples.

## Build

```bash
cargo build --release
```

## Quick start (local)

```bash
ruso validate --script check.ruso
ruso compile --script check.ruso
ruso exec --bytecode check.bc --target https://httpbin.org
ruso scan --script check.ruso --target https://httpbin.org -v
```

Example scripts: [ruso-script/examples](https://github.com/Hopeless-Labs/ruso-script/tree/main/examples).

## Quick start (with a registry)

```bash
# 1. Log in (PAT or session token from the backend's web flow).
#    Reads token from stdin if --token is omitted.
echo "ruso_pat_…" | ruso login

# 2. Publish a script. Namespace defaults to your username.
ruso publish ./mycheck.ruso --visibility public

# 3. Find shared scripts.
ruso search "log4j" --tag rce

# 4. Install + scan a registry-hosted check (cached at
#    ~/.ruso/scripts/<ns>/<name>/<version>.bc).
ruso install someuser/log4shell@^0.2
ruso scan --script someuser/log4shell --target https://target.example.com -v
```

### Pointing at a different registry

Registry URL precedence: `--registry <url>` > `$RUSO_REGISTRY_URL` > built-in default (`http://127.0.0.1:8080`, a placeholder until a hosted instance lands).

Credentials are stored per registry URL in `$XDG_CONFIG_HOME/ruso/credentials.json` (mode 0600 on Unix), so the same machine can be logged into a local backend *and* a hosted one at the same time.

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
