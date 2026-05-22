# CLI (`ruso`)

Binary name: **`ruso`** (package `ruso-cli`).

## Build

From a clone of the **ruso-cli** repository:

```bash
cargo build --release
./target/release/ruso --help
```

## Global flags

| Flag | Effect |
|------|--------|
| `-q` / `--quiet` | Less logging (repeat for quieter) |
| `-v` / `--verbose` | More logging (`-vv` trace) |
| `RUST_LOG` | Overrides default filter (e.g. `RUST_LOG=ruso_runtime=debug`) |

## Commands

### `parse`

Validate syntax; no network.

```bash
ruso parse --script path/to/check.ruso
ruso parse --script ./checks/ --format json
```

| Flag | Description |
|------|-------------|
| `--script` | `.ruso` file or directory (recursive) |
| `--format` | `human` (default) or `json` |

Exit success when all files parse.

### `compile`

Emit bytecode without executing.

```bash
ruso compile --script check.ruso --write check.bc
ruso compile --script check.ruso --format hex        # stdout (default)
ruso compile --script check.ruso --format disasm     # human-readable
```

`--write` stores raw RUSO v2 bytes. Use with `exec --bytecode @check.bc`.

### `exec`

Run precompiled bytecode.

```bash
ruso exec --bytecode @check.bc --target https://example.com
ruso exec --bytecode deadbeef... --target https://example.com
```

`@file` reads raw bytes from disk.

### `scan`

Parse, compile, and execute in one step (primary workflow).

```bash
ruso scan \
  --script examples/http_health.ruso \
  --target https://example.com \
  --timeout 30s \
  --output human

ruso scan \
  --script ./checks/ \
  --target targets.txt \
  --output json \
  --report findings.json \
  --insecure
```

| Flag | Description |
|------|-------------|
| `--script` | `.ruso` file or directory |
| `--target` | URL or file (one URL per line) |
| `--timeout` | Default duration (`30s`) |
| `--no-follow-redirects` | HTTP only |
| `--insecure` | Disable TLS verify (HTTP + TCP `tls`) |
| `--proxy` | HTTP proxy URL |
| `--output` | `human`, `json`, `csv` |
| `--report` | Output path (required for json/csv) |

### HTTP vs socket targets

- **HTTP checks** — `--target https://host` sets `ExecutorConfig.base_url`. Probe `path` is relative to that base.  
- **TCP/UDP/DNS socket checks** — host/port usually come from the script (`tcp { host "…" port … }`). `--target` may still be required by CLI but is not substituted into socket `host` automatically yet.

## Output formats

**Human** — findings and status to stdout.

**JSON / CSV** — structured report; requires `--report path`.

## Batch scanning

- **Scripts** — directory recursively collects `*.ruso`.  
- **Targets** — file with one URL per line runs cartesian product with each script (see CLI implementation in `src/cli/mod.rs`).

## Development workflow

```bash
# 1. Syntax
ruso parse --script mycheck.ruso -v

# 2. Run against lab target
ruso scan --script mycheck.ruso --target https://lab.local -vv

# 3. Freeze bytecode for CI
ruso compile --script mycheck.ruso --write mycheck.bc
ruso exec --bytecode @mycheck.bc --target https://lab.local
```

## Exit codes

Non-zero on parse/compile failure, runtime `fail`, or I/O errors. Successful run with no finding is still exit 0 unless the CLI maps detection differently—check `cmd_scan` for project-specific policy.
