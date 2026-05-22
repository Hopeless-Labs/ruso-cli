# CLI (`ruso`)

Binary name: **`ruso`**. Four commands only:

| Command | Purpose |
|---------|---------|
| `scan` | Parse, compile, and run `.ruso` against targets |
| `validate` | Check `.ruso` syntax (no network) |
| `compile` | Write binary bytecode to `<script>.bc` (silent on success) |
| `exec` | Run `.bc` bytecode against targets |

## Build

```bash
cargo build --release
./target/release/ruso --help
```

## Global flags

| Flag | Effect |
|------|--------|
| `-q` / `--quiet` | Less logging |
| `-v` / `--verbose` | More logging; live `detected` / `no` lines during scan/exec |
| `RUST_LOG` | Overrides default filter |

## `validate`

```bash
ruso validate --script check.ruso
ruso validate --script ./checks/
```

- File must be `.ruso`; directory collects `*.ruso` recursively.
- Exit `0` if all valid; errors on stderr only.
- No stdout on success.

## `compile`

```bash
ruso compile --script check.ruso
ruso compile --script ./checks/
```

- Writes **raw RUSO v2 bytes** (not hex) to `check.bc` beside `check.ruso`.
- No stdout on success.
- Format on disk: magic `RUSO` + pools + instructions (see ruso-runtime `docs/BYTECODE.md`).

## `exec`

```bash
ruso exec --bytecode check.bc --target https://example.com
ruso exec --bytecode ./built/ --target targets.txt -v
```

| Flag | Description |
|------|-------------|
| `--bytecode` | `.bc` file or directory of `.bc` files |
| `--target` | URL or file (one URL per line) |
| `--timeout` | Default `30s` |
| `--no-follow-redirects` | HTTP |
| `--insecure` | Skip TLS verify (HTTP + TCP `tls`) |
| `--proxy` | HTTP proxy |
| `--output` | `human`, `json`, `csv` |
| `--report` | Required for json/csv |

## `scan`

```bash
ruso scan --script check.ruso --target https://example.com
ruso scan --script ./checks/ --target targets.txt --output json --report out.json
```

Same target/timeout/TLS/report flags as `exec`, but runs `.ruso` source directly (no `.bc` file).

## Workflow

```bash
ruso validate --script mycheck.ruso
ruso compile --script mycheck.ruso          # → mycheck.bc
ruso exec --bytecode mycheck.bc --target https://lab.local -v

# Or one step from source:
ruso scan --script mycheck.ruso --target https://lab.local -v
```

## Exit codes

Non-zero on validation/compile failure, missing paths, runtime errors, or report I/O. A successful run with no finding is exit `0` (`no` in verbose human output).
