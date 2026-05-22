# CLI (`ruso`)

Binary name: **`ruso`**. Four commands only:

| Command | Purpose |
|---------|---------|
| `scan` | Parse, compile, and run `.ruso` against targets |
| `validate` | Check `.ruso` syntax (no network) |
| `compile` | Write hex-encoded bytecode to `<script>.bc` (silent on success) |
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

- Writes **lowercase hex** of the RUSO v1 bytecode to `check.bc` beside `check.ruso` (ASCII text, not raw binary).
- No stdout on success.
- `exec` decodes hex from `.bc` before running (legacy raw-binary `.bc` with `RUSO` header still works).

## `exec`

```bash
ruso exec --bytecode check.bc --target https://example.com
ruso exec --bytecode ./built/ --target targets.txt -v
```

| Flag | Description |
|------|-------------|
| `--bytecode` | `.bc` file or directory of `.bc` files (hex from `compile`) |
| `--target` | URL or file (one URL per line) |
| `--timeout` | Default `30s` |
| `--no-follow-redirects` | HTTP |
| `--verify-tls` | Verify TLS certs (default: off, scanner mode). HTTP `verify_ssl` in script overrides per probe |
| `--proxy` | HTTP proxy |
| `--output` | `human`, `json`, `csv` |
| `--report` | Required for json/csv |

### Port checks (`ruso-runtime`)

Before each script run, **ruso-runtime** TCP-probes required ports and caches `host:port` → open/closed for **30 seconds** (one `ruso` process, shared cache).

Endpoints:

- Socket probes: `host` + `port` from `tcp` / `udp` / wire-mode `dns`
- HTTP checks: `host` + port from `--target` (e.g. `https://example.com` → `example.com:443`)

**`skipped`** means *this script run* did not execute because a required port was closed (often from cache after an earlier script hit the same port). The scan **continues** with other scripts that use different ports. Example: three scripts on port 443 — first run finds 443 closed and caches it; the other two are `skipped` for that target; a script on port 22 still runs.

## `scan`

```bash
ruso scan --script check.ruso --target https://example.com
ruso scan --script ./checks/ --target targets.txt --output json --report out.json
```

Same target/timeout/TLS/report/port-cache flags as `exec`, but runs `.ruso` source directly (no `.bc` file). Each script is parsed and compiled once, then bytecode is reused for every target.

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
