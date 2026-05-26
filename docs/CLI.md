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

- Writes **lowercase hex** of the RUSO v2 bytecode to `check.bc` beside `check.ruso` (ASCII text, not raw binary).
- No stdout on success.
- `exec` decodes hex from `.bc` before running (legacy raw-binary `.bc` with `RUSO` header still works).
- v1 `.bc` files emitted by previous releases must be recompiled — the
  `CmpValue::Number` payload widened from `u32` to `u64`, and decoding a
  v1 file now returns `BadVersion(1)`.

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
| `--read-timeout` | Per-read I/O timeout for socket probes (default `10s`) |
| `--max-response-bytes` | HTTP body cap (default 10 MiB) |
| `--no-follow-redirects` | HTTP |
| `--insecure` | Disable TLS certificate verification. Defaults to **off** (TLS *is* verified); opt-in only for environments where you accept MITM and finding-injection risk. Emits a runtime warning when active. HTTP `verify_ssl` in the script still overrides per probe |
| `--proxy` | HTTP proxy |
| `--script-timeout` | Per-script wall-clock budget (default `5m`) |
| `--concurrency` | Parallel (target × script) runs (default `16`) |
| `--output` | `human`, `json`, `csv` |
| `--report` | Required for json/csv |

> **Migration note:** the previous `--verify-tls` flag (a positive opt-in
> for verification, disabled by default) is gone. Verification is now the
> default; pass `--insecure` to restore the old behaviour.

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

## Report output (`--output json` / `csv` / `human`)

Findings include check metadata from the script `metadata { … }` block. Besides `name`, `description`, `impact`, `severity`, `author`, and `evidence`, positive rows may include:

| Field | Source in `.ruso` |
|-------|-------------------|
| `cve` | `cve ["…", "…"]` list (JSON array; CSV/human joined with ` \| `) |
| `cwe` | `cwe ["…"]` list |
| `references` | `references ["…", "…"]` list (URLs, advisories, etc.) |
| `cvss` | Repeatable `cvss "…"` lines (CVSS vector, e.g. `CVSS:3.1/…`) |
| `cvss_score` | Repeatable `cvss_score 9.8` lines (numeric literal, stored as string in reports) |
| `mitigation` | Repeatable `mitigation "…"` lines (remediation guidance) |

Empty lists are omitted from JSON (`skip_serializing_if`).

### `skip_reason` vs `error`

JSON and CSV reports carry **two** separate channels for non-finding
outcomes:

- `skip_reason` is set when a run did not execute because a required
  port was closed (`port 80 closed`, etc.). `skipped` is `true` in the
  same row.
- `error` is set only for genuine failures (parse failure, IO error,
  runtime `fail` opcode, SSRF guard, budget exceeded).

Earlier revisions wrote the skip reason into `error`, which made
"intentional skip" indistinguishable from "the run blew up" in
downstream tooling. The CSV header now includes `skipped` and
`skip_reason` columns.

## Scan target and socket checks

- **HTTP** checks use `--target` as the request base URL.
- **TCP/UDP/DNS wire** checks use `host` in the `.ruso` script. Prefer `host "{{scan_host}}"` so the host comes from `--target`.
- `ruso validate` / `ruso compile` fail if the script has `match` or `evidence` but no `name` or `report` metadata.

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
