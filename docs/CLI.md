# CLI (`ruso`)

Binary name: **`ruso`**. Fifteen commands across two groups:

**Local** (no network):

| Command | Purpose |
|---------|---------|
| `scan` | Parse, compile, and run `.ruso` against targets |
| `validate` | Check `.ruso` syntax |
| `compile` | Write hex-encoded bytecode to `<script>.bc` (silent on success) |
| `exec` | Run `.bc` bytecode against targets |

**Registry** (talks to [`ruso-backend`](https://github.com/Hopeless-Labs/ruso-backend)):

| Command | Purpose |
|---------|---------|
| `login` | Save a PAT or session token for the active registry |
| `logout` | Delete the stored credential |
| `whoami` | Show the user the stored credential belongs to |
| `publish` | Upload a `.ruso` script (under your own namespace) |
| `install` | Download `<ns>/<name>[@<range>]` into the local cache |
| `search` | Search published scripts |
| `info` | Show registry metadata for a script (versions, install, tags, family) |
| `yank` / `unyank` | Pull / restore a published version (owner, idempotent) |
| `edit` | Update description / visibility of a script you own |
| `pat list/create/revoke` | Manage personal access tokens |

Plus: `scan` accepts `--script <ns>/<name>[@<range>]` (single registry ref) **or** `--family <name>` (every installed/published script in a curated family); `exec` accepts the same ref form in `--bytecode`. Refs resolve through the local cache, auto-installing on miss.

## Build

```bash
cargo build --release
./target/release/ruso --help
```

## Global flags

| Flag | Effect |
|------|--------|
| `-q` / `--quiet` | Less logging |
| `-v` / `--verbose` | More logging; live per-run status lines (`[SEVERITY] …`, `[OK]`, `[SKIP]`, `[ERROR]`) during scan/exec |
| `RUST_LOG` | Overrides default filter |

## Registry URL resolution

Every command that talks to a backend resolves the registry base URL in
this order:

1. `--registry <URL>` flag on the command
2. `RUSO_REGISTRY_URL` environment variable
3. Built-in default `https://ruso.hopeless-labs.com` (the hosted registry;
   use `http://127.0.0.1:8080` to point at a local `ruso-backend`)

Credentials are stored per registry base URL in
`$XDG_CONFIG_HOME/ruso/credentials.json` (Linux/macOS) or
`%APPDATA%\ruso\credentials.json` (Windows), mode `0600` on Unix. The
same machine can be logged into multiple registries at once.

## Registry refs

A *registry ref* is a string of the form `<namespace>/<name>[@<range>]`:

- `<namespace>` and `<name>` follow the slug rule
  `^[a-z0-9][a-z0-9-]{0,38}$`.
- `<range>` is an optional [SemVer
  range](https://docs.rs/semver/1/semver/struct.VersionReq.html) like
  `^1.2`, `>=0.3,<0.5`, or `=1.0.0`.

Refs are accepted wherever the CLI takes a script/bytecode path:

- `ruso install <ref>…`
- `ruso scan --script <ref>` / `ruso exec --bytecode <ref>`

Resolution rule for `scan` / `exec`:

1. If the argument exists on the filesystem → treat as a path.
   (Local files always win, so a directory named `myorg/check` still
   works.)
2. Else if it parses as a registry ref → resolve through the install
   cache (`$RUSO_HOME` or `$HOME/.ruso/scripts/<ns>/<name>/<version>.bc`),
   downloading from the registry on cache miss.
3. Else → error.

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
- While the runtime is `0.1.0-dev` the v1 wire format may change between
  commits without a version bump — recompile your `.bc` files after each
  upgrade.

## `exec`

```bash
ruso exec --bytecode check.bc --target https://example.com
ruso exec --bytecode ./built/ --target targets.txt -v
# Registry ref — auto-fetches if not cached.
ruso exec --bytecode myorg/log4shell@^0.2 --target https://lab.local
```

| Flag | Description |
|------|-------------|
| `--bytecode` | `.bc` file, directory of `.bc` files, or registry ref `<ns>/<name>[@<range>]` |
| `--target` | URL (`http(s)://…`), bare host/IP/domain (`127.0.0.1`, `db.internal:5432`, `[::1]:9000`), or a file with one target per line |
| `--registry <URL>` | Override the registry base URL (only consulted for ref inputs) |
| `--timeout` | Default `30s` |
| `--read-timeout` | Per-read I/O timeout for socket probes (default `10s`) |
| `--max-response-bytes` | HTTP body cap (default 10 MiB) |
| `--no-follow-redirects` | HTTP |
| `--insecure` | Disable TLS certificate verification. Defaults to **off** (TLS *is* verified); opt-in only for environments where you accept MITM and finding-injection risk. Emits a runtime warning when active. If a scan run fails because a target's certificate did not verify, a one-shot hint suggests `--insecure` (covers bare hosts and explicit `https://` alike). HTTP `verify_ssl` in the script still overrides per probe |
| `--proxy` | HTTP proxy |
| `--retries` | Auto-retry an HTTP probe that fails with a **transient transport error** — connection reset, connect/read timeout — up to N times (default `2`; `0` disables). A received HTTP response (any status) and a TLS-certificate rejection are never retried. A probe with its own `retry` directive opts out — the script's count wins. Helpful against CDN/edge resets under bursty scans. |
| `--script-timeout` | Per-script wall-clock budget (default `5m`) |
| `--concurrency` | Parallel (target × script) runs (default `16`) |
| `--max-per-host` | Cap concurrent in-flight scans against a single host (default `0` = disabled; only `--concurrency` applies). Prevents a high `-c` from piling many connections onto one sensitive target while still allowing wide parallelism across distinct hosts. |
| `--rps` | Cap on how often a new script run may start, scripts per second (default `0` = disabled). Coarse safety cap at the orchestrator: a running script can still send many probes. |
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
# Registry ref — auto-fetches if not cached.
ruso scan --script myorg/log4shell@^0.2 --target https://lab.local -v
```

Same target/timeout/TLS/report/port-cache flags as `exec`, but runs `.ruso` source directly (no `.bc` file). Each local script is parsed and compiled once, then bytecode is reused for every target. Registry-ref inputs skip the compile step — they are served as already-compiled bytecode from the cache and go through the same decode-and-run path as `exec`.

`--script` also accepts a `--registry <URL>` override for ref resolution.

Scan-only flags (in addition to the shared ones above):

| Flag | Description |
|------|-------------|
| `--family <name>` | Scan every published script in a registry family (mutually exclusive with `--script`) |
| `--default-scheme <https\|http>` | Scheme for a bare-host `--target` when the probe is disabled or nothing answers (default `https`). See [Scan target and socket checks](#scan-target-and-socket-checks). |
| `--no-scheme-probe` | Skip the https-first connectivity probe; apply `--default-scheme` directly (deterministic/offline runs) |

### Scan a whole family

```bash
ruso scan --family web --target https://lab.local -v
```

`--family <name>` is mutually exclusive with `--script` (exactly one is required). It queries the registry for every published script in that curated family (`web`, `network`, `database`, …), installs each into the local cache, and runs them all against the target(s). One script failing to install is warned and skipped, not fatal. A family with no scripts errors out rather than silently doing nothing.

## `login`

```bash
ruso login --token ruso_pat_xxxxxxxxxxxx
# Or read from stdin:
echo "ruso_pat_xxxxxxxxxxxx" | ruso login
# Interactive prompt if stdin is a tty:
ruso login
```

Verifies the token against the registry's `/v1/me` endpoint before
saving — better to fail loudly here than silently store a bad token.

| Flag | Effect |
|------|--------|
| `--token <TOKEN>` | PAT (`ruso_pat_…`) or session token (`ruso_sess_…`). |
| `--registry <URL>` | Override the registry base URL. |

## `logout`

```bash
ruso logout
ruso logout --registry https://other.example.com
```

Removes the stored credential for the active registry. Idempotent.

## `whoami`

```bash
ruso whoami
```

Prints the user the stored credential resolves to, plus the registry
URL the credential is bound to. Exits non-zero if no credential is
stored.

## `publish`

```bash
ruso publish ./mycheck.ruso
ruso publish ./mycheck.ruso --visibility private
```

| Flag | Effect |
|------|--------|
| `--visibility <public\|private>` | First-publish-only. Subsequent publishes inherit the existing visibility (change via `PATCH` — not yet exposed in the CLI). |
| `--registry <URL>` | Override the registry base URL. |

A script is always published under **your own username** as the
namespace — the registry has no organizations, so there's no flag to
target a different one. (The backend rejects a mismatched namespace
with 404.)

The script's `name "…"` metadata is slugified to form the URL path
component. `version "X.Y.Z"`, optional `tags [...]`, and optional
`family "…"` metadata are extracted from the `.ruso` source by the
backend at publish time — all immutable per version.

Success output:

```
published myuser/log4shell@0.2.0 (4321 bytes, public)
tags:     log4j, rce, jndi
```

## `install`

```bash
ruso install someuser/log4shell
ruso install someuser/log4shell@^0.2
ruso install --all-versions someuser/log4shell
ruso install --force someuser/log4shell                 # re-download
ruso install a/x b/y c/z@~1.4                            # multiple refs
```

Resolves the best non-yanked version matching the range (newest wins;
no range = newest overall) and writes it to
`$RUSO_HOME/scripts/<ns>/<name>/<version>.bc` (default
`~/.ruso/scripts/...`). Subsequent runs reuse the cache. A cached entry is
reused only if it still decodes with the current runtime; one that no longer
does (e.g. compiled by an older toolchain) is re-fetched automatically, so
`--force` is needed only to refresh an entry that is still valid.

| Flag | Effect |
|------|--------|
| `--force` | Re-download even if a matching version is already cached. The cached entry is replaced only once the new download succeeds — a failed `--force` (registry down, network error) leaves the existing cache intact. |
| `--all-versions` | Install every non-yanked version of the ref (honouring `@<range>` if given). Newest-first so Ctrl-C mid-install leaves the most-useful versions on disk. |
| `--registry <URL>` | Override the registry base URL. |

## `search`

```bash
ruso search "log4j"
ruso search --tag rce --tag auth          # AND on tags
ruso search --severity critical --cve CVE-2021-44228
ruso search --namespace someuser
ruso search "log4j" --json --per-page 50  # machine-readable
```

| Flag | Effect |
|------|--------|
| Positional `<QUERY>` | Free-text query (matches name + description + tags via tsvector). |
| `--tag <T>` | Filter by tag. Repeat for AND. |
| `--severity <S>` | Exact match on the latest version's severity. |
| `--cve <ID>` | Exact match on a CVE in the cached list. |
| `--namespace <NS>` | Filter by owner username. |
| `--page <N>` / `--per-page <N>` | Defaults `1` / `20`; `per-page` clamped to `[1, 100]`. |
| `--json` | Emit a JSON array of hits to stdout (table view by default). |
| `--registry <URL>` | Override the registry base URL. |

Anonymous searches see only public scripts; authenticated searches
also include private scripts owned by the caller. Scripts whose only
versions are yanked are excluded from results.

## `info`

```bash
ruso info someuser/log4shell
ruso info someuser/log4shell@^1            # filter versions by range
ruso info someuser/log4shell --json        # machine-readable
```

Read-only — works anonymously for public scripts, requires login for
private scripts you own.

| Flag | Effect |
|------|--------|
| Positional `<REF>` | `<ns>/<name>` or `<ns>/<name>@<semver-range>`. |
| `--json` | Emit the raw `ScriptResponse` shape to stdout. |
| `--registry <URL>` | Override the registry base URL. |

Human output shows: namespace/name, visibility, description, tags, the
latest non-yanked version + its download count, copy-paste install
commands, and the full version list with per-version size + download
count + yank flag.

## `yank` / `unyank`

```bash
ruso yank someuser/check@1.4.2 --reason "false-positive rate too high"
ruso unyank someuser/check@1.4.2
```

Owner-only. Idempotent — yanking an already-yanked version (or
unyanking an already-active one) is a no-op success.

| Flag | Effect |
|------|--------|
| Positional `<REF@VERSION>` | Exact SemVer, not a range. |
| `--reason <TEXT>` (yank only) | Surfaced in version metadata as `yank_reason`; helps installers understand why a previously-shipping version disappeared. |
| `--registry <URL>` | Override the registry base URL. |

Yank only requires the `yank` scope on PATs. Sessions carry full scope.
Yanked versions still serve their bytecode if explicitly requested by
version — the registry just stops recommending them in search +
`install` without `@<range>` matching.

## `edit`

```bash
ruso edit someuser/check --description "Now detects CVE-2024-XYZ too"
ruso edit someuser/check --visibility private
ruso edit someuser/check --description "" --visibility public   # combo
```

Owner-only. Updates fields on the script (not on a version — version
data is immutable once published).

| Flag | Effect |
|------|--------|
| Positional `<REF>` | `<ns>/<name>` — no version part. |
| `--description <TEXT>` | New description. Pass `""` to clear. |
| `--visibility <public\|private>` | Toggle visibility. |
| `--registry <URL>` | Override the registry base URL. |

Refuses to call with neither flag set (would be a no-op round-trip).

## `pat`

Personal access tokens lifecycle from the terminal — the full set of
operations the web UI's Tokens page exposes.

```bash
ruso pat list                                       # table view
ruso pat list --active-only --json                  # filter + JSON
ruso pat create laptop                              # default scope: read
ruso pat create ci --scope read --scope publish
ruso pat create release --scope yank \
                       --expires-at 2026-12-31T00:00:00Z
ruso pat revoke <PAT_UUID>
```

All three subcommands need a stored credential (`ruso login` first).
Backend re-checks ownership — you can only see / mutate your own
PATs.

### `pat list`

| Flag | Effect |
|------|--------|
| `--active-only` | Hide revoked tokens. By default they're shown with a `revoked` status marker so you can audit what's been cleaned up. |
| `--json` | Machine-readable output (array of token records). |
| `--registry <URL>` | Override the registry base URL. |

Sorted newest-first by `created_at`. The plaintext token is never
shown — only `pat create` returns that, and only once.

### `pat create`

> **Requires a session token, not a PAT.** Backend deliberately
> rejects PAT-authed `create` calls — a leaked PAT shouldn't be able
> to mint sibling PATs. Sign in via the web UI's Tokens page, grab
> the `ruso_sess_…` cookie, and `ruso login` with that to use this
> command. `pat list` and `pat revoke` work with either token type.

| Flag | Effect |
|------|--------|
| Positional `<NAME>` | Human label so you remember what the token is for. Stored verbatim. |
| `--scope <SCOPE>` | Repeatable. Allowed: `read`, `publish`, `yank`. Defaults to `read` if not specified. Pick the minimum needed for the job. |
| `--expires-at <RFC3339>` | Optional. Omit for a never-expiring token (still revocable via `pat revoke`). |
| `--registry <URL>` | Override the registry base URL. |

Output:

```
created PAT `laptop` (id 0a35…, scopes: read)

Store this token now — it won't be shown again:
  ruso_pat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### `pat revoke`

| Flag | Effect |
|------|--------|
| Positional `<ID>` | PAT UUID, copy from `pat list`. |
| `--registry <URL>` | Override the registry base URL. |

Idempotent — already-revoked tokens still return success.

## Report output (`--output json` / `csv` / `human`)

**Human output is a one line per finding:** `[SEVERITY] <target> <title>`
(e.g. `[CRITICAL] 127.0.0.1 Redis exposed without authentication`). The
`[SEVERITY]` tag is colour-coded by level (critical = magenta, high = red,
medium = yellow, low = cyan, info = grey), the target is bold, and tags are
padded to one column so targets line up. Findings **stream as they are found**
during the scan (a progress spinner sits below them on a TTY), not in a single
dump at the end. The full metadata is intentionally kept out of the console —
use `--output json` / `csv` with `--report <path>` for the complete record. In
`-v` mode each run instead logs a status line as it completes: `[OK]` (green),
`[SKIP] … (reason)` (yellow), or `[ERROR] … (msg)` (red).

Scanning is **pipelined**: a bare-host `--target`'s scheme (http/https) is
resolved lazily, once per target, as part of scanning — so a large target file
starts producing results immediately instead of waiting for every target to be
probed up front.

For a multi-run scan the human output ends with a **per-target summary table**
and a duration footer:

```text
┌─────────────┬──────────┬────────┬─────────┬───────┐
│ target      │ detected │ failed │ skipped │ clean │
├─────────────┼──────────┼────────┼─────────┼───────┤
│ protergo.id │        0 │     48 │       0 │     0 │
└─────────────┴──────────┴────────┴─────────┴───────┘
scan duration 1.4s · 48 runs across 1 target
```

Each count is coloured by bucket when non-zero (detected/failed red, skipped
yellow, clean green) and dimmed at zero.

Colour is applied only when stdout is a terminal; piped or redirected output
(and any run with the `NO_COLOR` environment variable set) stays plain, so
escape codes never pollute logs or `grep`.

Every interactive invocation also prints a **startup banner** (the "ruso"
wordmark plus version / GitHub / registry links) to stderr — shown only when
stderr is a terminal, so piped/CI output and the report on stdout are
unaffected. `NO_COLOR` drops its colour like everywhere else.

The **json/csv report carries every metadata field** from the script
`metadata { … }` block. Besides `name`, `description`, `impact`, `severity`,
`author`, and `evidence`:

| Field | Source in `.ruso` |
|-------|-------------------|
| `cve` | `cve ["…", "…"]` list (JSON array; CSV joined with ` \| `) |
| `cwe` | `cwe ["…"]` list |
| `references` | `references ["…", "…"]` list (URLs, advisories, etc.) |
| `cvss` | Repeatable `cvss "…"` lines (CVSS vector, e.g. `CVSS:3.1/…`) |
| `cvss_score` | Repeatable `cvss_score 9.8` lines (numeric literal, stored as string in reports) |
| `mitigation` | Single `mitigation "…"` line (remediation guidance; declaring it twice is a compile error) |
| `version` | `version "X.Y.Z"` (script SemVer) |
| `family` | `family "web"` (curated category) |
| `tags` | `tags ["…", "…"]` free-form labels |

Empty lists / absent fields are omitted from JSON (`skip_serializing_if`).

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

- `--target` accepts a full URL or a bare host/IP/domain. A target that already
  carries a scheme is used as-is.
- **Bare-host scheme resolution (`scan`).** For a bare host, `scan` resolves the
  scheme **https-first**: it probes `https://` and uses it on any HTTP response;
  it falls back to `http://` only when 443 is unreachable at the connection level
  (refused/reset/timeout) — it never downgrades to cleartext because of a
  certificate or HTTP-status error. If 443 is reachable but the certificate does
  not verify and `--insecure` was not given, it stays on https and warns you to
  pass `--insecure`. Control it with `--default-scheme <https|http>` (the fallback
  when probing is off or nothing answers; default `https`) and `--no-scheme-probe`
  (skip the probe, apply `--default-scheme` directly). A **non-HTTP** scan
  (TCP/UDP/DNS only — Redis, NTP, …) skips the probe and keeps an `http://`
  carrier, since the scheme never reaches the wire (`--target 127.0.0.1`).
- **HTTP** checks use `--target` as the request base URL.
- **TCP/UDP/DNS wire** checks use `host` in the `.ruso` script. Prefer `host "{{scan_host}}"` so the host comes from `--target`.
- **Failure reasons are reported in full.** A failed run shows the underlying
  cause, not just a generic line — e.g. `http error: error sending request for
  url (…): client error (Connect): invalid peer certificate: UnknownIssuer`
  rather than a bare `error sending request`.
- `ruso validate` / `ruso compile` fail if the script has `match` or `evidence` but no `name` or `report` metadata.

## Workflow

```bash
# Local development loop.
ruso validate --script mycheck.ruso
ruso compile --script mycheck.ruso          # → mycheck.bc
ruso exec --bytecode mycheck.bc --target https://lab.local -v

# Or one step from source:
ruso scan --script mycheck.ruso --target https://lab.local -v

# Publish a finished check and run someone else's:
echo "$RUSO_PAT" | ruso login --registry https://registry.example.com
ruso publish ./mycheck.ruso --visibility public
ruso install someone/another-check@^1
ruso scan --script someone/another-check --target https://lab.local -v
```

## Exit codes

Non-zero on validation/compile failure, missing paths, runtime errors, or report I/O. A successful run with no finding is exit `0` (`[OK]` line in verbose human output).
