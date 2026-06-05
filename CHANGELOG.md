# Changelog

All notable changes to the `ruso` CLI are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/), and the project
aims to follow [Semantic Versioning](https://semver.org/).

## [0.1.0-beta.4] - 2026-06-05

### Added
- **Startup banner.** Every interactive invocation now prints the "ruso"
  wordmark (figlet ANSI Shadow) in a ruso-orange vertical gradient, with the
  version, GitHub, and registry links beneath it. It goes to stderr and only
  when stderr is a terminal, so piped/CI output and the report on stdout stay
  clean.

### Changed
- **The multi-run scan summary is now a per-target table.** Each target gets a
  row of `detected / failed / skipped / clean` counts, followed by a footer with
  the scan duration and run/target totals (`scan duration 1.4s · 3 runs across 3
  targets`). Counts are coloured by bucket when non-zero (detected/failed red,
  skipped yellow, clean green) and dimmed at zero.
- **Warnings and errors print a styled `[WARNING]` / `[ERROR]` tag** (yellow /
  red on a TTY) instead of the lowercase `warning:` / `error:` prefix, matching
  the scan output. Colour follows stderr's own TTY/`NO_COLOR` state.
- **No more duplicate TLS-certificate warning.** A bare-host scan whose 443
  answered but failed cert verification printed two near-identical `--insecure`
  hints — one from the scheme probe, one after the scan. The post-scan hint now
  skips targets the scheme probe already warned about, so each target is flagged
  once. Explicitly-schemed `https://` targets (which bypass the probe) still get
  the post-scan hint.
- **Human scan output is now colour-coded.** The `[SEVERITY]` finding tag is
  coloured by level (critical = magenta, high = red, medium = yellow, low =
  cyan, info = grey), the target is bold, secondary text (script label, skip/
  error reason) is dimmed, and tags are padded to a single column so targets
  line up. Verbose `[OK]`/`[SKIP]`/`[ERROR]` rows and the multi-run summary are
  coloured too. Colour auto-disables when stdout is not a terminal or
  `NO_COLOR` is set, so piped/redirected output stays plain.

### Fixed
- **`scan` / `exec` now show a progress spinner.** Only `validate` / `compile`
  started one, so a non-verbose scan looked frozen until the summary. The scan
  loop now drives an orange `⠋ scanning <done>/<total>` spinner (suppressed in
  verbose mode, where per-run lines stream instead). The spinner is also
  TTY-gated now — piped/CI runs no longer get spinner escape codes on stderr.
- `install --force` no longer destroys a working cache entry when the
  re-download fails. It used to delete every cached `.bc` for the ref *before*
  fetching, so a registry outage or network error left you with no script at
  all. Now the download lands in a temp file and is atomically renamed over the
  existing entry only on success — a failed `--force` leaves the cache
  untouched. The write is atomic for normal installs too, so a crash mid-write
  can't leave a half-written `.bc`.

### Changed
- **`repeat` is now fully removed** from the DSL and the VM (via bumped
  ruso-script / ruso-runtime). It is no longer recognised syntax — a script
  using it gets a plain parse error rather than the beta.3 migration hint — and
  the `Repeat` bytecode opcode is gone (opcode 18 reserved). Bytecode that does
  not use `repeat` is byte-identical, so this is not a format change: no version
  bump, and every published script keeps working. Use `for` to iterate or
  `retry` to re-send.

## [0.1.0-beta.3] - 2026-06-05

### Added
- `--retries <N>` (default `2`): auto-retry an HTTP probe that fails with a
  *transient* transport error — connection reset, connect/read timeout — with a
  short backoff. A received HTTP response (any status) and a TLS-certificate
  rejection are never retried. A probe with its own `retry` directive opts out,
  so author-controlled re-sends and the automatic retry never multiply. Helps
  against CDN/edge resets under bursty scans.

### Changed
- **Failures report the real cause.** A failed run now shows the underlying
  error chain (`http error: error sending request for url (…): operation timed
  out`) instead of a bare `error sending request`.
- The bare-host certificate warning, and a one-shot `--insecure` hint when a run
  fails on certificate verification, now print at default verbosity — and the
  hint covers explicitly-schemed `https://` targets, not just bare hosts.
- The bare-host scheme probe now uses the runtime's HTTP client, so it honors
  `--proxy` and matches the executor's TLS behaviour.
- **DSL: `repeat N … end` was removed** (via the ruso-script bump). A script
  using it now fails at compile with a hint to use `for` / `retry`. Previously
  compiled bytecode still runs.

### Fixed
- A cached `<ns>/<name>/<ver>.bc` that no longer decodes with the current
  runtime is re-fetched instead of failing with `corrupt bytecode` — the install
  cache self-heals.

## [0.1.0-beta.2] - 2026-06-05

### Added
- `scan` resolves the URL scheme for a bare-host `--target` **https-first**: it
  probes `https://` and uses it on any HTTP response, falling back to `http://`
  only when 443 is unreachable at the connection level (refused/reset/timeout).
  It never downgrades to cleartext because of a certificate or HTTP-status
  error; if 443 is reachable but the certificate does not verify and
  `--insecure` was not given, it stays on https and warns you to pass it.
  Resolution runs once per target and is skipped for pure socket (TCP/UDP/DNS)
  scans.
- `--default-scheme <https|http>` — scheme to assume for a bare host when the
  probe is disabled or nothing answers (default `https`).
- `--no-scheme-probe` — skip the connectivity probe and apply `--default-scheme`
  directly (deterministic/offline runs).

### Changed
- A bare host/domain `--target` now defaults to **https** instead of an
  `http://` carrier (port 80), matching TLS-first production. This supersedes
  the bare-host note from 0.1.0-beta.1. Socket (TCP/UDP/DNS) scans are
  unaffected — they keep the `http://` carrier since the scheme never reaches
  the wire. Targets with an explicit scheme are untouched.

## [0.1.0-beta.1] - 2026-05-30

First public beta.

### Added
- `--target` accepts a bare host/IP/domain (`127.0.0.1`, `db.internal:5432`,
  `[::1]:9000`) in addition to URLs and target files — handy for non-HTTP
  (TCP/UDP/DNS) scans. A bare target gets an `http://` carrier internally so
  `{{scan_host}}` and HTTP probes still work.
- `--family <name>` scans every published script in a registry family.
- The json/csv report now carries **all** check metadata, including
  `version`, `family`, and `tags`.

### Changed
- Default registry is now the hosted instance
  `https://ruso.hopeless-labs.com` (point at a local `ruso-backend` with
  `--registry` / `RUSO_REGISTRY_URL`).
- Human scan output is one readable line per finding —
  `[SEVERITY] <target> <title>` — with the carrier scheme stripped. Verbose
  runs log uniform `[OK]` / `[SKIP]` / `[ERROR]` status lines. Full detail
  lives in the `--report` file.
- Derived publish slugs are capped at 39 chars to match the registry rule.

### Fixed
- Spinner no longer deadlocks: any failed `scan` / `validate` / `compile`
  used to hang instead of printing the error and exiting non-zero.

### Security
- `scan --family` validates namespace/name slugs before building cache paths.
  A hostile or `--registry`-pointed server can no longer return a crafted
  `namespace` (`../…`) that writes downloaded bytecode outside the cache.

[0.1.0-beta.4]: https://github.com/Hopeless-Labs/ruso-cli/releases/tag/v0.1.0-beta.4
[0.1.0-beta.3]: https://github.com/Hopeless-Labs/ruso-cli/releases/tag/v0.1.0-beta.3
[0.1.0-beta.2]: https://github.com/Hopeless-Labs/ruso-cli/releases/tag/v0.1.0-beta.2
[0.1.0-beta.1]: https://github.com/Hopeless-Labs/ruso-cli/releases/tag/v0.1.0-beta.1
