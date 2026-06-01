# Changelog

All notable changes to the `ruso` CLI are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/), and the project
aims to follow [Semantic Versioning](https://semver.org/).

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

[0.1.0-beta.1]: https://github.com/Hopeless-Labs/ruso-cli/releases/tag/v0.1.0-beta.1
