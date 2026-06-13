# ruso-cli — guidance for Claude

The `ruso` binary: scan orchestration, registry client, and reporting. Part of
the Ruso ecosystem — the **Ruso Scripting Language (RSL)** compiles `.rsl`
source to `.rbc` bytecode, which this CLI runs.

Documentation lives in **The Ruso Book** (<https://docs.ruso.hopeless-labs.com>),
not in this repo — the local `docs/` was removed; the book is the single source.

## Quality gate (keep green before any commit)

```bash
cargo fmt --all -- --check
cargo clippy --all-targets
cargo test
```

## Dev setup

Clone `ruso-runtime` and `ruso-script` as siblings; the `paths` override in
`.cargo/config.toml` picks them up automatically. When absent, Cargo falls back
to the `git` dependencies pinned on `main`.

## Conventions

- **Don't bump the version on every change** — accumulate notes under the
  current `0.1.0-beta.x` heading in `CHANGELOG.md`.
- **Preview output / UX changes and get approval before committing them.**
- Match the surrounding code's style and comment density.
- Reporting: a single `--report <file.json|file.csv>` picks both path and format
  (json/csv only); there is no `--output` flag. The human console always prints;
  `--report` additionally writes the file. The report is **grouped by target**.
- **Don't name private repos in user-facing text** — call the registry the
  "Ruso registry", not `ruso-backend`.
