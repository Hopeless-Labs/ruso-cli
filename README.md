# ruso-cli

Command-line tool for Ruso checks.

## Documentation

- [CLI reference](../docs/CLI.md)
- [Examples](../docs/EXAMPLES.md)

## Dependencies

`ruso-cli` pulls libraries from GitHub (`main`):

- [ruso-runtime](https://github.com/Hopeless-Labs/ruso-runtime.git)
- [ruso-script](https://github.com/Hopeless-Labs/ruso-script.git)

```toml
ruso-runtime = { git = "https://github.com/Hopeless-Labs/ruso-runtime.git", branch = "main" }
ruso-script = { git = "https://github.com/Hopeless-Labs/ruso-script.git", branch = "main" }
```

A `[patch]` in `Cargo.toml` may override `ruso-script`'s transitive `ruso-runtime` until both repos use matching git deps on `main`.

## Install / build

```bash
cargo build --release
```

Binary: `ruso`.

## Quick commands

```bash
ruso parse --script check.ruso
ruso scan --script check.ruso --target https://example.com
ruso compile --script check.ruso --write check.bc
ruso exec --bytecode @check.bc --target https://example.com
```

## License

MIT OR Apache-2.0
