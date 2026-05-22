# ruso-cli

Command-line tool for Ruso checks (`ruso` binary).

## Documentation

- **[CLI reference](docs/CLI.md)** — commands, flags, output formats
- **[docs/README.md](docs/README.md)** — ecosystem map and links to runtime/script docs

Example `.ruso` scripts: [ruso-script/examples](https://github.com/Hopeless-Labs/ruso-script/tree/main/examples) and [docs/EXAMPLES.md](https://github.com/Hopeless-Labs/ruso-script/blob/main/docs/EXAMPLES.md).

## Dependencies

```toml
ruso-runtime = { git = "https://github.com/Hopeless-Labs/ruso-runtime.git", branch = "main" }
ruso-script = { git = "https://github.com/Hopeless-Labs/ruso-script.git", branch = "main" }
```

## Build

```bash
cargo build --release
./target/release/ruso --help
```

## Quick commands

```bash
ruso parse --script check.ruso
ruso scan --script check.ruso --target https://example.com
ruso compile --script check.ruso --write check.bc
ruso exec --bytecode @check.bc --target https://example.com
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
