# ruso-cli

> **Development status:** This project is under active development. APIs, bytecode format, and CLI behavior may change without notice. Not recommended for production use yet.

Command-line tool for Ruso checks (`ruso` binary).

## Commands

| Command | Description |
|---------|-------------|
| `scan` | Run `.ruso` scripts against targets |
| `validate` | Validate `.ruso` syntax |
| `compile` | Compile to `<name>.bc` (hex text, no terminal output) |
| `exec` | Run `.bc` bytecode against targets |

See **[docs/CLI.md](docs/CLI.md)** for flags and examples.

## Build

```bash
cargo build --release
```

## Quick start

```bash
ruso validate --script check.ruso
ruso compile --script check.ruso
ruso exec --bytecode check.bc --target https://httpbin.org
ruso scan --script check.ruso --target https://httpbin.org -v
```

Example scripts: [ruso-script/examples](https://github.com/Hopeless-Labs/ruso-script/tree/main/examples).

## Dependencies

```toml
ruso-runtime = { git = "https://github.com/Hopeless-Labs/ruso-runtime.git", branch = "main" }
ruso-script = { git = "https://github.com/Hopeless-Labs/ruso-script.git", branch = "main" }
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
