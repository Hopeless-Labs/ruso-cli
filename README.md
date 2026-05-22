# ruso-cli

Command-line tool for Ruso checks.

## Documentation

- [CLI reference](../docs/CLI.md)
- [Examples](../docs/EXAMPLES.md)

## Install / build

```bash
cargo build --release -p ruso-cli
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
