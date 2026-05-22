# Ruso CLI documentation

Documentation for the **ruso-cli** crate and the **`ruso`** binary.

## Contents

- **[CLI reference](CLI.md)** — commands, flags, output formats, batch scanning.

## Install / build

From a clone of [ruso-cli](https://github.com/Hopeless-Labs/ruso-cli):

```bash
cargo build --release
./target/release/ruso --help
```

Dependencies are pulled from GitHub (`main`):

- [ruso-runtime](https://github.com/Hopeless-Labs/ruso-runtime)
- [ruso-script](https://github.com/Hopeless-Labs/ruso-script)

## Typical workflow

```bash
ruso parse --script check.ruso
ruso scan --script check.ruso --target https://example.com
ruso compile --script check.ruso --write check.bc
ruso exec --bytecode @check.bc --target https://example.com
```

Example `.ruso` files live in the **ruso-script** repository under `examples/`. Clone that repo or pass a path to scripts on disk.

## Full documentation map

| Topic | Repository |
|-------|------------|
| DSL syntax | [ruso-script/docs/DSL_REFERENCE.md](https://github.com/Hopeless-Labs/ruso-script/blob/main/docs/DSL_REFERENCE.md) |
| Example scripts | [ruso-script/docs/EXAMPLES.md](https://github.com/Hopeless-Labs/ruso-script/blob/main/docs/EXAMPLES.md) |
| Architecture | [ruso-runtime/docs/ARCHITECTURE.md](https://github.com/Hopeless-Labs/ruso-runtime/blob/main/docs/ARCHITECTURE.md) |
| Bytecode v2 | [ruso-runtime/docs/BYTECODE.md](https://github.com/Hopeless-Labs/ruso-runtime/blob/main/docs/BYTECODE.md) |
