# SDitH Protocol implementation in Rust

This is a Rust implementation of the SDitH protocol. The SDitH protocol is a quantum secure signature scheme using MPCitH (Multi-Party Computation in the Head), Syndrome Decoding and Fiat-Shamir Heuristic.

## Testing

To run the tests, execute the following command:

```bash
cargo test
```

## Categories

The protocol has three proposed instances which support different security levels. These are separated into three categories:

- **Category 1**: 143-bit security level
- **Category 3**: 207-bit security level
- **Category 5**: 272-bit security level

The protocol compiles with the constants for each category according to the environment variable `CATEGORY`. The default category is "ONE".

To compile the code with a different category, set the environment variable `CATEGORY` to the desired category. For example, to compile the code with category 3, execute the following command:

```bash
CATEGORY=THREE cargo build
```

## Benchmarking

To run the benchmarks, execute the following command:

```bash
cargo bench
```

## CLI usage

```
Usage: sdith [COMMAND]

Commands:
  keygen  SDitH signature protocol key generation
  sign    SDitH signature protocol signing
  verify  SDitH signature protocol verification
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## Profiling

For profiling, use can use [samply](https://github.com/mstange/samply). To profile the code, execute the following command:

First build the code without release.

```bash
cargo build
```

Then run the profiler using the desired CLI commands: `keygen`, `sign` or `verify`. Check [CLI-usage](#cli-usage). For example

```bash
samply record target/debug/sdith sign --msg "Hello, World!" --sk path/to/sk/file
```
