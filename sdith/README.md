# SDitH Protocol implementation in Rust

This is a Rust implementation of the SDitH protocol. The SDitH protocol is a quantum secure signature scheme using MPCitH (Multi-Party Computation in the Head), Syndrome Decoding and Fiat-Shamir Heuristic.

## Testing

To run the tests, execute the following command:

```bash
cargo test
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
