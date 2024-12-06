# SDitH Protocol implementation in Rust

This is a Rust implementation of the SDitH protocol. The SDitH protocol is a quantum secure signature scheme using MPCitH (Multi-Party Computation in the Head), Syndrome Decoding and Fiat-Shamir Heuristic.

## Testing

To run the tests, execute the following command:

```bash
cargo test
```

For Category 5, you might have to increase the stack size. To do so, execute the following command:

```bash
RUST_MIN_STACK=8388608 cargo test --features category_five
```

### Specification tests

The folder `src/spec_tests` contains tests that compare inputs and outputs of the implementation to the SDitH c++ implementation. To run these tests, include the feature flag `spec_tests`:

```bash
cargo test --features spec_tests
```

Note that these tests are only available for category 1.

## Categories

The protocol has three proposed instances which support different security levels. These are separated into three categories:

- **Category 1**: 143-bit security level
- **Category 3**: 207-bit security level
- **Category 5**: 272-bit security level

Rust compiles the protocol with the constants needed for each category. The default category is "ONE".

You can set the category by the feature flag `category_#`.

```bash
# Set the category through the feature flag
cargo build --features category_three
```

## Feature flags

### Parallel

You can use the `parallel` feature flag to enable parallelism in the protocol. By default, the implementation uses a single thread.

```bash
cargo build --features parallel
```

### Blake3

You can use the `xof_blake3` or `hash_blake3` feature flag to use the Blake3 hash `blake3` crate for hashing and XOF respectively. By default, the implementation uses the SHA3 and Shake implementations from the `tiny-keccak` crate as specified in the protocol.

Note that Blake3 increases performance, but only supports category 1 due to the bit security level of 128.

```bash
cargo build --features xof_blake3,hash_blake3
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
