# SDitH Protocol implementation in Rust

This is a Rust implementation of the SDitH protocol. The SDitH protocol is a quantum secure signature scheme using MPCitH (Multi-Party Computation in the Head), Syndrome Decoding and Fiat-Shamir Heuristic.

## Feature flags

### Categories

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

### Optimisations

The package provides several optimisations that can be enabled through feature flags.

- `parallel`: A common bottleneck in the protocsimdol is when you have to compute input shares or commitments as they rely on hashing
- `simd`: The protocol uses SIMD instructions to speed up matrix multiplication and vector operations
- `jemalloc` and `mimalloc`: Change the allocator used by the Rust runtime

The most performant configuration can be set with the `optimized` feature flag.

```bash
cargo build --features simd,parallel,jemalloc
cargo build --features optimized
```

### Blake3

You can use the `xof_blake3` or `hash_blake3` feature flag to use the Blake3 hash `blake3` crate for hashing and XOF respectively. By default, the implementation uses the SHA3 and Shake implementations from the `tiny-keccak` crate as specified in the protocol.

Note that Blake3 increases performance, but only supports category 1 due to the bit security level of 128.

```bash
cargo build --features xof_blake3,hash_blake3
````

## Testing

To run the tests, execute the following command:

```bash
cargo test
```

For Category 5, you might have to increase the stack size. To do so, execute the following command:

```bash
RUST_MIN_STACK=8388608 cargo test --features category_five
```

### KAT tests

The folder `src/kat` contains tests that compare inputs and outputs of the implementation to the SDitH c++ implementation. To run these tests, include the feature flag `kat`:

```bash
cargo test --features kat
```

## CLI usage

The sdith cli is the main binary built and it is located in the `src/bin/cli` folder.

You can run it by either building the binary or using the `cargo run` command.

```bash
# Build the binary
cargo build --release

# Run the binary
./target/release/sdith

# Or use cargo run
cargo run
```

The cli has the following api

```
SDitH signature protocol
NIST Category ONE variant

Usage: sdith [COMMAND]

Commands:
  keygen      SDitH signature protocol -- key generation
  sign        SDitH signature protocol -- signing
  verify      SDitH signature protocol -- verification
  parameters  SDitH signature protocol -- print parameters
  help        Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```


## Benchmarking

To run the benchmarks, execute the following command:

```bash
cargo bench
```

### Profiling

For profiling, use can use [samply](https://github.com/mstange/samply). To profile the code, execute the following command:

First build the selected 

- src/bin/profiling_sign
- src/bin/profiling_keygen -- not implemented
- src/bin/profiling_verify -- not implemented

```bash
cargo build --bin profiling_sign
```

Then run the profiler using the desired CLI commands: `keygen`, `sign` or `verify`. Check [CLI-usage](#cli-usage). For example

```bash
samply record target/debug/profiling_sign [iterations]
```

### Constant time benchmarks

We run the [dudect_bencher](https://docs.rs/dudect-bencher/latest/dudect_bencher/) to benchmark the constant time implementations of the protocol.

To run the benchmarks, execute the following command:

```bash
cargo run --release --example dudect
```
