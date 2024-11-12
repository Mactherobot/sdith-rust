# Notes from development

- Using Keccak and the same instantiated RBG as used in the reference implementation
- Using salt in Merkle tree construction
- Missing final in spec (we removed our spec-tests)

# Things we want to know

- What is the security of the protocol (Benjamin)
  - Why is it quantum secure?
  - How does NIST evaluate the security of the protocol?
  - What are the security assumptions?
  - What are the security proofs?
  - Parameters for each category, I, III and V.
  - https://blog.cloudflare.com/nist-post-quantum-surprise/
- What is SD? (Magnus)
  - Galois field 256 (AES)
- MPCitH
- Shamir's secret sharing
- Homomorphism (by addition)
- Beavers triples for multiplication
- Fiat-Shamir heuristic
  - Hashing
  - Commitment schemes (Merkle trees)
- ZK proofs
- NIST methodology
  - Standards
  - Competitions
  - CLI API
  - Criteria for this competition
- Rust optimisation
  - SIMD
  - https://doc.rust-lang.org/std/simd/index.html
  - https://nrempel.com/using-simd-for-parallel-processing-in-rust/
  - Is this something we can look into?
  - u8x4 for Points.
  - u8x32 for Ceil vector const
  - Parallelism
  - Memory management (Heap vs Stack)
  - Nightly vs stable performance.
- Benchmarking and profiling
- What have we done so far?
- Criterion (cycles and time),
- Profiling (samply)
- Heaptrack (memory)

# Things we want to code

- NIST tests and API \*
- SIMD optimisations for Points and other vectors. \*
- Final version (how to structure a rust package/cli) Maybe do after handing in \*
- Remove const feature flag to test stable rust.
- Test performance of stable vs nightly.
- TODOs...
- More parallelism?
- Batching for merkle tree
- MPC do vector additions of the evaluations with SIMD
- Better documentation
- Clean up and more tests
- https://github.com/kste/haraka Hashing?
