# Notes from development

- Using Keccak and the same instantiated RBG as used in the reference implementation
- Using salt in Merkle tree construction
- Missing final in spec (we removed our spec-tests)

# Spec issues

# Things we want to know

- What is the security of the protocol (Benjamin)
  - Why is it quantum secure?
  - How does NIST evaluate the security of the protocol?
  - What are the security assumptions?
  - What are the security proofs?
  - Parameters for each category, I, III and V.
  - https://blog.cloudflare.com/nist-post-quantum-surprise/
- What is SD? (Magnus)
  - Galois field 256 (AES) https://encyclopediaofmath.org/index.php?title=Galois_field
  - S, Q, P, F reduction to SD problem
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
  - Lookup tables, can we place these in the stack?
- Benchmarking and profiling
- What have we done so far?
- Criterion (cycles and time),
- Profiling (samply)
- Heaptrack (memory)
- Parallelism: test with different number of threads, 2, 4, 8, 16
- ulimit -s unlimited

# Things we want to code

- [] NIST tests and API \*
  - [] Tests: currently we cannot compare to their results (probably due to hashing)
  - [] API: we need to implement the API for the NIST tests
- [x] SIMD optimisations for Points and other vectors. \*
  - [x] MPC do vector additions of the evaluations with SIMD
  - [x] Matrix multiplication
- [] Hash functions: Haraka v2, Xoodyak (NIST finalist), K12 (less rounds)
  - [] Haraka v2 512 is specifically for merkle tree construction
  - [x] Blake3
  - [] Xoodyak
  - [] K12
- [] Final version (how to structure a rust package/cli) Maybe do after handing in \*
- [x] Remove const feature flag to test stable rust.
- [] Test performance of stable vs nightly.
- [] TODOs...
- [] More parallelism?
- [] Batching for merkle tree
- [] Better documentation
- [] Clean up and more tests
- [] Benchmarking and profiling
  - [x] Benching api functions (keygen, sign, verify)
  - [] More granular benchmarking
    - [x] SIMD
    - [x] Parallelism

# Message to the SDitH people

Dear SDith Team,

We are currently writing our masters thesis on implementing the SDith protocol in Rust. Currently we have a working implementation of the protocol.

While implementing we found some bugs/interesting things, and struggled with some understanding along the way!

For bugs/interesting things we found the following:

1. In the ´´´expand_view_challenge_hash´´´ function when initializing the Shake XOF (views.c:10-11) there's a missing finalise for the xof. This proved itself to be problematic when attempting to compare outputs between our implementations. The problem mostly stems from the fact that the Rust library we used (https://github.com/debris/tiny-keccak) does not supply a fine grained API, meaning we could not get into the same state. Based on your implementation of the expand mpc challenge, (mpc.c:207) it seemed like it is missing. We added a finalize to your implementation for comparisons, which worked. We have created a [PR]() for this.

2. When implementing our matrix multiplication, we ran into a curious issue. Accidentally removing the matrix multiplication did not make the signing and verification fail. We are still unsure about why this is the case, but we suspect that you essentially just run into the "random" SD intance where H' is I. Essentially, this is still a valid SD instance, but of course now we have that y = H'x_a + x_b = x_a + x_b. We expect that this comes to a case of an insecure key generation. For our implementation we added a check for this case. However, we are interested in hearing your thoughts on this.

As for the specification paper we ran into the following issues (mostly understanding):

- The section for compute party and inverse party computation, specifically the computing the plain broadcast shares we found that we spent quite some time trying to reason about the structure of the MPC algorithms.
- For the section on performance, we could not find any information on how the RAM usage was found. As we are trying to compare our implementation with your c++ implementation, we would like to know how you found the RAM usage.
- Nitpicking (sorry)
  - Algorithm 4, line 22: Should be "Serialize(c)" or exchange other references to `c` ?
  - Algorithm 13, line 10: Should be "InversePartyComputation" instead of "PartyComputationFromBroadcast"?

Finally, we wanted to ask if you have any optimisations that are not mentioned in round 1? We have looked a little into replacing the merkle tree with a verkle tree. But are a bit unsure if it's cost in creation of the tree outweighs the gain. If so, we would love to hear about them and potentially implement them.

Greetings Benjamin and Magnus

### Notes from meeting

-
