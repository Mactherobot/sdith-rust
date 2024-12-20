#![allow(dead_code)]
use criterion::{measurement::Measurement, Criterion};
use nist_pqc_seeded_rng::{NistPqcAes256CtrRng, Seed};
use rand::{RngCore, SeedableRng as _};
use rsdith::{
    constants::params::{PARAM_DIGEST_SIZE, PARAM_SEED_SIZE},
    keygen::keygen,
    signature::Signature,
    utils::marshalling::Marshalling as _,
};

/// Benchmarking api functions, i.e. keygen, signing and verification
pub(crate) fn api_benchmark<M: Measurement>(c: &mut Criterion<M>) {
    let mut rng = NistPqcAes256CtrRng::from_seed(Seed::default());
    let mut group = c.benchmark_group("api");
    if cfg!(feature = "flat_sampling") {
        group.sampling_mode(criterion::SamplingMode::Flat);
    }

    // First create master seed
    let mut keygen_seed = [0u8; PARAM_SEED_SIZE];
    rng.fill_bytes(&mut keygen_seed);

    // Benchmark keygen
    group.bench_function("keygen", |b| b.iter(|| keygen(keygen_seed)));

    // Benchmark signing
    let (pk, sk) = keygen(keygen_seed);

    let mut sign_seed = [0u8; PARAM_SEED_SIZE];
    let mut sign_salt = [0u8; PARAM_DIGEST_SIZE];
    rng.fill_bytes(&mut sign_seed);
    rng.fill_bytes(&mut sign_salt);
    let entropy = (sign_seed, sign_salt);

    let message: Vec<u8> = vec![1, 2, 3, 4];
    group.bench_function("signing", |b| {
        b.iter(|| Signature::sign_message(entropy, &sk, &message))
    });

    // Benchmark verification
    let signature: Vec<u8> = Signature::sign_message(entropy, &sk, &message)
        .unwrap()
        .serialise();
    group.bench_function("verification", |b| {
        b.iter(|| Signature::verify_signature(&pk, &signature))
    });

}