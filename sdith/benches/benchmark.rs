#![feature(portable_simd)]
use criterion::{criterion_group, criterion_main, Criterion};
#[cfg(all(target_os = "linux", feature = "cycles_per_byte"))]
use criterion_cycles_per_byte::CyclesPerByte;
use nist_pqc_seeded_rng::{NistPqcAes256CtrRng, RngCore, Seed, SeedableRng};
use sdith::arith::gf256::gf256_matrices::{field_mul_matrix_vector, HPrimeMatrix};
use sdith::arith::gf256::gf256_vector::{gf256_add_vector, gf256_mul_scalar_add_vector};
use sdith::constants::params::{
    PARAM_DIGEST_SIZE, PARAM_K, PARAM_M_SUB_K, PARAM_N, PARAM_SALT_SIZE, PARAM_SEED_SIZE, PARAM_TAU,
};
use sdith::constants::types::Hash;
use sdith::keygen::keygen;
use sdith::mpc;
use sdith::signature::input::INPUT_SIZE;
use sdith::signature::Signature;
use sdith::subroutines::marshalling::Marshalling as _;
use sdith::subroutines::merkle_tree::{MerkleTree, MerkleTreeTrait as _};
use sdith::subroutines::prg::PRG;

/// Benchmarking api functions, i.e. keygen, signing and verification
fn api_benchmark(c: &mut Criterion) {
    let mut rng = NistPqcAes256CtrRng::from_seed(Seed::default());
    // First create master seed
    let mut keygen_seed = [0u8; PARAM_SEED_SIZE];
    rng.fill_bytes(&mut keygen_seed);

    // Benchmark keygen
    c.bench_function("api: `keygen`", |b| b.iter(|| keygen(keygen_seed)));

    // Benchmark signing
    let (pk, sk) = keygen(keygen_seed);

    let mut sign_seed = [0u8; PARAM_SEED_SIZE];
    let mut sign_salt = [0u8; PARAM_DIGEST_SIZE];
    rng.fill_bytes(&mut sign_seed);
    rng.fill_bytes(&mut sign_salt);
    let entropy = (sign_seed, sign_salt);

    let message: Vec<u8> = vec![1, 2, 3, 4];
    c.bench_function("api: `Signature::sign_message`", |b| {
        b.iter(|| Signature::sign_message(entropy, &sk, &message))
    });

    // Benchmark verification
    let signature: Vec<u8> = Signature::sign_message(entropy, &sk, &message)
        .unwrap()
        .serialise();
    c.bench_function("api: `Signature::verify_signature`", |b| {
        b.iter(|| Signature::verify_signature(&pk, &signature))
    });
}

/// Benchmarking functions that use SIMD operations: Matrix multiplication, Vector operations
fn simd_benchmark(c: &mut Criterion) {
    let mut rng = NistPqcAes256CtrRng::from_seed(Seed::default());
    let mut seed = [0u8; PARAM_SEED_SIZE];
    rng.fill_bytes(&mut seed);
    let mut prg = PRG::init(&seed, None);

    // Benchmarking matrix multiplication

    let mut matrix: HPrimeMatrix = [0u8; PARAM_M_SUB_K * PARAM_K];
    prg.sample_field_fq_elements(&mut matrix);
    let mut vector: [u8; PARAM_K] = [0u8; PARAM_K];
    prg.sample_field_fq_elements(&mut vector);

    let mut out: [u8; PARAM_M_SUB_K] = [0u8; PARAM_M_SUB_K];

    c.bench_function("simd: `field_mul_matrix_vector`", |b| {
        b.iter(|| {
            field_mul_matrix_vector::<PARAM_M_SUB_K, PARAM_K>(
                &mut out,
                &matrix,
                PARAM_M_SUB_K,
                PARAM_K,
                &vector,
            )
        })
    });

    // Benchmarking vector addition
    let vx = [1u8; PARAM_M_SUB_K];
    let mut vz = [0u8; PARAM_M_SUB_K];
    c.bench_function("simd: `gf256_add_vector`", |b| {
        b.iter(|| gf256_add_vector(&mut vz, &vx))
    });

    // Benchmarking vector addition times scalar
    let vx = [1u8; PARAM_M_SUB_K];
    let mut vz = [0u8; PARAM_M_SUB_K];
    let scalar = 2u8;
    c.bench_function("simd: `gf256_mul_scalar_add_vector`", |b| {
        b.iter(|| gf256_mul_scalar_add_vector(&mut vz, &vx, scalar))
    });
}

/// Benchmarking functions that use parallel operations: commit shares, compute input shares
fn parallel_benchmark(c: &mut Criterion) {
    let mut rng = NistPqcAes256CtrRng::from_seed(Seed::default());
    let mut seed = [0u8; PARAM_SEED_SIZE];
    rng.fill_bytes(&mut seed);
    let mut prg = PRG::init(&seed, None);

    // Benchmarking compute input shares
    let mut input_plain = [0u8; INPUT_SIZE];
    prg.sample_field_fq_elements(&mut input_plain);

    c.bench_function("parallel: `mpc::compute_input_shares`", |b| {
        b.iter(|| mpc::compute_input_shares(&input_plain, &mut prg))
    });

    // Benchmarking commit shares
    let mut input_shares = Box::new([[[0u8; INPUT_SIZE]; PARAM_N]; PARAM_TAU]);
    for i in 0..PARAM_TAU {
        for j in 0..PARAM_N {
            prg.sample_field_fq_elements(&mut input_shares[i][j]);
        }
    }
    let mut salt = [0u8; PARAM_SALT_SIZE];
    prg.sample_field_fq_elements(&mut salt);

    c.bench_function("parallel: `Signature::commit_shares`", |b| {
        b.iter(|| Signature::commit_shares(&input_shares, salt))
    });
}

fn merkle_benchmark(c: &mut Criterion) {
    // Benchmark the Merkle tree create.
    let mut rng = rand::thread_rng();
    let commitments: [Hash; 256] = (0..PARAM_N)
        .map(|_| {
            let mut input_share = [0u8; PARAM_DIGEST_SIZE];
            rng.fill_bytes(&mut input_share);
            input_share
        })
        .collect::<Vec<_>>()
        .as_slice()
        .try_into()
        .unwrap();

    let mut salt = [0u8; PARAM_SALT_SIZE];
    rng.fill_bytes(&mut salt);

    c.bench_function("MerkleTree::new", |b| {
        b.iter(|| MerkleTree::new(commitments, Some(salt)));
    });
}

#[cfg(all(target_os = "linux", feature = "cycles_per_byte"))]
criterion_group! {
    name = benches;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = api_benchmark, simd_benchmark
}

#[cfg(not(all(target_os = "linux", feature = "cycles_per_byte")))]
criterion_group!(
    benches,
    api_benchmark,
    simd_benchmark,
    parallel_benchmark,
    merkle_benchmark
);

criterion_main!(benches);
