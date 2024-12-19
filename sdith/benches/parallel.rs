#![allow(dead_code)]
use criterion::{measurement::Measurement, Criterion};
use nist_pqc_seeded_rng::{NistPqcAes256CtrRng, Seed};
use rand::{RngCore as _, SeedableRng as _};
use rsdith::{
    constants::params::{PARAM_N, PARAM_SALT_SIZE, PARAM_SEED_SIZE, PARAM_TAU},
    signature::{input::INPUT_SIZE, Signature},
    subroutines::{mpc, prg::PRG},
};

/// Benchmarking functions that use parallel operations: commit shares, compute input shares
pub(crate) fn parallel_benchmark<M: Measurement>(c: &mut Criterion<M>) {
    let mut group = c.benchmark_group("parallel");
    let mut rng = NistPqcAes256CtrRng::from_seed(Seed::default());
    let mut seed = [0u8; PARAM_SEED_SIZE];
    rng.fill_bytes(&mut seed);
    let mut prg = PRG::init(&seed, None);

    // Benchmarking compute input shares
    let mut input_plain = [0u8; INPUT_SIZE];
    prg.sample_field_fq_elements(&mut input_plain);

    group.bench_function("mpc::compute_input_shares", |b| {
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

    group.bench_function("Signature::commit_shares", |b| {
        b.iter(|| Signature::commit_shares(&input_shares, salt))
    });
    group.finish();
}
