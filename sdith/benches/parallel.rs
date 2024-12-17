#![allow(dead_code)]
use criterion::{black_box, measurement::Measurement, Criterion};
use nist_pqc_seeded_rng::{NistPqcAes256CtrRng, Seed};
use rand::{RngCore as _, SeedableRng as _};
use rsdith::{
    arith::gf256::gf256_matrices::HPrimeMatrix,
    constants::{
        params::{
            PARAM_M_SUB_K, PARAM_N, PARAM_SALT_SIZE, PARAM_SEED_SIZE, PARAM_TAU,
        },
        types::hash_default,
    },
    mpc::{
        self, beaver::BeaverTriples, broadcast::Broadcast, challenge::Challenge, compute_broadcast,
    },
    signature::{
        input::{Input, INPUT_SIZE},
        Signature,
    },
    subroutines::{marshalling::Marshalling as _, prg::PRG},
    witness::{generate_witness, sample_polynomial_relation, Solution},
};

fn prepare_party_computation(
    mseed: rsdith::constants::types::Seed,
    hseed: rsdith::constants::types::Seed,
) -> (
    Input,
    Broadcast,
    Challenge,
    HPrimeMatrix,
    [u8; PARAM_M_SUB_K],
) {
    let mut prg = PRG::init(&mseed, Some(&[0; PARAM_SALT_SIZE]));

    let (q, s, p, _) = sample_polynomial_relation(&mut prg);
    let witness = generate_witness(hseed, (q, s, p));

    let beaver = BeaverTriples::generate(&mut prg);
    let chal = Challenge::new(hash_default());

    let solution = Solution {
        s_a: witness.s_a,
        q_poly: q,
        p_poly: p,
    };

    let input = Input { solution, beaver };

    let broadcast = compute_broadcast(input.clone(), &chal, witness.h_prime, witness.y);
    if broadcast.is_err() {
        panic!("Failed to compute broadcast");
    } else {
        let broadcast = broadcast.unwrap();
        (input, broadcast, chal, witness.h_prime, witness.y)
    }
}

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

    let (input, broadcast, chal, h_prime, y) = prepare_party_computation(seed, seed);

    group.bench_function("party_computation", |b| {
        b.iter(|| {
            black_box(mpc::party_computation(
                input.serialise(),
                &chal,
                h_prime,
                y,
                &broadcast,
                true,
            ))
        })
    });

    group.finish();
}
