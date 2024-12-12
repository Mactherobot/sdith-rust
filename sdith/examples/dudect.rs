#![allow(deprecated)]
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use rand::Rng;
use sdith::arith::gf256::gf256_arith::{_mul_lookup, _mul_spec, _mul_wiki};

/// Benchmark multiplication in GF(256). We check if we keep `a` constant for a random `b` is there a notable difference
/// in the time it takes to do the multiplication
/// used for different implementations of multiplication
fn run_mul_bench(
    runner: &mut CtRunner,
    rng: &mut BenchRng,
    mul: &dyn Fn(u8, u8) -> u8,
    right: u8,
    left: u8,
) {
    let mut inputs: Vec<u8> = Vec::new();
    let mut classes = Vec::new();

    // Make 100,000 random pairs
    for _ in 0..100_000 {
        // Flip a coin. To choose class. Left is 10 * b and right is 245 * b
        inputs.push(rng.gen::<u8>());
        classes.push(if rng.gen::<bool>() {
            Class::Left
        } else {
            Class::Right
        });
    }

    for (class, v) in classes.into_iter().zip(inputs.into_iter()) {
        // Now time how long it takes to do a vector comparison
        let a = match class {
            Class::Left => left,
            Class::Right => right,
        };
        runner.run_one(class, || mul(v, a));
    }
}

// We choose two arbitrary values for the multiplication. However we try to distance them from each other
const MUL_LEFT: u8 = 10u8;
const MUL_RIGHT: u8 = 245u8;

fn gf256_mul_lookup(runner: &mut CtRunner, rng: &mut BenchRng) {
    run_mul_bench(runner, rng, &_mul_lookup, MUL_LEFT, MUL_RIGHT);
}

fn gf256_mul_lookup_zero(runner: &mut CtRunner, rng: &mut BenchRng) {
    run_mul_bench(runner, rng, &_mul_lookup, 0u8, MUL_RIGHT);
}

fn gf256_mul_spec(runner: &mut CtRunner, rng: &mut BenchRng) {
    run_mul_bench(runner, rng, &_mul_spec, MUL_LEFT, MUL_RIGHT);
}

fn gf256_mul_spec_zero(runner: &mut CtRunner, rng: &mut BenchRng) {
    run_mul_bench(runner, rng, &_mul_spec, 0u8, MUL_RIGHT);
}

fn gf256_mul_wiki(runner: &mut CtRunner, rng: &mut BenchRng) {
    run_mul_bench(runner, rng, &_mul_wiki, MUL_LEFT, MUL_RIGHT);
}

// Crate the main function to include the bench for vec_eq
ctbench_main!(
    gf256_mul_lookup,
    gf256_mul_lookup_zero,
    gf256_mul_spec,
    gf256_mul_spec_zero,
    gf256_mul_wiki
);
