#![allow(deprecated)]
use criterion::black_box;
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use rand::Rng;
use rsdith::arith::gf256::gf256_arith::{_mul_lookup, _mul_spec, _mul_wiki};

/// Benchmark multiplication in GF(256). We check if we keep `a` constant for a random `b` is there a notable difference
/// in the time it takes to do the multiplication used for different implementations of multiplication
fn run_mul_bench(
    runner: &mut CtRunner,
    rng: &mut BenchRng,
    mul: &dyn Fn(u8, u8) -> u8,
    right: u8,
    left: u8,
    flip: bool,
) {
    // Make 100,000 iterations
    for _ in 0..100_000 {
        // Flip a coin for class.
        let class = if rng.gen::<bool>() {
            Class::Left
        } else {
            Class::Right
        };
        // Contant value for the multiplication depending on the class
        let a = match class {
            Class::Left => left,
            Class::Right => right,
        };
        // Random value for the multiplication
        let b = rng.gen::<u8>();
        // runner.run_one(class, || mul(b, a));
        if flip {
            runner.run_one(class, || black_box(mul(b, a)));
        } else {
            runner.run_one(class, || black_box(mul(a, b)));
        }
    }
}

// We choose two arbitrary values for the multiplication. However we try to distance them from each other
const MUL_LEFT: u8 = 1u8;
const MUL_RIGHT: u8 = 245u8;

fn gf256_mul_lookup(runner: &mut CtRunner, rng: &mut BenchRng) {
    run_mul_bench(runner, rng, &_mul_lookup, MUL_LEFT, MUL_RIGHT, false);
}

/// Compare the multiplication in the lookup implementation with two constant values
/// Left class: 0, Right class: 245
/// Otherwise the other value is random.
fn gf256_mul_lookup_zero(runner: &mut CtRunner, rng: &mut BenchRng) {
    run_mul_bench(runner, rng, &_mul_lookup, 0u8, MUL_RIGHT, false);
}

fn gf256_mul_spec(runner: &mut CtRunner, rng: &mut BenchRng) {
    run_mul_bench(runner, rng, &_mul_spec, MUL_LEFT, MUL_RIGHT, false);
}

/// Compare the multiplication in the spec implementation with two constant values
/// Left class: 0, Right class: 245
/// Otherwise the other value is random.
fn gf256_mul_spec_zero(runner: &mut CtRunner, rng: &mut BenchRng) {
    run_mul_bench(runner, rng, &_mul_spec, 0u8, MUL_RIGHT, false);
}

fn gf256_mul_wiki(runner: &mut CtRunner, rng: &mut BenchRng) {
    run_mul_bench(runner, rng, &_mul_wiki, MUL_LEFT, MUL_RIGHT, false);
}

fn gf256_mul_wiki_flip_ab(runner: &mut CtRunner, rng: &mut BenchRng) {
    run_mul_bench(runner, rng, &_mul_wiki, MUL_LEFT, MUL_RIGHT, true);
}

// Crate the main function to include the bench for vec_eq
ctbench_main!(
    gf256_mul_lookup,
    gf256_mul_lookup_zero,
    gf256_mul_spec,
    gf256_mul_spec_zero,
    gf256_mul_wiki,
    gf256_mul_wiki_flip_ab
);
