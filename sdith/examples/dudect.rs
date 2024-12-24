#![allow(deprecated)]
use criterion::black_box;
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use rand::Rng;
use rsdith::subroutines::arith::gf256::gf256_arith::{_mul_lookup, _mul_shift_and_add};

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
            runner.run_one(class, || mul(b, a));
        } else {
            runner.run_one(class, || mul(a, b));
        }
    }
}

// We choose two arbitrary values for the multiplication. However we try to distance them from each other
const MUL_LEFT: u8 = 1u8;
const MUL_RIGHT: u8 = 245u8;

fn gf256_mul_lookup(runner: &mut CtRunner, rng: &mut BenchRng) {
    run_mul_bench(
        runner,
        rng,
        &black_box(_mul_lookup),
        MUL_LEFT,
        MUL_RIGHT,
        false,
    );
}

fn gf256_mul_lookup_flip(runner: &mut CtRunner, rng: &mut BenchRng) {
    run_mul_bench(
        runner,
        rng,
        &black_box(_mul_lookup),
        MUL_LEFT,
        MUL_RIGHT,
        true,
    );
}

/// Compare the multiplication in the lookup implementation with two constant values
/// Left class: 0, Right class: 245
/// Otherwise the other value is random.
fn gf256_mul_lookup_zero(runner: &mut CtRunner, rng: &mut BenchRng) {
    run_mul_bench(runner, rng, &black_box(_mul_lookup), 0u8, MUL_RIGHT, false);
}

fn gf256_mul_lookup_zero_no_bb(runner: &mut CtRunner, rng: &mut BenchRng) {
    run_mul_bench(runner, rng, &_mul_lookup, 0u8, MUL_RIGHT, false);
}

fn gf256_mul_shift_and_add(runner: &mut CtRunner, rng: &mut BenchRng) {
    run_mul_bench(
        runner,
        rng,
        &black_box(_mul_shift_and_add),
        MUL_LEFT,
        MUL_RIGHT,
        false,
    );
}

fn gf256_mul_shift_and_add_flip(runner: &mut CtRunner, rng: &mut BenchRng) {
    run_mul_bench(
        runner,
        rng,
        &black_box(_mul_shift_and_add),
        MUL_LEFT,
        MUL_RIGHT,
        true,
    );
}

/// Compare the multiplication in the spec implementation with two constant values
/// Left class: 0, Right class: 245
/// Otherwise the other value is random.
fn gf256_mul_shift_and_add_zero(runner: &mut CtRunner, rng: &mut BenchRng) {
    run_mul_bench(
        runner,
        rng,
        &black_box(_mul_shift_and_add),
        0u8,
        MUL_RIGHT,
        false,
    );
}

fn gf256_mul_shift_and_add_zero_no_bb(runner: &mut CtRunner, rng: &mut BenchRng) {
    run_mul_bench(runner, rng, &_mul_shift_and_add, 0u8, MUL_RIGHT, false);
}

// Crate the main function to include the bench for vec_eq
ctbench_main!(
    gf256_mul_lookup,
    gf256_mul_lookup_zero,
    gf256_mul_lookup_flip,
    gf256_mul_lookup_zero_no_bb,
    gf256_mul_shift_and_add,
    gf256_mul_shift_and_add_zero,
    gf256_mul_shift_and_add_flip,
    gf256_mul_shift_and_add_zero_no_bb
);
