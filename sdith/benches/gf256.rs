#![allow(dead_code)]
use criterion::{measurement::Measurement, Criterion};
use rand::Rng as _;
use rsdith::subroutines::arith::gf256;

/// Benchmarking functions that use parallel operations: commit shares, compute input shares
pub(crate) fn mul_benchmark<M: Measurement>(c: &mut Criterion<M>) {
    let mut group = c.benchmark_group("gf256");
    let mut rng = rand::thread_rng();

    group.bench_function("mul_lookup", |b| {
        b.iter_batched(
            || (rng.gen::<u8>(), rng.gen::<u8>()),
            #[allow(deprecated)]
            |(a, b)| gf256::gf256_arith::_mul_lookup(a, b),
            criterion::BatchSize::SmallInput,
        )
    });

    group.bench_function("mul_shift_and_add", |b| {
        b.iter_batched(
            || (rng.gen::<u8>(), rng.gen::<u8>()),
            |(a, b)| gf256::gf256_arith::_mul_shift_and_add(a, b),
            criterion::BatchSize::SmallInput,
        )
    });
    group.finish();
}
