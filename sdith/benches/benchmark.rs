#![feature(portable_simd)]
use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Duration;

#[cfg(all(target_os = "linux", feature = "cycles_per_byte"))]
use criterion_cycles_per_byte::CyclesPerByte;

mod api;
mod gf256;
mod merkle;
mod parallel;
mod simd;
mod size;

use api::api_benchmark;
use merkle::merkle_benchmark;
use parallel::parallel_benchmark;
use simd::simd_benchmark;
use gf256::mul_benchmark;

fn get_config() -> Criterion {
    Criterion::default()
        .significance_level(0.1)
        .sample_size(500)
        .without_plots()
        .measurement_time(Duration::from_secs(30))
}

#[cfg(all(target_os = "linux", feature = "cycles_per_byte"))]
criterion_group! {
    name = benches;
    config = get_config().with_measurement(CyclesPerByte);
    targets = api_benchmark, simd_benchmark, parallel_benchmark, merkle_benchmark, mul_benchmark
}

#[cfg(not(feature = "cycles_per_byte"))]
criterion_group!(
    name = benches;
    config = get_config();
    targets = api_benchmark, simd_benchmark, parallel_benchmark, merkle_benchmark, mul_benchmark
);

criterion_group!(
    name = proof_size;
    config = Criterion::default().with_filter("size");
    targets = size::proof_size_benchmark
);

criterion_main!(benches, proof_size);
