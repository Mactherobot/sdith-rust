
#![allow(dead_code)]
use criterion::{black_box, measurement::Measurement, Criterion};
use nist_pqc_seeded_rng::{NistPqcAes256CtrRng, Seed};
use rand::{RngCore as _, SeedableRng as _};
use rsdith::{arith::gf256::{gf256_matrices::{field_mul_matrix_vector, HPrimeMatrix}, gf256_vector::{gf256_add_vector, gf256_mul_scalar_add_vector}}, constants::params::{PARAM_K, PARAM_M_SUB_K, PARAM_SEED_SIZE}, subroutines::prg::PRG};

/// Benchmarking functions that use SIMD operations: Matrix multiplication, Vector operations
pub(crate) fn simd_benchmark<M: Measurement>(c: &mut Criterion<M>) {
  let mut rng = NistPqcAes256CtrRng::from_seed(Seed::default());
  let mut seed = [0u8; PARAM_SEED_SIZE];
  rng.fill_bytes(&mut seed);
  let mut prg = PRG::init(&seed, None);
  let mut group = c.benchmark_group("simd");

  // Benchmarking matrix multiplication

  let mut matrix: HPrimeMatrix = [0u8; PARAM_M_SUB_K * PARAM_K];
  prg.sample_field_fq_elements(&mut matrix);
  let mut vector: [u8; PARAM_K] = [0u8; PARAM_K];
  prg.sample_field_fq_elements(&mut vector);

  let mut out: [u8; PARAM_M_SUB_K] = [0u8; PARAM_M_SUB_K];

  group.bench_function("field_mul_matrix_vector", |b| {
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
  let mut vx = [1u8; PARAM_M_SUB_K];
  rng.fill_bytes(&mut vx);
  let mut vz = [0u8; PARAM_M_SUB_K];
  rng.fill_bytes(&mut vz);
  group.bench_function("gf256_add_vector", |b| {
      b.iter(|| gf256_add_vector(black_box(&mut vz), black_box(&vx)))
  });

  // Benchmarking vector addition times scalar
  let vx = [1u8; PARAM_M_SUB_K];
  let mut vz = [0u8; PARAM_M_SUB_K];
  let scalar = 2u8;
  group.bench_function("gf256_mul_scalar_add_vector", |b| {
      b.iter(|| gf256_mul_scalar_add_vector(&mut vz, &vx, scalar))
  });

  group.finish();
}