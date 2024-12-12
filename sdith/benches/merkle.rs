
#![allow(dead_code)]
use criterion::measurement::Measurement;
use criterion::Criterion;
use nist_pqc_seeded_rng::RngCore;
use sdith::constants::params::{PARAM_DIGEST_SIZE, PARAM_N, PARAM_SALT_SIZE};
use sdith::constants::types::Hash;
use sdith::subroutines::merkle_tree::{MerkleTree, MerkleTreeTrait as _};


pub(crate) fn merkle_benchmark<M: Measurement>(c: &mut Criterion<M>) {
  let mut group = c.benchmark_group("merkle");
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

  group.bench_function("MerkleTree::new", |b| {
      b.iter(|| MerkleTree::new(commitments, Some(salt)));
  });
  group.finish();
}