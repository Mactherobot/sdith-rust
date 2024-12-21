//! # Commitment
//!
//! Commitment primitive for shares in the MPCitH protocol.
//! Allows for verifying the MPC protocol _in the head_ execution.

#[cfg(feature = "parallel")]
use rayon::iter::{IndexedParallelIterator as _, ParallelIterator as _};

use super::{
    merkle_tree::{MerkleTree, MerkleTreeTrait as _},
    mpc::input::INPUT_SIZE,
    prg::hashing::{SDitHHash, SDitHHashTrait as _},
};
use crate::{
    constants::{
        params::{PARAM_DIGEST_SIZE, PARAM_N, PARAM_TAU},
        types::{Hash, Salt},
    },
    utils::iterator::get_iterator_mut,
};

/// The prefix for the commitment hash function.
const COMMITMENT_HASH_PREFIX: [u8; 1] = [0];

/// Commit to a share, using a salt, execution index and party index, through hashing.
///
/// `commit_share(salt, e, i, share) = Hash(0 || salt || e_0 || e_1 || i_0 || i_1 || share)`
///
/// # Arguments
/// - `salt`: 2λ-bit salt
/// - `e`: Execution index [`crate::constants::params::PARAM_TAU`] of the share
/// - `i`: Party index [`crate::constants::params::PARAM_N`] of the share
/// - `share`: Share data to commit to
///
/// where `e` and `i` are split into little-endian bytes.
pub fn commit_share(salt: &Salt, e: u16, i: u16, share: &[u8]) -> Hash {
    // get e_0, e_1 such that e = e_0 + 256 * e_1
    let [e_0, e_1] = e.to_le_bytes();
    // get i_0, i_1 such that i = i_0 + 256 * i_1
    let [i_0, i_1] = i.to_le_bytes();

    let mut hasher = SDitHHash::init_with_prefix(&COMMITMENT_HASH_PREFIX);

    hasher.update(salt);
    hasher.update(&[e_0, e_1, i_0, i_1]);
    hasher.update(share);

    SDitHHash::finalize(hasher)
}

#[inline(always)]
/// Commit shares to the MPC protocol
pub fn commit_shares(
    input_shares: &[[[u8; INPUT_SIZE]; PARAM_N]; PARAM_TAU],
    salt: Salt,
) -> ([[u8; PARAM_DIGEST_SIZE]; PARAM_TAU], Vec<MerkleTree>) {
    let mut commitments: [Hash; PARAM_TAU] = [[0u8; PARAM_DIGEST_SIZE]; PARAM_TAU];
    let mut merkle_trees: Vec<MerkleTree> = Vec::with_capacity(PARAM_TAU);
    let mut commitments_prime = [[0u8; PARAM_DIGEST_SIZE]; PARAM_N];
    for e in 0..PARAM_TAU {
        get_iterator_mut(&mut commitments_prime)
            .enumerate()
            .for_each(|(i, commitment)| {
                *commitment = commit_share(&salt, e as u16, i as u16, &input_shares[e][i]);
            });

        let merkle_tree = MerkleTree::new(commitments_prime, Some(salt));
        commitments[e] = merkle_tree.root();
        merkle_trees.push(merkle_tree);
    }

    (commitments, merkle_trees)
}

#[cfg(test)]
mod commit_share_tests {
    use crate::constants::params::PARAM_SALT_SIZE;

    #[test]
    fn test_that_same_input_gives_same_output() {
        let salt = [0u8; PARAM_SALT_SIZE];
        let e = 1;
        let i = 2;
        let share = [3u8; PARAM_SALT_SIZE];

        let hash1 = super::commit_share(&salt, e, i, &share);
        let hash2 = super::commit_share(&salt, e, i, &share);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_that_different_salt_gives_different_output() {
        let salt = [0u8; PARAM_SALT_SIZE];
        let diff_salt = [1u8; PARAM_SALT_SIZE];
        let e = 1;
        let i = 2;
        let share = [3u8; PARAM_SALT_SIZE];

        let hash1 = super::commit_share(&salt, e, i, &share);
        let hash2 = super::commit_share(&diff_salt, e, i, &share);

        assert_ne!(hash1, hash2);
    }
}
