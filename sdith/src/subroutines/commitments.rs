use tiny_keccak::Hasher;

use crate::constants::types::Hash;

use super::prg::hashing::{get_hasher_with_prefix, hash_finalize};

pub(crate) const COMMITMENT_HASH_PREFIX: [u8; 1] = [0];

/// The subroutine Commit takes as input a 2λ-bit `salt`, an execution index `i`,
/// a share index `i` and some data `data` ∈ {0, 1}∗ . It hashes them all together and returns the
/// corresponding digest.
pub(crate) fn commit_share(salt: &Hash, e: u16, i: u16, share: &[u8]) -> Hash {
    // get e_0, e_1 such that e = e_0 + 256 * e_1
    let [e_0, e_1] = e.to_le_bytes();
    // get i_0, i_1 such that i = i_0 + 256 * i_1
    let [i_0, i_1] = i.to_le_bytes();

    let mut hasher = get_hasher_with_prefix(&COMMITMENT_HASH_PREFIX);

    hasher.update(salt);
    hasher.update(&[e_0, e_1, i_0, i_1]);
    hasher.update(share);

    hash_finalize(hasher)
}
