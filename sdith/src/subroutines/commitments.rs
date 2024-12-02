//! # Commitment
//! 
//! Commitment primitive for shares in the MPCitH protocol.

use crate::constants::types::{Hash, Salt};
use super::prg::hashing::{SDitHHash, SDitHHashTrait as _};

/// The prefix for the commitment hash function.
pub const COMMITMENT_HASH_PREFIX: [u8; 1] = [0];

/// Commit to a share through hashing.
/// 
/// # Arguments
/// - `salt`: 2λ-bit salt
/// - `e`: Execution index [`crate::constants::params::PARAM_TAU`] of the share
/// - `i`: Party index [`crate::constants::params::PARAM_N`] of the share
/// - `share`: Share data to commit to
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
}
