use crate::constants::{COMMITMENT_SALT_SIZE, HASH_SIZE};

use super::hashing::get_hasher_with_prefix;

pub type Commitment = [u8; HASH_SIZE];

pub const COMMITMENT_HASH_PREFIX: [u8; 1] = [0];

/// The subroutine Commit takes as input a 2λ-bit `salt`, an execution index `i`,
/// a share index `i` and some data `data` ∈ {0, 1}∗ . It hashes them all together and returns the
/// corresponding digest.
///
///
pub fn commit_share(
    salt: &[u8; COMMITMENT_SALT_SIZE],
    e: usize,
    i: usize,
    share: &[u8],
) -> Commitment {
    // get e_0, e_1 such that e = e_0 + 256 * e_1
    let e_0: u8 = (e & 0xFF).try_into().unwrap();
    let e_1: u8 = (e >> 8_u8).try_into().unwrap();

    // get i_0, e_1 such that i = e_0 + 256 * e_1
    let i_0: u8 = (i & 0xFF).try_into().unwrap();
    let i_1: u8 = (i >> 8_u8).try_into().unwrap();

    let mut hasher = get_hasher_with_prefix(&COMMITMENT_HASH_PREFIX);

    let mut data_bytes: Vec<u8> = Vec::with_capacity(salt.len() + 4 + share.len());
    data_bytes.extend_from_slice(salt);
    data_bytes.push(e_0);
    data_bytes.push(e_1);
    data_bytes.push(i_0);
    data_bytes.push(i_1);
    data_bytes.extend_from_slice(&share);

    hasher.update(data_bytes.as_slice());
    let result = hasher.finalize_reset();
    if let Ok(result) = (*result).try_into() {
        result
    } else {
        panic!("Hash output size mismatch")
    }
}
