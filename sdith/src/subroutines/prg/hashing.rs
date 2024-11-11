use tiny_keccak::{Hasher, Sha3};

use crate::constants::params::{HashPrimitive, HASH_PRIMITIVE, PARAM_DIGEST_SIZE};
use crate::constants::types::Hash;

pub(crate) const HASH_PREFIX_CHALLENGE_1: [u8; 1] = [1];
pub(crate) const HASH_PREFIX_CHALLENGE_2: [u8; 1] = [2];

pub(crate) fn get_hash() -> Sha3 {
    match HASH_PRIMITIVE {
        HashPrimitive::SHA3_256 => return Sha3::v256(),
        HashPrimitive::SHA3_384 => return Sha3::v384(),
        HashPrimitive::SHA3_512 => return Sha3::v512(),
    }
}

pub(crate) fn get_hasher_with_prefix(prefix: &[u8]) -> Sha3 {
    let mut hasher = get_hash();
    hasher.update(prefix);
    hasher
}

pub(crate) fn hash_finalize(hasher: Sha3) -> Hash {
    let result: &mut Hash = &mut [0_u8; PARAM_DIGEST_SIZE];
    hasher.finalize(result);

    *result
}

pub(crate) fn hash(data: &[u8]) -> Hash {
    let mut hasher = get_hash();
    hasher.update(data);
    return hash_finalize(hasher);
}

// Fiat-Shamir Hashes p26 of the spec

/// Hash_1 (data) = Hash(1 ∥ data)
pub(crate) fn hash_1(data: Vec<&[u8]>) -> Hash {
    let mut hasher = get_hasher_with_prefix(&HASH_PREFIX_CHALLENGE_1.clone());
    for d in data {
        hasher.update(d);
    }
    return hash_finalize(hasher);
}

/// Hash_2 (data) = Hash(2 ∥ data)
pub(crate) fn hash_2(data: Vec<&[u8]>) -> Hash {
    let mut hasher = get_hasher_with_prefix(&HASH_PREFIX_CHALLENGE_2.clone());
    for d in data {
        hasher.update(d);
    }
    return hash_finalize(hasher);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_prefix() {}

    #[test]
    fn test_hash_1() {
        let data_1 = [2, 3, 4, 5];
        let hash_1 = hash_1(vec![&data_1]);
        assert!(hash_1.len() == PARAM_DIGEST_SIZE);

        let data_2 = [1, 2, 3, 4, 5];
        let hash = hash(&data_2);
        assert!(hash.len() == PARAM_DIGEST_SIZE);

        assert_eq!(hash_1, hash);
    }

    #[test]
    fn test_hash_2() {
        let data_1 = [3, 4, 5, 6];
        let data_2 = [2, 3, 4, 5, 6];
        let hash_2 = hash_2(vec![&data_1]);
        assert!(hash_2.len() == PARAM_DIGEST_SIZE);
        let hash = hash(&data_2);
        assert!(hash.len() == PARAM_DIGEST_SIZE);
        assert_eq!(hash_2, hash);
    }
}
