//! # Hashing for the SDitH protocol
//!
//! Cryptographic hashing functions are used to compute Fiat-Shamir hashes and Commitment
//! hashes e.g for [Merke-Tree Commitment Scheme](crate::subroutines::merkle_tree::MerkleTree)

#[cfg(not(feature = "hash_blake3"))]
use tiny_keccak::{Hasher, Sha3};

#[cfg(not(feature = "hash_blake3"))]
use crate::constants::params::{HashPrimitive, HASH_PRIMITIVE};
use crate::constants::types::Hash;

/// Hash prefix for challenge 1 Fiats-Shamir Heuristic
pub const HASH_PREFIX_CHALLENGE_1: [u8; 1] = [1];
/// Hash prefix for challenge 2 Fiats-Shamir Heuristic
pub const HASH_PREFIX_CHALLENGE_2: [u8; 1] = [2];

/// SDitH Hash Trait
///
/// Defines the methods for the SDitH Hash and used to switch between different hash primitives e.g. Blake3
pub trait SDitHHashTrait<T> {
    /// Get the hasher for the hash primitive
    ///
    /// Matches the [`HASH_PRIMITIVE`] to get the correct hash based on Category configuration.
    fn get_hasher() -> T;
    /// Initialize the hasher
    fn init() -> Self;
    /// Initialize the hasher with a prefix. E.g. for challenge 1.
    fn init_with_prefix(prefix: &[u8]) -> Self;
    /// Finalize the hash, returning the [`type@Hash`] value
    fn finalize(self) -> Hash;
    /// Update the hasher with data
    fn update(&mut self, data: &[u8]);
}

/// SDitH Hash struct
///
/// Holds the generic hasher
pub struct SDitHHash<T> {
    hasher: T,
}

#[cfg(not(feature = "hash_blake3"))]
impl SDitHHashTrait<Sha3> for SDitHHash<Sha3> {
    fn get_hasher() -> Sha3 {
        match HASH_PRIMITIVE {
            HashPrimitive::SHA3_256 => Sha3::v256(),
            HashPrimitive::SHA3_384 => Sha3::v384(),
            HashPrimitive::SHA3_512 => Sha3::v512(),
        }
    }

    fn init() -> Self {
        SDitHHash {
            hasher: Self::get_hasher(),
        }
    }

    fn init_with_prefix(prefix: &[u8]) -> Self {
        let mut hasher = Self::get_hasher();
        hasher.update(prefix);
        SDitHHash { hasher }
    }


    fn finalize(self) -> Hash {
        let mut output = [0u8; crate::constants::params::PARAM_DIGEST_SIZE];
        self.hasher.finalize(&mut output);
        output
    }

    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }
}

#[cfg(feature = "hash_blake3")]
impl SDitHHashTrait<blake3::Hasher> for SDitHHash<blake3::Hasher> {
    fn get_hasher() -> blake3::Hasher {
        blake3::Hasher::new()
    }

    fn init() -> Self {
        SDitHHash {
            hasher: Self::get_hasher(),
        }
    }

    fn init_with_prefix(prefix: &[u8]) -> Self {
        let mut hasher = Self::get_hasher();
        hasher.update(prefix);
        SDitHHash { hasher }
    }

    fn finalize(self) -> Hash {
        self.hasher.finalize().into()
    }

    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }
}

/// Hash `data` using the SDitH Hash initiated with the challenge 1 prefix
pub fn hash_1(data: Vec<&[u8]>) -> Hash {
    let mut hasher = SDitHHash::init_with_prefix(&HASH_PREFIX_CHALLENGE_1);
    for d in data {
        hasher.update(d);
    }
    SDitHHash::finalize(hasher)
}

/// Hash `data` using the SDitH Hash initiated with the challenge 2 prefix
pub fn hash_2(data: Vec<&[u8]>) -> Hash {
    let mut hasher = SDitHHash::init_with_prefix(&HASH_PREFIX_CHALLENGE_2);
    for d in data {
        hasher.update(d);
    }
    SDitHHash::finalize(hasher)
}

#[cfg(test)]
mod tests {
    use crate::constants::params::PARAM_DIGEST_SIZE;
    use super::*;

    fn hash(data: &[u8]) -> Hash {
        let mut hasher = SDitHHash::init();
        hasher.update(data);
        SDitHHash::finalize(hasher)
    }

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
