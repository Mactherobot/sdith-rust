use sha3::{digest::DynDigest, Digest};

use crate::constants::HASH_SIZE;

fn get_hasher() -> Box<dyn DynDigest> {
    match HASH_SIZE {
        256 => Box::new(sha3::Sha3_256::default()),
        384 => Box::new(sha3::Sha3_384::default()),
        512 => Box::new(sha3::Sha3_512::default()),
        _ => panic!("Unsupported hash size: {} = 2λ", HASH_SIZE),
    }
}

pub fn get_hasher_with_prefix(prefix: &[u8]) -> Box<dyn DynDigest> {
    match HASH_SIZE {
        256 => Box::new(sha3::Sha3_256::new_with_prefix(prefix)),
        384 => Box::new(sha3::Sha3_384::new_with_prefix(prefix)),
        512 => Box::new(sha3::Sha3_512::new_with_prefix(prefix)),
        _ => panic!("Unsupported hash size: {} = 2λ", HASH_SIZE),
    }
}

// Hash bytes with dynamically selected hash size by security parameter LAMBDA
pub fn hash(data: &[u8], hasher: &mut dyn DynDigest) -> [u8; HASH_SIZE] {
    hasher.update(data);
    let result = hasher.finalize_reset();
    if let Ok(result) = (*result).try_into() {
        result
    } else {
        panic!("Hash output size mismatch")
    }
}

// Fiat-Shamir Hashes p26 of the spec

/// Hash_1 (data) = Hash(1 ∥ data)
pub fn hash_1(data: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = get_hasher();
    let binding = [&[1], data].concat();
    let data: &[u8] = binding.as_slice();
    return hash(data, &mut *hasher);
}

/// Hash_2 (data) = Hash(2 ∥ data)
pub fn hash_2(data: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = get_hasher();
    let binding = [&[2], data].concat();
    let data: &[u8] = binding.as_slice();
    return hash(data, &mut *hasher);
}
