//! # Types
//!
//! Reusable types that are defined by constants.
//! These are used throughout the codebase.

use super::params::{PARAM_DIGEST_SIZE, PARAM_N, PARAM_SALT_SIZE, PARAM_SEED_SIZE};

/// Hash type u8 array of size [`PARAM_DIGEST_SIZE`]
pub type Hash = [u8; PARAM_DIGEST_SIZE];

/// Generate a default empty hash [0u8; PARAM_DIGEST_SIZE]
pub fn hash_default() -> Hash {
    [0u8; PARAM_DIGEST_SIZE]
}

/// Seed type u8 array of size [`PARAM_SEED_SIZE`]
pub type Seed = [u8; PARAM_SEED_SIZE];
/// Salt type u8 array of size [`PARAM_SALT_SIZE`]
pub type Salt = [u8; PARAM_SALT_SIZE];

/// Commitments array of size [`PARAM_N`]
pub type CommitmentsArray = [Hash; PARAM_N];

#[derive(Debug)]
/// Compiled version category of the protocol
pub enum Categories {
    /// NIST security category one 143 bit security
    ONE = 1,
    /// NIST security category three 207 bit security
    THREE = 3,
    /// NIST security category five 272 bit security
    FIVE = 5,
}

#[derive(Debug)]
///  Hash primitive used in the signature scheme
pub enum HashPrimitive {
    /// SHA3-256 hash
    SHA3_256,
    /// SHA3-384 hash
    SHA3_384,
    /// SHA3-512 hash
    SHA3_512,
}

#[derive(Debug)]
///  XOF primitive used in the signature scheme
pub enum XOFPrimitive {
    /// SHAKE128 XOF
    SHAKE128,
    /// SHAKE256 XOF
    SHAKE256,
}
