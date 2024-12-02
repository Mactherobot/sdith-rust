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
