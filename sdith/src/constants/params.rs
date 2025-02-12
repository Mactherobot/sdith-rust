#![allow(missing_docs)]

//! # Category Parameters
//!
//! This module contains constants for the three categories of the SDitH Signature Scheme.
//! Each category is conditionally compiled using the `category_one`, `category_three`, and `category_five` feature flags.

#[cfg(not(feature = "category_custom"))]
#[cfg_attr(
    not(any(feature = "category_three", feature = "category_five",)),
    path = "params/cat1.rs"
)]
#[cfg_attr(feature = "category_three", path = "params/cat3.rs")]
#[cfg_attr(feature = "category_five", path = "params/cat5.rs")]
mod cat;

#[cfg(feature = "category_custom")]
mod cat {
    include!(env!("SDITH_CUSTOM_PARAMS_PATH"));
}

use super::types::{Categories, HashPrimitive, XOFPrimitive};

// ## Constants

/// Compiled category for the protocol
pub const COMPILED_CATEGORY: Categories = cat::COMPILED_CATEGORY;
/// Hash primitive used in the signature scheme
pub const HASH_PRIMITIVE: HashPrimitive = cat::HASH_PRIMITIVE;
/// XOF primitive used in the signature scheme
pub const XOF_PRIMITIVE: XOFPrimitive = cat::XOF_PRIMITIVE;

// ### SD Parameters
/// (q) The Galois field size GL(q) = GL(2^8) = GL(256)
pub const PARAM_Q: usize = cat::PARAM_Q;
/// Code length PARAM_CODE_LENGTH
pub const PARAM_M: usize = cat::PARAM_M;
/// Vector dimension PARAM_CODE_DIMENSION
pub const PARAM_K: usize = cat::PARAM_K;
/// The Hamming weight bound PARAM_CODE_WEIGHT
pub const PARAM_W: usize = cat::PARAM_W;
/// Splitting factor for the syndrome variant
pub const PARAM_SPLITTING_FACTOR: usize = cat::PARAM_SPLITTING_FACTOR;

// ### MPCitH Parameters
/// (t) Number of random evaluation points
pub const PARAM_T: usize = cat::PARAM_T;
/// (η) F_point size for F_point = F_(q^η)
pub const PARAM_ETA: usize = cat::PARAM_ETA;
/// (N) Number of secret parties = q
pub const PARAM_N: usize = cat::PARAM_N;
/// (τ) Number of repetitions of the protocol
pub const PARAM_TAU: usize = cat::PARAM_TAU;
/// (ℓ) Privacy threshold (number of open parties)
pub const PARAM_L: usize = cat::PARAM_L;

// ### Signature Parameters
/// Seed size in bytes
pub const PARAM_SEED_SIZE: usize = cat::PARAM_SEED_SIZE / 8;
/// Salt size in bytes
pub const PARAM_SALT_SIZE: usize = cat::PARAM_SALT_SIZE / 8;
/// Digest (Hash) size in bytes
pub const PARAM_DIGEST_SIZE: usize = cat::PARAM_DIGEST_SIZE / 8;

// ### Computed Parameters
/// (log_2(N)) Number of log2(nb_parties) for the number of parties
pub const PARAM_LOG_N: usize = PARAM_N.ilog2() as usize;
/// (λ) Security parameter. E.g. used for the 2λ bit salt for commitments
pub const PARAM_LAMBDA: usize = PARAM_Q / 2;
/// m - k
pub const PARAM_M_SUB_K: usize = PARAM_M - PARAM_K;
/// Chunk size for the splitting variant of the Syndrome Decoding Problem for Code Length m
pub const PARAM_CHUNK_M: usize = PARAM_M / PARAM_SPLITTING_FACTOR;
/// Chunk size for the splitting variant of the Syndrome Decoding Problem for Hamming weight w
pub const PARAM_CHUNK_W: usize = PARAM_W / PARAM_SPLITTING_FACTOR;
/// m-k rounded up to 32 for performance
pub const PARAM_M_SUB_K_CEIL32: usize = ((PARAM_M - PARAM_K + 31) >> 5) << 5;
/// m rounded up to 32 for performance
pub const PARAM_M_CEIL32: usize = ((PARAM_M + 31) >> 5) << 5;

// ## Precomputed constants

/// Precomputed public polynomial F
pub const PRECOMPUTED_F_POLY: [u8; PARAM_CHUNK_M + 1] = cat::PRECOMPUTED_F_POLY;
/// Lagrange scalar coefficients for computing S
///
/// 1 / ∏_{j \neq i}(alpha_i - alpha_j)
pub const PRECOMPUTED_LAGRANGE_INTERPOLATION_WEIGHTS: [u8; PARAM_CHUNK_M] =
    cat::PRECOMPUTED_LAGRANGE_INTERPOLATION_WEIGHTS;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_n_constraint() {
        // For the threshold variant the number N of parties is limited by the size of the field F_q ,
        // i.e. N <= q, which is due to the MDS conjecture
        assert!(PARAM_N <= PARAM_Q, "N must be smaller than or equal to |F_q| due to the MDS conjecture");
    }

    #[test]
    fn check_q_constraint() {
        // The size of the field F_q is limited by the size of the biggest polynomial. 
        // These are sized by the splitting factor.
        assert!(PARAM_CHUNK_M <= PARAM_Q, "Chunk size must be smaller than or equal to |F_q|");
        assert!(PARAM_CHUNK_W <= PARAM_Q, "Chunk size must be smaller than or equal to |F_q|");
    }
}
