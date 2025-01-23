//! # Challenge
//!
//! MPCitH challenge generation and precomputed values
//!
//! - MPCChallenge: pair (r, e) ∈ F_point^t, (F_point^t)^d
//! - View opening challenge: I ∈ \[N\] for |I| = l

use core::fmt;
use std::fmt::Formatter;

use crate::{
    constants::{
        params::{
            PARAM_CHUNK_M, PARAM_L, PARAM_LOG_N, PARAM_SPLITTING_FACTOR, PARAM_T, PARAM_TAU,
            PRECOMPUTED_F_POLY,
        },
        types::{hash_default, Hash},
    },
    subroutines::{
        arithmetics::{
            gf256::{extensions::FPoint, polynomials::gf256_polynomial_evaluation_in_point_r},
            FieldArith as _,
        },
        prg::PRG,
    },
};

/// MPC Challenge pair `(r, e) ∈ F_point^t, (F_point^t)^d`
#[derive(Clone)]
pub struct MPCChallenge {
    /// Challenge value r. The verifier challenges the prover in at several points to check the correctness of the
    /// polynomial relation.
    pub r: [FPoint; PARAM_T],
    /// Challenge value epsilon. The idea from the Sacrificing Protocol by Baum and Nof and allows the
    /// verifier to check the correctness of the randomly generated "pre-processed" beaver triples.
    pub eps: [[FPoint; PARAM_T]; PARAM_SPLITTING_FACTOR],
    /// Pre-computed powers of r for each evaluation and splitting.
    pub powers_of_r: [[FPoint; PARAM_CHUNK_M + 1]; PARAM_T],
    /// Pre-computed polynomial evaluations of the f polynomial times epsilon at the powers of r for each evaluation and splitting.
    pub f_poly_eval: [FPoint; PARAM_T],
}

impl MPCChallenge {
    /// Generate `number_of_pairs` of challenges (r, e) ∈ F_point^t, (F_point^t)^d
    /// Uses h1 hash for Fiat-Shamir Transform
    pub fn new(h1: Hash) -> Self {
        let mut prg = PRG::init_base(&h1);
        let mut r = [FPoint::default(); PARAM_T];
        prg.sample_field_fpoint_elements(&mut r);

        let mut eps = [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR];
        for e_i in eps.iter_mut() {
            prg.sample_field_fpoint_elements(e_i);
        }

        // Pre-compute the powers of r as they are used multiple times
        let mut powers_of_r = [[FPoint::default(); PARAM_CHUNK_M + 1]; PARAM_T];
        // Pre-compute f(r) for each d and t
        let mut f_poly_eval = [FPoint::default(); PARAM_T];

        for t in 0..PARAM_T {
            powers_of_r[t][1] = r[t];
            get_powers(r[t], &mut powers_of_r[t]);
            f_poly_eval[t] =
                gf256_polynomial_evaluation_in_point_r(&PRECOMPUTED_F_POLY, &powers_of_r[t])
        }

        Self {
            r,
            eps,
            powers_of_r,
            f_poly_eval,
        }
    }
}

impl Default for MPCChallenge {
    fn default() -> Self {
        Self::new(hash_default())
    }
}

impl std::fmt::Debug for MPCChallenge {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MPCChallenge {{ \n\tr: {:?}, \n\teps[0]: {:?} \n\tpowers_of_r[0][..5]: {:?} \n}}",
            &self.r,
            &self.eps[0],
            &self.powers_of_r[0][..5]
        )
    }
}

/// Compute the powers of a point for fixed length. Used for precomputing the powers of r.
pub fn get_powers(point: FPoint, out: &mut [FPoint]) {
    out[0] = FPoint::field_mul_identity();
    out[1] = point;
    for i in 2..out.len() {
        out[i] = out[i - 1].field_mul(point);
    }
}

/// Expands h2 hash into the view opening challenge
///
/// While the categories are all within u8 size, we
/// use u16 to allow for higher number of parties
///
/// `I ∈ [N]` for `|I| = l`
pub fn expand_view_challenge_hash(h2: Hash) -> [[u16; PARAM_L]; PARAM_TAU] {
    // Initialize the XOF (extendable output function) context with the
    // second Fiat-Shamir transform hash
    let mut prg = PRG::init_base(&h2);

    // Define a mask for reducing the value range. We use a mask to limit the value
    // range to [0, N-1] to ensure that we can index into the opened_views array.
    let modulo: u16 = (1 << PARAM_LOG_N) - 1;
    let mut opened_views = [[0u16; PARAM_L]; PARAM_TAU];

    let mut tmp = [0u8; 2]; // Temporary buffer for sampled bytes
    let mut value: u16; // The sampled value

    for i in 0..PARAM_TAU {
        let mut unique_values = std::collections::HashSet::new(); // To ensure uniqueness within a set

        for j in 0..PARAM_L {
            loop {
                // Sample bytes from entropy and convert to u16 (handling endianness)
                prg.sample_field_fq_elements(&mut tmp);
                value = (tmp[0] as u16) | ((tmp[1] as u16) << 8);
                value &= modulo; // Apply modulo to limit value range

                // Ensure the value is unique
                if unique_values.insert(value) {
                    break;
                }
            }

            opened_views[i][j] = value;
        }
        // Sort the values in the set. This is required for the Merkle Tree calculations.
        opened_views[i].sort();
    }
    opened_views
}

#[cfg(test)]
mod challenge_tests {
    use crate::{
        constants::params::{PARAM_DIGEST_SIZE, PARAM_ETA, PARAM_N},
        subroutines::arithmetics::FieldArith,
    };

    use super::*;

    #[test]
    fn test_generate() {
        let hash = [0u8; PARAM_DIGEST_SIZE];
        let challenge = MPCChallenge::new(hash);
        assert_eq!(challenge.r.len(), PARAM_T);
        assert_eq!(challenge.eps.len(), PARAM_SPLITTING_FACTOR);
        for r in challenge.r.iter() {
            assert_eq!(r.len(), PARAM_ETA);
        }

        // Test powers of r
        for _ in 0..PARAM_SPLITTING_FACTOR {
            for t in 0..PARAM_T {
                for i in 1..PARAM_CHUNK_M + 1 {
                    assert_eq!(
                        challenge.powers_of_r[t][i],
                        challenge.r[t].field_pow(i as u8)
                    );
                }
            }
        }
    }

    #[test]
    fn test_powers() {
        let mut prg = PRG::init_base(&hash_default());
        let point = FPoint::field_sample(&mut prg);
        let mut out = [FPoint::default(); PARAM_CHUNK_M + 1];
        get_powers(point, &mut out);
        (0..PARAM_CHUNK_M + 1).for_each(|i| {
            assert_eq!(out[i], point.field_pow(i as u8));
        });
    }

    #[test]
    fn test_expand_view_challenge_hash() {
        let mut prg = PRG::init_base(&[0]);
        let mut h2 = [0u8; PARAM_DIGEST_SIZE];
        for _ in 0..1000 {
            prg.sample_field_fq_elements(&mut h2);
            let view_challenges = expand_view_challenge_hash(h2);
            assert_eq!(view_challenges.len(), PARAM_TAU);
            for view_challenge in view_challenges {
                assert_eq!(view_challenge.len(), PARAM_L);
                for &x in view_challenge.iter() {
                    assert!(
                        (x as usize) < PARAM_N,
                        "View challenge should be less than N: {x} < {PARAM_N}",
                    );
                }
            }

            // Assert that the view opening challenges are sorted
            for views in view_challenges.iter() {
                for i in 1..views.len() {
                    assert!(views[i - 1] <= views[i], "View opening challenges should be sorted in ascending order for Merkle Tree implementation");
                }
            }
        }
    }
}
