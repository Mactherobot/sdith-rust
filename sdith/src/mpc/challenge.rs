use core::fmt;
use std::fmt::Formatter;

use crate::{
    arith::gf256::{gf256_ext::FPoint, FieldArith},
    constants::{
        params::{PARAM_CHUNK_M, PARAM_CHUNK_W, PARAM_SPLITTING_FACTOR, PARAM_T},
        precomputed::PRECOMPUTED_F_POLY,
        types::Hash,
    },
    subroutines::prg::prg::PRG,
};

use super::mpc::MPC;

/// Challenge pair `(r, e) ∈ F_point^t, (F_point^t)^d`
#[derive(Clone)]
pub(crate) struct Challenge {
    /// Challenge value r
    pub(crate) r: [FPoint; PARAM_T],
    /// Challenge value epsilon
    pub(crate) eps: [[FPoint; PARAM_T]; PARAM_SPLITTING_FACTOR],
    /// Pre-computed powers of r for each evaluation and splitting.
    pub(crate) powers_of_r: [[FPoint; PARAM_CHUNK_M + 1]; PARAM_T],
    /// Pre-computed polynomial evaluations of the f polynomial times epsilon at the powers of r for each evaluation and splitting.
    pub(crate) f_poly_eval: [FPoint; PARAM_T],
}

impl Challenge {
    /// Generate `number_of_pairs` of challenges (r, e) ∈ F_point^t, (F_point^t)^d
    /// Uses h1 hash for Fiat-Shamir Transform
    pub(crate) fn new(h1: Hash) -> Self {
        println!("h1 {:?}", h1);
        let mut prg = PRG::init_base(&h1);
        let mut r = [FPoint::default(); PARAM_T];
        prg.sample_field_fpoint_elements(&mut r);

        // Print r

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
            f_poly_eval[t] = MPC::polynomial_evaluation(&PRECOMPUTED_F_POLY, &powers_of_r[t])
        }

        Self {
            r,
            eps,
            powers_of_r,
            f_poly_eval,
        }
    }
}

impl Default for Challenge {
    fn default() -> Self {
        Self::new(Hash::default())
    }
}

impl std::fmt::Debug for Challenge {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Challenge {{ r: {:?}, e: {:?} }}",
            &self.r[0], &self.eps[0]
        )
    }
}

/// Compute the powers of a point for fixed length. Used for precomputing the powers of r.
pub(crate) fn get_powers(point: FPoint, out: &mut [FPoint]) {
    out[0] = FPoint::field_one();
    out[1] = point.clone();
    for i in 2..out.len() {
        out[i] = out[i - 1].field_mul(point);
    }
}

#[cfg(test)]
mod challenge_tests {
    use crate::constants::params::PARAM_ETA;

    use super::*;

    #[test]
    fn test_generate() {
        let hash = Hash::default();
        let challenge = Challenge::new(hash);
        assert_eq!(challenge.r.len(), PARAM_T);
        assert_eq!(challenge.eps.len(), PARAM_SPLITTING_FACTOR);
        for r in challenge.r.iter() {
            assert_eq!(r.len(), PARAM_ETA);
        }

        // Test powers of r
        for d in 0..PARAM_SPLITTING_FACTOR {
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
        let mut prg = PRG::init_base(&Hash::default());
        let point = FPoint::field_sample(&mut prg);
        let mut out = [FPoint::default(); PARAM_CHUNK_M + 1];
        get_powers(point, &mut out);
        for i in 0..PARAM_CHUNK_M + 1 {
            assert_eq!(out[i], point.field_pow(i as u8));
        }
    }
}
