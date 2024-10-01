use crate::{
    arith::{
        beaver_triples, concat_arrays_stable,
        gf256::{
            gf256_ext::{gf256_ext32_add, gf256_ext32_mul, gf256_ext32_pow, FPoint},
            gf256_poly::{
                gf256_evaluate_polynomial_horner, gf256_evaluate_polynomial_horner_monic,
            },
            gf256_vector::gf256_mul_vector_by_scalar,
        },
        matrices::MatrixGF256,
        split_array_stable,
    },
    constants::{
        params::{
            PARAM_CHUNK_M, PARAM_K, PARAM_L, PARAM_LOG_N, PARAM_M, PARAM_M_SUB_K,
            PARAM_SPLITTING_FACTOR, PARAM_T, PARAM_TAU,
        },
        types::{Hash, Salt, Seed},
    },
    subroutines::prg::prg::PRG,
    witness::{QPoly, SPoly, Solution, Witness},
};

use super::{
    beaver::{Beaver, BeaverA, BeaverABPlain, BeaverB, BeaverC, BeaverCPlain},
    challenge::Challenge,
};

#[derive(Debug)]
pub(crate) struct MPC {}

/// A bit mask that ensures the value generated in expand_view_challenges is within 1:PARAM_N
const MASK: u16 = (1 << PARAM_LOG_N) - 1;

type BroadcastValue = [[FPoint; PARAM_T]; PARAM_SPLITTING_FACTOR];
pub(crate) struct Broadcast {
    pub(crate) alpha: BroadcastValue,
    pub(crate) beta: BroadcastValue,
}

impl Default for Broadcast {
    fn default() -> Self {
        let alpha = [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR];
        let beta = [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR];
        Self { alpha, beta }
    }
}

impl MPC {
    pub(crate) fn generate_beaver_triples(mseed: Seed, salt: Salt) -> (BeaverA, BeaverB, BeaverC) {
        Beaver::generate_beaver_triples(mseed, salt)
    }

    pub(crate) fn expand_mpc_challenges(n: usize) -> Vec<Challenge> {
        let mut challenges = Vec::with_capacity(n);
        for _ in 0..n {
            challenges.push(Challenge::new());
        }

        challenges
    }

    /// Sample the view challenges for the MPC protocol. The view challenges are sampled from a set {}
    pub(crate) fn expand_view_challenges_threshold(h2: Hash) -> [[u16; PARAM_L]; PARAM_TAU] {
        let mut prg = PRG::init_base(&h2);
        let mut view_challenges = [[0u16; PARAM_L]; PARAM_TAU];
        let mut tmp = [0u8; 2];
        for i in 0..PARAM_TAU {
            for j in 0..PARAM_L {
                prg.sample_field_fq_non_zero(&mut tmp);
                let mut value: u16 = u16::from_le_bytes(tmp);
                value &= MASK;
                view_challenges[i][j] = value
            }
        }

        view_challenges
    }

    /// Evaluate the polynomial at a given point in FPoint. See p. 20 of the specification.
    /// The polynomial is evaluated using Horner's method.
    /// If `use_monic` is true, the polynomial is evaluated using the monic form by adding the leading coefficient 1.
    /// Otherwise, the polynomial is evaluated as is.
    fn polynomial_evaluation(poly_d: Vec<u8>, r: FPoint, use_monic: bool) -> FPoint {
        let mut sum = FPoint::default();
        for i in 1..poly_d.len() {
            // sum += r^(i-1) * q_poly_d[i]
            let mut r_n = gf256_ext32_pow(r, i - 1);
            let eval_poly = if use_monic {
                gf256_evaluate_polynomial_horner_monic(&poly_d, i as u8)
            } else {
                gf256_evaluate_polynomial_horner(&poly_d, i as u8)
            };
            gf256_mul_vector_by_scalar(&mut r_n, eval_poly);

            sum = gf256_ext32_add(sum, r_n);
        }

        return sum;
    }

    /// computes the publicly recomputed values of the MPC protocol (i.e. the plain
    /// values corresponding to the broadcasted shares). It takes as input the plain input of the MPC
    /// protocol, made of the witness (sA , Q′ , P ) and the Beaver triples (a, b, c), the syndrome decoding
    /// instance (H ′ , y), and the MPC challenge (r, ε). From these inputs, it computes and returns the
    /// plain broadcast values (α, β). Note that the subroutine does not recompute v which is always
    /// zero.
    /// Input: (wit plain, beav ab plain, beav c plain), chal, (H′, y)
    pub(crate) fn compute_broadcast(
        witness: Witness,
        beaver_triples: (BeaverA, BeaverB, BeaverC),
        chal: Challenge,
    ) -> Broadcast {
        let (a, b, _c) = beaver_triples;
        let (r, e) = (chal.r, chal.e);

        // Generate s = (sA, y * H')
        let s_b: [u8; PARAM_M_SUB_K] = witness.matrix_h_prime.gf256_mul_vector(&witness.y);
        let s: [u8; PARAM_M] = concat_arrays_stable(witness.s_a, s_b);
        let mut s_poly: SPoly = [[0u8; PARAM_CHUNK_M]; PARAM_SPLITTING_FACTOR];
        for (i, s_poly_d) in s.chunks(PARAM_CHUNK_M).enumerate() {
            s_poly[i] = s_poly_d.try_into().expect("Invalid chunk size");
        }

        let mut broadcast = Broadcast::default();

        for j in 0..PARAM_T {
            for d in 0..PARAM_SPLITTING_FACTOR {
                let q_poly_d = witness.q_poly[d].to_vec();
                let s_poly_d = s_poly[d].to_vec();

                // α[d][j] = ε[d][j] ⊗ Evaluate(Q[ν], r[j]) + a[d][j]
                broadcast.alpha[d][j] = gf256_ext32_add(
                    gf256_ext32_mul(e[d][j], MPC::polynomial_evaluation(q_poly_d, r[j], true)),
                    a[d][j],
                );

                // β[d][j] = Evaluate(S[ν], r[j]) + b[d][j]
                broadcast.beta[d][j] =
                    gf256_ext32_add(MPC::polynomial_evaluation(s_poly_d, r[j], false), b[d][j]);
            }
        }

        return broadcast;
    }

    pub(crate) fn party_computation() {
        todo!("Implement the party computation")
    }

    pub(crate) fn inverse_party_computation() {
        todo!("Implement the inverse party computation")
    }
}

#[cfg(test)]
mod mpc_tests {
    use crate::constants::params::{PARAM_DIGEST_SIZE, PARAM_N};

    use super::*;

    #[test]
    fn test_expand_view_challenges_threshold() {
        let mut prg = PRG::init_base(&[0]);
        let mut h2 = [0u8; PARAM_DIGEST_SIZE];
        for _ in 0..1000 {
            prg.sample_field_fq_elements(&mut h2);
            let view_challenges = MPC::expand_view_challenges_threshold(h2);
            assert_eq!(view_challenges.len(), PARAM_TAU);
            for view_challenge in view_challenges {
                assert_eq!(view_challenge.len(), PARAM_L);
                for &x in view_challenge.iter() {
                    assert_ne!(x, 0, "View challenge should not be zero: {}", x);
                    assert!(
                        x as usize <= PARAM_N,
                        "View challenge should be less than N: {} <= {}",
                        x,
                        PARAM_N as u8
                    );
                }
            }
        }
    }

    #[test]
    fn test_polynomial_evaluation() {
        todo!("Implement the test for polynomial evaluation")
    }

    #[test]
    fn test_compute_broadcast() {
        todo!("Implement the test for compute broadcast")
    }
}
