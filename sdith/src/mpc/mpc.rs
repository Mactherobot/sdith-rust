use crate::{
    arith::{
        beaver_triples, concat_arrays_stable,
        gf256::{
            gf256_ext::{gf256_ext32_add, gf256_ext32_mul, gf256_ext32_pow, FPoint},
            gf256_poly::{
                gf256_evaluate_polynomial_horner, gf256_evaluate_polynomial_horner_monic,
            },
            gf256_vector::{gf256_add_vector, gf256_mul_vector_by_scalar},
        },
        matrices::MatrixGF256,
        split_array_stable,
    },
    constants::{
        params::{
            PARAM_CHUNK_M, PARAM_CHUNK_W, PARAM_K, PARAM_L, PARAM_LOG_N, PARAM_M, PARAM_M_SUB_K,
            PARAM_SPLITTING_FACTOR, PARAM_T, PARAM_TAU,
        },
        precomputed::PRECOMPUTED_F_POLY,
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

pub(crate) struct BroadcastShare {
    pub(crate) alpha: BroadcastValue,
    pub(crate) beta: BroadcastValue,
    pub(crate) v: [FPoint; PARAM_T],
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

        sum
    }

    /// computes the publicly recomputed values of the MPC protocol (i.e. the plain
    /// values corresponding to the broadcasted shares). It takes as input the plain input of the MPC
    /// protocol, made of the witness (sA , Q′ , P ) and the Beaver triples (a, b, c), the syndrome decoding
    /// instance (H′ , y), and the MPC challenge (r, ε). From these inputs, it computes and returns the
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

        // Generate s = (sA, y + H's_a)
        let mut h_prime_s_a: [u8; PARAM_M_SUB_K] =
            witness.matrix_h_prime.gf256_mul_vector(&witness.s_a);
        gf256_add_vector(&mut h_prime_s_a, &witness.y);
        let s_b: [u8; PARAM_M_SUB_K] = h_prime_s_a;
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

        broadcast
    }

    /// performs the party computation, namely it computes the shares broadcast by a party. It takes the
    /// input shares of the party (sA, Q′, P )i and (a, b, c)i, the syndrome decoding instance (H′, y),
    /// the MPC challenge (r, ε) and the recomputed values (α, β) and returns the broadcast shares
    /// (α, β, v)i of the party.
    /// TODO: Is missing the share part of this
    pub(crate) fn party_computation(
        witness: Witness,
        beaver_triples: (BeaverA, BeaverB, BeaverC),
        chal: Challenge,
        broadcast: Broadcast,
        with_offset: bool,
    ) -> BroadcastShare {
        let (a, b, _c) = beaver_triples;
        let (r, e) = (chal.r, chal.e);
        let (alpha, beta) = (broadcast.alpha, broadcast.beta);
        let mut s = [0u8; PARAM_M];

        if with_offset {
            // Generate s = (sA, y + H's_a)
            let mut h_prime_s_a: [u8; PARAM_M_SUB_K] =
                witness.matrix_h_prime.gf256_mul_vector(&witness.s_a);
            gf256_add_vector(&mut h_prime_s_a, &witness.y);
            let s_b: [u8; PARAM_M_SUB_K] = h_prime_s_a;
            s = concat_arrays_stable(witness.s_a, s_b);

            // Compute the completed q_poly by inserting the leading coef
            let mut q_poly: QPoly = [[0u8; PARAM_CHUNK_W]; PARAM_SPLITTING_FACTOR];
            complete_q(&mut q_poly, &witness, 1u8);
        } else {
            // Generate s = (sA, y + H's_a)
            let s_b: [u8; PARAM_M_SUB_K] = witness.matrix_h_prime.gf256_mul_vector(&witness.s_a);
            s = concat_arrays_stable(witness.s_a, s_b);

            // Compute the completed q_poly by inserting the 0 as the leading coef, this is due to
            // when the parties locally add a constant value to a sharing, the constant addition is only done by one party. The Boolean
            // with offset is set to True for this party while it is set to False for the other parties.
            let mut q_poly: QPoly = [[0u8; PARAM_CHUNK_W]; PARAM_SPLITTING_FACTOR];
            complete_q(&mut q_poly, &witness, 0u8);
        }

        // Compute the S polynomial
        let mut s_poly: SPoly = [[0u8; PARAM_CHUNK_M]; PARAM_SPLITTING_FACTOR];
        for (i, s_poly_d) in s.chunks(PARAM_CHUNK_M).enumerate() {
            s_poly[i] = s_poly_d.try_into().expect("Invalid chunk size");
        }

        let mut alpha_share = [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR];
        let mut beta_share = [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR];
        let mut v = [FPoint::default(); PARAM_T];
        for j in 0..PARAM_T {
            // Set v[j] to the negated correlated value from c
            // TODO: figure out how to find the negated value
            for d in 0..PARAM_SPLITTING_FACTOR {
                // Set alpha as ε[j][ν] ⊗ Evaluate(Q[ν], r[j]) + a[j][ν]
                let eval_q = MPC::polynomial_evaluation(witness.q_poly[d].to_vec(), r[j], true);
                let _a = a[j][d];
                let _epsilon = e[j][d];
                alpha_share[j][d] = gf256_ext32_add(gf256_ext32_mul(_epsilon, eval_q), _a);

                // Set beta as Evaluate(S[d], r[j]) + b[j][d]
                let eval_s = MPC::polynomial_evaluation(s_poly[d].to_vec(), r[j], false);
                let _b = b[j][d];
                beta_share[j][d] = gf256_ext32_add(eval_s, _b);

                // Add ε[j][ν] ⊗ Evaluate(F, r[j]) ⊗ Evaluate(P
                // [ν], r[j]) to v[j]
                let eval_p = MPC::polynomial_evaluation(witness.p_poly[d].to_vec(), r[j], false);
                let eval_f = MPC::polynomial_evaluation(PRECOMPUTED_F_POLY.to_vec(), r[j], false);
                let eval_f_p = gf256_ext32_mul(eval_f, eval_p);
                let eval_epsilon_f_p = gf256_ext32_mul(_epsilon, eval_f_p);
                v[j] = gf256_ext32_add(v[j], eval_epsilon_f_p);

                // Add α[j][ν] ⊗ b[j][ν] + ¯β[j][ν] ⊗ a[j][ν] to v[j]
                let plain_alpha = alpha[j][d];
                let plain_beta = beta[j][d];
                let eval_plain_alpha_b = gf256_ext32_mul(plain_alpha, _b);
                let eval_plain_beta_a = gf256_ext32_mul(plain_beta, _a);
                let eval_alpha_beta = gf256_ext32_add(eval_plain_alpha_b, eval_plain_beta_a);
                v[j] = gf256_ext32_add(v[j], eval_alpha_beta);

                // If with_offset then add − α[j][ν] ⊗ β[j][ν] to v[j]
                if with_offset {
                    let eval_alpha_beta = gf256_ext32_mul(plain_alpha, plain_beta);
                    v[j] = gf256_ext32_add(v[j], eval_alpha_beta);
                }
            }
        }
        return BroadcastShare {
            alpha: alpha_share,
            beta: beta_share,
            v,
        };
    }

    /// computes the shares of the Beaver triples from the shares of the witness and the broadcast
    /// shares of a party.
    /// TODO: This is missing the share part of this
    pub(crate) fn inverse_party_computation(
        witness: Witness,
        broadcast_share: BroadcastShare,
        chal: Challenge,
        broadcast: Broadcast,
        with_offset: bool,
    ) -> (BeaverA, BeaverB, BeaverC) {
        let (alpha_share, beta_share, v) = (
            broadcast_share.alpha,
            broadcast_share.beta,
            broadcast_share.v,
        );
        let (r, e) = (chal.r, chal.e);
        let (alpha, beta) = (broadcast.alpha, broadcast.beta);
        let mut s = [0u8; PARAM_M];

        if with_offset {
            // Generate s = (sA, y + H's_a)
            let mut h_prime_s_a: [u8; PARAM_M_SUB_K] =
                witness.matrix_h_prime.gf256_mul_vector(&witness.s_a);
            gf256_add_vector(&mut h_prime_s_a, &witness.y);
            let s_b: [u8; PARAM_M_SUB_K] = h_prime_s_a;
            s = concat_arrays_stable(witness.s_a, s_b);

            // Compute the completed q_poly by inserting the leading coef
            let mut q_poly: QPoly = [[0u8; PARAM_CHUNK_W]; PARAM_SPLITTING_FACTOR];
            complete_q(&mut q_poly, &witness, 1u8);
        } else {
            // Generate s = (sA, y + H's_a)
            let s_b: [u8; PARAM_M_SUB_K] = witness.matrix_h_prime.gf256_mul_vector(&witness.s_a);
            s = concat_arrays_stable(witness.s_a, s_b);
            // Compute the completed q_poly by inserting the 0 as the leading coef, this is due to
            // when the parties locally add a constant value to a sharing, the constant addition is only done by one party. The Boolean
            // with offset is set to True for this party while it is set to False for the other parties.
            let mut q_poly: QPoly = [[0u8; PARAM_CHUNK_W]; PARAM_SPLITTING_FACTOR];
            complete_q(&mut q_poly, &witness, 0u8);
        }

        // Compute the S polynomial
        let mut s_poly: SPoly = [[0u8; PARAM_CHUNK_M]; PARAM_SPLITTING_FACTOR];
        for (i, s_poly_d) in s.chunks(PARAM_CHUNK_M).enumerate() {
            s_poly[i] = s_poly_d.try_into().expect("Invalid chunk size");
        }

        let mut a = [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR];
        let mut b = [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR];
        let mut c = [FPoint::default(); PARAM_T];
        for j in 0..PARAM_T {
            // Set c[j] to the negated correlated value from v
            // TODO: figure out how to find the negated value
            for d in 0..PARAM_SPLITTING_FACTOR {
                // First we need to set alpha as ε[j][ν] ⊗ Evaluate(Q[ν], r[j]) + a[j][ν]
                let eval_q = MPC::polynomial_evaluation(witness.q_poly[d].to_vec(), r[j], true);
                let _alpa_share = alpha_share[j][d];
                let _epsilon = e[j][d];
                a[j][d] = gf256_ext32_add(gf256_ext32_mul(_epsilon, eval_q), _alpa_share);

                // Next we need to set beta as Evaluate(S[d], r[j]) + b[j][d]
                let eval_s = MPC::polynomial_evaluation(s_poly[d].to_vec(), r[j], false);
                let _beta_share = beta_share[j][d];
                b[j][d] = gf256_ext32_add(eval_s, _beta_share);

                // Now we need to add  ε[j][ν] ⊗ Evaluate(F, r[j]) ⊗ Evaluate(P
                // [ν], r[j]) to c[j]
                let eval_p = MPC::polynomial_evaluation(witness.p_poly[d].to_vec(), r[j], false);
                let eval_f = MPC::polynomial_evaluation(PRECOMPUTED_F_POLY.to_vec(), r[j], false);
                let eval_f_p = gf256_ext32_mul(eval_f, eval_p);
                let eval_epsilon_f_p = gf256_ext32_mul(_epsilon, eval_f_p);
                c[j] = gf256_ext32_add(c[j], eval_epsilon_f_p);

                // Add α[j][ν] ⊗ b[j][ν] + ¯β[j][ν] ⊗ a[j][ν] to c[j]
                let plain_alpha = alpha[j][d];
                let plain_beta = beta[j][d];
                let eval_plain_alpha_b = gf256_ext32_mul(plain_alpha, _beta_share);
                let eval_plain_beta_a = gf256_ext32_mul(plain_beta, _alpa_share);
                let eval_alpha_beta = gf256_ext32_add(eval_plain_alpha_b, eval_plain_beta_a);
                c[j] = gf256_ext32_add(c[j], eval_alpha_beta);

                // If with_offset then add − α[j][ν] ⊗ β[j][ν] to c[j]
                if with_offset {
                    let eval_alpha_beta = gf256_ext32_mul(plain_alpha, plain_beta);
                    c[j] = gf256_ext32_add(c[j], eval_alpha_beta);
                }
            }
        }
        return Default::default();
    }
}

/// Completes the q polynomial by inserting the leading coefficient
/// TODO: This is only a helper function an is currently used for adding the leading coef when
/// computing the partyComputation
fn complete_q(
    q_poly: &mut [[u8; PARAM_CHUNK_W]; PARAM_SPLITTING_FACTOR],
    witness: &Witness,
    leading: u8,
) {
    for d in 0..PARAM_SPLITTING_FACTOR {
        q_poly[d][0] = leading;
        for i in 0..PARAM_K {
            q_poly[d][i + 1] = witness.q_poly[d][i];
        }
    }
}

#[cfg(test)]
mod mpc_tests {
    use crate::{
        constants::params::{PARAM_DIGEST_SIZE, PARAM_N},
        witness::{generate_instance_with_solution, generate_witness, sample_witness},
    };

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

    /// Test that we can evaluate a polynomial correctly
    #[test]
    fn test_polynomial_evaluation_len_2() {
        // Create test polynomial
        // f(x) = 1 + 2x
        let poly = vec![1, 2];
        // Create test point
        let r = FPoint::from([1, 1, 3, 1]);
        // Compute the polynomial evaluation
        let result = MPC::polynomial_evaluation(poly, r, false);

        // The expected result is:
        let expected = FPoint::from([3, 0, 0, 0]);
        assert_eq!(result, expected);
    }

    /// Test that we can evaluate larger polynomials
    #[test]
    fn test_polynomial_evaluation_len_4() {
        // Create test polynomial
        // f(x) = 1 + 2x + 3x^2 + 4x^3
        let poly = vec![1, 2, 3, 4];
        // Create test point
        // r = [1, 1, 3, 1]
        let r = FPoint::from([1, 1, 3, 1]);
        // Compute the polynomial evaluation
        let result = MPC::polynomial_evaluation(poly, r, false);

        // The expected result is:
        let expected = FPoint::from([221, 70, 69, 29]);
        assert_eq!(result, expected)
    }

    /// Test that we compute the correct sized broadcast values
    #[test]
    fn test_compute_broadcast() {
        let mseed = Seed::from([0; 16]);
        let hseed = Seed::from([0; 16]);
        let (q, s, p, _) = sample_witness(mseed);
        let witness = generate_witness(hseed, (q, s, p));
        let beaver_triples = Beaver::generate_beaver_triples(mseed, [0; 32]);
        let chal = Challenge::new();
        let broadcast = MPC::compute_broadcast(witness, beaver_triples, chal);
        assert_eq!(broadcast.alpha.len(), PARAM_SPLITTING_FACTOR);
        assert_eq!(broadcast.beta.len(), PARAM_SPLITTING_FACTOR);
        for i in 0..PARAM_SPLITTING_FACTOR {
            assert_eq!(broadcast.alpha[i].len(), PARAM_T);
            assert_eq!(broadcast.beta[i].len(), PARAM_T);
        }
    }
}
