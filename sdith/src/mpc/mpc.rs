use crate::signature::input::{Input, InputSharePlain};
use crate::witness::{HPrimeMatrix, Solution, SOLUTION_PLAIN_SIZE};
use crate::{
    arith::{
        concat_arrays_stable,
        gf256::{
            gf256_ext::{gf256_ext32_add, gf256_ext32_mul, gf256_ext32_pow, FPoint},
            gf256_poly::gf256_evaluate_polynomial_horner,
            gf256_vector::gf256_mul_vector_by_scalar,
        },
        matrices::MatrixGF256,
    },
    constants::{
        params::{
            PARAM_CHUNK_W, PARAM_L, PARAM_LOG_N, PARAM_M, PARAM_M_SUB_K, PARAM_SPLITTING_FACTOR,
            PARAM_T, PARAM_TAU,
        },
        precomputed::PRECOMPUTED_F_POLY,
        types::Hash,
    },
    subroutines::prg::prg::PRG,
    witness::{complete_q, compute_s, compute_s_poly, QPolyComplete},
};

use super::broadcast::{Broadcast, BroadcastShare};
use super::{
    beaver::{Beaver, BeaverA, BeaverB, BeaverC},
    challenge::Challenge,
};

#[derive(Debug)]
pub(crate) struct MPC {}

/// A bit mask that ensures the value generated in expand_view_challenges is within 1:PARAM_N
const MASK: u16 = (1 << PARAM_LOG_N) - 1;

impl MPC {
    pub(crate) fn generate_beaver_triples(prg: &mut PRG) -> (BeaverA, BeaverB, BeaverC) {
        Beaver::generate_beaver_triples(prg)
    }

    pub(crate) fn expand_mpc_challenges(h1: Hash, n: usize) -> Vec<Challenge> {
        let mut challenges = Vec::with_capacity(n);
        for _ in 0..n {
            challenges.push(Challenge::new(h1));
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
            view_challenges[i].sort();
        }

        view_challenges
    }

    /// Evaluate the polynomial at a given point in FPoint. See p. 20 of the specification.
    /// The polynomial is evaluated using Horner's method.
    fn polynomial_evaluation(poly_d: &[u8], r: FPoint) -> FPoint {
        let mut sum = FPoint::default();
        for i in 1..poly_d.len() {
            // sum += r^(i-1) * q_poly_d[i]
            let mut r_n = gf256_ext32_pow(r, i - 1);
            let eval_poly = gf256_evaluate_polynomial_horner(poly_d, i as u8);
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
        input: Input,
        chal: &Challenge,
        h_prime: HPrimeMatrix,
        y: [u8; PARAM_M_SUB_K],
    ) -> Broadcast {
        let (a, b) = input.beaver_ab;
        let solution = input.solution;
        let (r, e) = (chal.r, chal.e);

        // Generate s = (sA, y + H's_a)
        let s = compute_s(&solution.s_a, &h_prime, &y);
        let s_poly = compute_s_poly(s);

        // CompleteQ(Q', 1)
        let mut q_poly_complete: QPolyComplete = [[0u8; PARAM_CHUNK_W + 1]; PARAM_SPLITTING_FACTOR];
        complete_q(&mut q_poly_complete, solution.q_poly, 1);

        let mut broadcast = Broadcast::default();

        for j in 0..PARAM_T {
            for d in 0..PARAM_SPLITTING_FACTOR {
                // α[d][j] = ε[d][j] ⊗ Evaluate(Q[ν], r[j]) + a[d][j]
                broadcast.alpha[d][j] = gf256_ext32_add(
                    gf256_ext32_mul(
                        e[d][j],
                        MPC::polynomial_evaluation(&q_poly_complete[d], r[j]),
                    ),
                    a[d][j],
                );

                // β[d][j] = Evaluate(S[ν], r[j]) + b[d][j]
                broadcast.beta[d][j] =
                    gf256_ext32_add(MPC::polynomial_evaluation(&s_poly[d], r[j]), b[d][j]);
            }
        }

        broadcast
    }

    /// Compute the shares broadcast by a party. It takes the input shares of the party (sA, Q′, P )_i and (a, b, c)_i,
    /// the syndrome decoding instance (H′, y), the MPC challenge (r, ε) and the recomputed values (α, β) and returns the broadcast shares
    /// (α, β, v)_i of the party.
    pub(crate) fn party_computation(
        input_share_plain: InputSharePlain,
        chal: &Challenge,
        h_prime: HPrimeMatrix,
        y: [u8; PARAM_M_SUB_K],
        broadcast: &Broadcast,
        with_offset: bool,
    ) -> BroadcastShare {
        let input_share = Input::parse(input_share_plain);
        let (a, b) = input_share.beaver_ab;
        let c = input_share.beaver_c;
        let solution = input_share.solution;
        let (r, e) = (chal.r, chal.e);

        // Plain broadcast values
        let (alpha, beta) = (broadcast.alpha, broadcast.beta);
        let mut _s = [0u8; PARAM_M];
        let mut q_poly_complete: QPolyComplete = [[0u8; PARAM_CHUNK_W + 1]; PARAM_SPLITTING_FACTOR];
        let s_a = solution.s_a;

        if with_offset {
            // Generate s = (sA, y + H's_a)
            _s = compute_s(&s_a, &h_prime, &y);

            // Compute the completed q_poly by inserting the leading coefficient
            complete_q(&mut q_poly_complete, solution.q_poly, 1u8);
        } else {
            // Generate s = (sA, y + H's_a)
            let s_b: [u8; PARAM_M_SUB_K] = h_prime.gf256_mul_vector(&s_a);
            _s = concat_arrays_stable(s_a, s_b);

            // Compute the completed q_poly by inserting the 0 as the leading coefficient, this is due to
            // when the parties locally add a constant value to a sharing, the constant addition is only done by one party. The Boolean
            // with offset is set to True for this party while it is set to False for the other parties.
            complete_q(&mut q_poly_complete, solution.q_poly, 0u8);
        }

        // Compute the S polynomial
        let s_poly = compute_s_poly(_s);

        let mut alpha_share = [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR];
        let mut beta_share = [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR];
        let mut v = [FPoint::default(); PARAM_T];
        for j in 0..PARAM_T {
            // Set v[j] to the negated correlated value from c
            v[j] = c[j];
            for d in 0..PARAM_SPLITTING_FACTOR {
                // Set alpha as ε[j][ν] ⊗ Evaluate(Q[ν], r[j]) + a[j][ν]
                let eval_q = MPC::polynomial_evaluation(&q_poly_complete[d], r[j]);
                let _a = a[d][j];
                let _epsilon = e[d][j];
                alpha_share[d][j] = gf256_ext32_add(gf256_ext32_mul(_epsilon, eval_q), _a);

                // Set beta as Evaluate(S[d], r[j]) + b[j][d]
                let eval_s = MPC::polynomial_evaluation(&s_poly[d], r[j]);
                let _b = b[d][j];
                beta_share[d][j] = gf256_ext32_add(eval_s, _b);

                // Add ε[j][ν] ⊗ Evaluate(F, r[j]) ⊗ Evaluate(P[ν], r[j]) to v[j]
                let eval_p = MPC::polynomial_evaluation(&solution.p_poly[d], r[j]);
                let eval_f = MPC::polynomial_evaluation(&PRECOMPUTED_F_POLY, r[j]);
                let eval_f_p = gf256_ext32_mul(eval_f, eval_p);
                let eval_epsilon_f_p = gf256_ext32_mul(_epsilon, eval_f_p);
                v[j] = gf256_ext32_add(v[j], eval_epsilon_f_p);

                // Add α[j][ν] ⊗ b[j][ν] + ¯β[j][ν] ⊗ a[j][ν] to v[j]
                let plain_alpha = alpha[d][j];
                let plain_beta = beta[d][j];
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
        solution_plain: [u8; SOLUTION_PLAIN_SIZE],
        broadcast_share: &BroadcastShare,
        chal: &Challenge,
        h_prime: HPrimeMatrix,
        y: [u8; PARAM_M_SUB_K],
        broadcast: &Broadcast,
        with_offset: bool,
    ) -> (BeaverA, BeaverB, BeaverC) {
        let solution = Solution::parse(solution_plain);
        // (α, β, v) The broadcast share values
        let (alpha_share, beta_share, _v) = (
            broadcast_share.alpha,
            broadcast_share.beta,
            broadcast_share.v,
        );
        // (¯α, ¯β) are the broadcast values
        let (alpha, beta) = (broadcast.alpha, broadcast.beta);
        // Challenge values
        let (r, e) = (chal.r, chal.e);

        // Mutable variables
        let mut _s = [0u8; PARAM_M];
        let mut q_poly_complete: QPolyComplete = [[0u8; PARAM_CHUNK_W + 1]; PARAM_SPLITTING_FACTOR];
        let s_a = solution.s_a;

        if with_offset {
            // Generate s = (sA, y + H's_a)
            _s = compute_s(&s_a, &h_prime, &y);

            // Compute the completed q_poly by inserting the leading coefficient
            complete_q(&mut q_poly_complete, solution.q_poly, 1u8);
        } else {
            // Generate s = (sA, y + H's_a)
            let s_b: [u8; PARAM_M_SUB_K] = h_prime.gf256_mul_vector(&s_a);
            _s = concat_arrays_stable(s_a, s_b);
            // Compute the completed q_poly by inserting the 0 as the leading coefficient, this is due to
            // when the parties locally add a constant value to a sharing, the constant addition is only done by one party. The Boolean
            // with offset is set to True for this party while it is set to False for the other parties.
            complete_q(&mut q_poly_complete, solution.q_poly, 0u8);
        }

        // Compute the S polynomial
        let s_poly = compute_s_poly(_s);

        let mut a = [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR];
        let mut b = [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR];
        let mut c = [FPoint::default(); PARAM_T];
        for j in 0..PARAM_T {
            // Set c[j] to the negated correlated value from v
            c[j] = _v[j];
            for d in 0..PARAM_SPLITTING_FACTOR {
                // First we need to set alpha as ε[j][ν] ⊗ Evaluate(Q[ν], r[j]) + a[j][ν]
                let eval_q = MPC::polynomial_evaluation(&q_poly_complete[d], r[j]);
                let _alpha_share = alpha_share[d][j];
                let _epsilon = e[d][j];
                a[d][j] = gf256_ext32_add(gf256_ext32_mul(_epsilon, eval_q), _alpha_share);

                // Next we need to set beta as Evaluate(S[d], r[j]) + b[j][d]
                let eval_s = MPC::polynomial_evaluation(&s_poly[d], r[j]);
                let _beta_share = beta_share[d][j];
                b[d][j] = gf256_ext32_add(eval_s, _beta_share);

                // Now we need to add  ε[j][ν] ⊗ Evaluate(F, r[j]) ⊗ Evaluate(P[ν], r[j]) to c[j]
                let eval_p = MPC::polynomial_evaluation(&solution.p_poly[d], r[j]);
                let eval_f = MPC::polynomial_evaluation(&PRECOMPUTED_F_POLY, r[j]);
                let eval_f_p = gf256_ext32_mul(eval_f, eval_p);
                let eval_epsilon_f_p = gf256_ext32_mul(_epsilon, eval_f_p);
                c[j] = gf256_ext32_add(c[j], eval_epsilon_f_p);

                // Add α[j][ν] ⊗ b[j][ν] + ¯β[j][ν] ⊗ a[j][ν] to c[j]
                let plain_alpha = alpha[d][j];
                let plain_beta = beta[d][j];
                let eval_plain_alpha_b = gf256_ext32_mul(plain_alpha, b[d][j]);
                let eval_plain_beta_a = gf256_ext32_mul(plain_beta, a[d][j]);
                let eval_alpha_beta = gf256_ext32_add(eval_plain_alpha_b, eval_plain_beta_a);
                c[j] = gf256_ext32_add(c[j], eval_alpha_beta);

                // If with_offset then add − α[j][ν] ⊗ β[j][ν] to c[j]
                if with_offset {
                    let eval_alpha_beta = gf256_ext32_mul(plain_alpha, plain_beta);
                    c[j] = gf256_ext32_add(c[j], eval_alpha_beta);
                }
            }
        }
        return (a, b, c);
    }
}

#[cfg(test)]
mod mpc_tests {
    use crate::{
        constants::{
            params::{PARAM_DIGEST_SIZE, PARAM_N, PARAM_SALT_SIZE},
            types::Seed,
        },
        witness::{generate_witness, sample_witness},
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
        let poly = [1, 2];
        // Create test point
        let r = FPoint::from([1, 1, 3, 1]);
        // Compute the polynomial evaluation
        let result = MPC::polynomial_evaluation(&poly, r);

        // The expected result is:
        let expected = FPoint::from([3, 0, 0, 0]);
        assert_eq!(result, expected);
    }

    /// Test that we can evaluate larger polynomials
    #[test]
    fn test_polynomial_evaluation_len_4() {
        // Create test polynomial
        // f(x) = 1 + 2x + 3x^2 + 4x^3
        let poly = [1, 2, 3, 4];
        // Create test point
        // r = [1, 1, 3, 1]
        let r = FPoint::from([1, 1, 3, 1]);
        // Compute the polynomial evaluation
        let result = MPC::polynomial_evaluation(&poly, r);

        // The expected result is:
        let expected = FPoint::from([221, 70, 69, 29]);
        assert_eq!(result, expected)
    }

    /// Test that we compute the correct sized broadcast values
    #[test]
    fn test_compute_broadcast() {
        let mseed = Seed::from([0; 16]);
        let hseed = Seed::from([0; 16]);
        let mut prg = PRG::init(&mseed, Some(&[0; PARAM_SALT_SIZE]));

        let (q, s, p, _) = sample_witness(mseed);
        let witness = generate_witness(hseed, (q, s, p));
        let beaver_triples = Beaver::generate_beaver_triples(&mut prg);

        let hash1 = Hash::default();
        let chal = Challenge::new(hash1);

        let broadcast = MPC::compute_broadcast(
            Input {
                solution: Solution {
                    s_a: witness.s_a,
                    q_poly: q,
                    p_poly: p,
                },
                beaver_ab: (beaver_triples.0, beaver_triples.1),
                beaver_c: beaver_triples.2,
            },
            &chal,
            witness.h_prime,
            witness.y,
        );

        assert_eq!(broadcast.alpha.len(), PARAM_SPLITTING_FACTOR);
        assert_eq!(broadcast.beta.len(), PARAM_SPLITTING_FACTOR);
        for i in 0..PARAM_SPLITTING_FACTOR {
            assert_eq!(broadcast.alpha[i].len(), PARAM_T);
            assert_eq!(broadcast.beta[i].len(), PARAM_T);
        }
    }

    /// Test that we can compute the party computation and inverse it again
    #[test]
    fn test_compute_party_computation_and_inverted_computation_are_the_same() {
        let mseed = Seed::from([0; 16]);
        let hseed = Seed::from([0; 16]);
        let mut prg = PRG::init(&mseed, Some(&[0; PARAM_SALT_SIZE]));

        let (q, s, p, _) = sample_witness(mseed);
        let witness = generate_witness(hseed, (q, s, p));

        let beaver_triples = Beaver::generate_beaver_triples(&mut prg);
        let chal = Challenge::new(Hash::default());

        let solution = Solution {
            s_a: witness.s_a,
            q_poly: q,
            p_poly: p,
        };

        let input = Input {
            solution: solution.clone(),
            beaver_ab: (beaver_triples.0, beaver_triples.1),
            beaver_c: beaver_triples.2,
        };

        let broadcast = MPC::compute_broadcast(input.clone(), &chal, witness.h_prime, witness.y);

        let with_offset = false;
        let h_prime = witness.h_prime;
        let y = witness.y;

        let party_computation = MPC::party_computation(
            input.serialise(),
            &chal,
            h_prime,
            y,
            &broadcast,
            with_offset,
        );

        let inverse_party_computation = MPC::inverse_party_computation(
            Input::truncate_beaver_triples(input.serialise()),
            &party_computation,
            &chal,
            h_prime,
            y,
            &broadcast,
            with_offset,
        );

        let (a, b, c) = inverse_party_computation;

        // Assert that the computed values are the same as the original values
        for i in 0..PARAM_SPLITTING_FACTOR {
            for j in 0..PARAM_T {
                assert_eq!(a[i][j], beaver_triples.0[i][j]);
                assert_eq!(b[i][j], beaver_triples.1[i][j]);
                assert_eq!(c[i], beaver_triples.2[i]);
            }
        }
    }
}
