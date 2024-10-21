use crate::{
    arith::gf256::{
        gf256_ext::FPoint,
        gf256_poly::gf256_evaluate_polynomial_horner,
        gf256_vector::{gf256_add_vector, gf256_add_vector_mul_scalar, gf256_mul_vector_by_scalar},
        FieldArith,
    },
    constants::{
        params::{
            PARAM_L, PARAM_LOG_N, PARAM_M_SUB_K, PARAM_N, PARAM_SPLITTING_FACTOR, PARAM_T,
            PARAM_TAU,
        },
        types::Hash,
    },
    signature::input::{Input, InputSharePlain, INPUT_SIZE},
    subroutines::prg::prg::PRG,
    witness::{complete_q, compute_s, compute_s_poly, HPrimeMatrix, Solution, SOLUTION_PLAIN_SIZE},
};

use super::{
    beaver::{Beaver, BeaverA, BeaverB, BeaverC},
    broadcast::{Broadcast, BroadcastShare},
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

    pub(crate) fn expand_view_challenge_hash(digest: Hash) -> [[u16; PARAM_L]; PARAM_TAU] {
        // Initialize the XOF (extendable output function) context with the digest
        let mut prg = PRG::init_base(&digest);

        // Define a mask for reducing the value range
        let mask: u16 = (1 << PARAM_LOG_N) - 1;
        let mut opened_views = [[0u16; PARAM_L]; PARAM_TAU]; // Array for storing the opened views

        let mut tmp = [0u8; 2]; // Temporary buffer for sampled bytes
        let mut value: u16; // The sampled value

        // Loop through all sets (PARAM_TAU sets)
        for i in 0..PARAM_TAU {
            let mut unique_values = std::collections::HashSet::new(); // To ensure uniqueness within a set

            // Generate unique values for the set (PARAM_L values per set)
            for j in 0..PARAM_L {
                loop {
                    // Sample bytes from entropy and convert to u16 (handling endianness)
                    prg.sample_field_fq_elements(&mut tmp);
                    value = (tmp[0] as u16) | ((tmp[1] as u16) << 8);
                    value &= mask; // Apply mask to limit value range

                    // Ensure the value is within valid range and is unique
                    if value < PARAM_N as u16 && unique_values.insert(value) {
                        break;
                    }
                }

                // Store the unique value in the output array
                opened_views[i][j] = value;
            }
            opened_views[i].sort();
        }
        // Return the resulting array of opened views
        opened_views
    }

    /// Compute shamir secret sharing of the [`Input`]'s.
    /// Returns (shares, coefficients).
    ///
    /// Randomly
    pub(crate) fn compute_input_shares(
        input_plain: [u8; INPUT_SIZE],
        prg: &mut PRG,
    ) -> (
        [[[u8; INPUT_SIZE]; PARAM_N]; PARAM_TAU],
        [[[u8; INPUT_SIZE]; PARAM_L]; PARAM_TAU],
    ) {
        let mut input_shares = [[[0u8; INPUT_SIZE]; PARAM_N]; PARAM_TAU];

        // Generate coefficients
        let mut input_coefs = [[[0u8; INPUT_SIZE]; PARAM_L]; PARAM_TAU];
        for e in 0..PARAM_TAU {
            for i in 0..PARAM_L {
                prg.sample_field_fq_elements(&mut input_coefs[e][i]);
            }
        }

        for e in 0..PARAM_TAU {
            for i in 0..(PARAM_N - 1) {
                // We need to compute the following:
                // input_share[e][i] = input_plain + sum^ℓ_(j=1) fi^j · input_coef[e][j]
                let f_i = u8::try_from(i + 1).unwrap();
                let mut eval_sum = [0u8; INPUT_SIZE];

                // Compute the inner sum
                // sum^ℓ_(j=1) fij · input coef[e][j]
                for j in 0..PARAM_L {
                    gf256_add_vector_mul_scalar(
                        &mut eval_sum,
                        &input_coefs[e][j],
                        f_i.field_pow((j + 1) as u8),
                    );
                }

                // Add the input_plain to the sum
                // input_plain + eval_sum
                gf256_add_vector(&mut eval_sum, &input_plain);

                // input_shares[e][i] = ...
                gf256_add_vector(&mut input_shares[e][i], &eval_sum);
            }

            // From line 13 in Algorithm 12
            // input[e][N-1] = input_coef[e][L-1]
            input_shares[e][PARAM_N - 1] = input_coefs[e][PARAM_L - 1];
        }

        (input_shares, input_coefs)
    }

    /// Evaluate the polynomial at a given point in FPoint. See p. 20 of the specification.
    /// The polynomial is evaluated using Horner's method.
    pub(super) fn polynomial_evaluation(poly_d: &[u8], powers_of_r: &[FPoint]) -> FPoint {
        assert!(powers_of_r.len() >= poly_d.len());
        let mut sum = FPoint::default();
        for i in 1..poly_d.len() {
            // sum += r^(i-1) * q_poly_d[i]
            let mut r_n = powers_of_r[i - 1];
            let eval_poly = gf256_evaluate_polynomial_horner(poly_d, i as u8);
            gf256_mul_vector_by_scalar(&mut r_n, eval_poly);

            sum = sum.field_add(r_n);
        }

        sum
    }

    /// computes the publicly recomputed values of the MPC protocol (i.e. the plain
    /// values corresponding to the broadcasted shares). It takes as input the plain input of the MPC
    /// protocol, made of the witness (sA , Q' , P ) and the Beaver triples (a, b, c), the syndrome decoding
    /// instance (H' , y), and the MPC challenge (r, ε). From these inputs, it computes and returns the
    /// plain broadcast values (α, β). Note that the subroutine does not recompute v which is always
    /// zero.
    /// Input: (wit plain, beav ab plain, beav c plain), chal, (H', y)
    pub(crate) fn compute_broadcast(
        input: Input,
        chal: &Challenge,
        h_prime: HPrimeMatrix,
        y: [u8; PARAM_M_SUB_K],
    ) -> Broadcast {
        let broadcast = MPC::_party_computation(
            input.serialise(),
            chal,
            h_prime,
            y,
            &Broadcast::default(),
            true,
            false,
        );

        Broadcast {
            alpha: broadcast.alpha,
            beta: broadcast.beta,
        }
    }

    /// Compute the shares broadcast by a party. It takes the input shares of the party `(sA, Q', P )_i` and `(a, b, c)_i`,
    /// the syndrome decoding instance `(H', y)`, the MPC challenge `(r, ε)` and the recomputed values `(α, β)` and returns the broadcast shares
    /// `(α, β, v)_i` of the party.
    pub(crate) fn party_computation(
        input_share_plain: InputSharePlain,
        chal: &Challenge,
        h_prime: HPrimeMatrix,
        y: [u8; PARAM_M_SUB_K],
        broadcast: &Broadcast,
        with_offset: bool,
    ) -> BroadcastShare {
        return MPC::_party_computation(
            input_share_plain,
            chal,
            h_prime,
            y,
            broadcast,
            with_offset,
            true,
        );
    }

    fn _party_computation(
        input_share_plain: InputSharePlain,
        chal: &Challenge,
        h_prime: HPrimeMatrix,
        y: [u8; PARAM_M_SUB_K],
        broadcast: &Broadcast,
        with_offset: bool,
        compute_v: bool,
    ) -> BroadcastShare {
        let input_share = Input::parse(input_share_plain);
        let (a, b) = input_share.beaver_ab;
        let c = input_share.beaver_c;
        let (s_a, q_poly, p_poly) = (
            input_share.solution.s_a,
            input_share.solution.q_poly,
            input_share.solution.p_poly,
        );

        // Compute S
        let s = compute_s(&s_a, &h_prime, if with_offset { Some(&y) } else { None });
        let s_poly = compute_s_poly(s);

        // Complete Q
        let q_poly_complete = complete_q(q_poly, if with_offset { 1u8 } else { 0u8 });

        // Outputs
        let mut alpha_share = [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR];
        let mut beta_share = [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR];
        let mut v = [FPoint::default(); PARAM_T];

        for j in 0..PARAM_T {
            // v[j] = -c[j]
            if compute_v {
                v[j] = c[j].field_neg();
            }
            for d in 0..PARAM_SPLITTING_FACTOR {
                let a = a[d][j];
                let b = b[d][j];

                // Challenge values
                let powers_of_r_j = chal.powers_of_r[d][j];

                // α[d][j] = ε[d][j] ⊗ Evaluate(Q[d], r[j]) + a[d][j]
                let eval_q = MPC::polynomial_evaluation(&q_poly_complete[d], &powers_of_r_j);
                alpha_share[d][j] = chal.eps[d][j].field_mul(eval_q).field_add(a);

                // β[d][j] = Evaluate(S[d], r[j]) + b[d][j]
                let eval_s = MPC::polynomial_evaluation(&s_poly[d], &powers_of_r_j);
                beta_share[d][j] = eval_s.field_add(b);

                if compute_v {
                    // v[j] += ε[d][j] ⊗ Evaluate(F, r[j]) ⊗ Evaluate(P[d], r[j])
                    let eval_p = MPC::polynomial_evaluation(&p_poly[d], &powers_of_r_j);
                    v[j] = v[j].field_add(chal.f_poly_eval_times_eps[d][j].field_mul(eval_p));

                    // v[j] += α'[d][j] ⊗ b[d][j] + β'[d][j] ⊗ a[d][j]
                    v[j] = v[j].field_add(broadcast.alpha[d][j].field_mul(b));
                    v[j] = v[j].field_add(broadcast.beta[d][j].field_mul(a));

                    if with_offset {
                        // v[j] =+ -α[d][j] ⊗ β[d][j]
                        v[j] = v[j]
                            .field_add(alpha_share[d][j].field_neg().field_mul(beta_share[d][j]));
                    }
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
        let (s_a, q_poly, p_poly) = (solution.s_a, solution.q_poly, solution.p_poly);

        // (α, β, v) The broadcast share values
        let (alpha_share, beta_share, v) = (
            broadcast_share.alpha,
            broadcast_share.beta,
            broadcast_share.v,
        );

        // Compute S
        let s = compute_s(&s_a, &h_prime, if with_offset { Some(&y) } else { None });
        let s_poly = compute_s_poly(s);

        // Complete Q
        let q_poly_complete = complete_q(q_poly, if with_offset { 1u8 } else { 0u8 });

        let mut a = [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR];
        let mut b = [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR];
        let mut c = [FPoint::default(); PARAM_T];
        for j in 0..PARAM_T {
            // c[j] = -v[j]
            c[j] = v[j].field_neg();
            for d in 0..PARAM_SPLITTING_FACTOR {
                let alpha_share = alpha_share[d][j];
                let beta_share = beta_share[d][j];

                // Challenge values
                let powers_of_r_j = chal.powers_of_r[d][j];

                // a[d][j] = α[d][j] - ε[d][j] ⊗ Evaluate(Q[d], r[j])
                let eval_q = MPC::polynomial_evaluation(&q_poly_complete[d], &powers_of_r_j);
                a[d][j] = alpha_share.field_sub(chal.eps[d][j].field_mul(eval_q));

                // b[d][j] = β[d][j] - Evaluate(S[d], r[j])
                let eval_s = MPC::polynomial_evaluation(&s_poly[d], &powers_of_r_j);
                b[d][j] = beta_share.field_sub(eval_s);

                // c[j] +=  ε[d][j] ⊗ Evaluate(F, r[j]) ⊗ Evaluate(P[d], r[j])
                let eval_p = MPC::polynomial_evaluation(&p_poly[d], &powers_of_r_j);
                c[j] = c[j].field_add(chal.f_poly_eval_times_eps[d][j].field_mul(eval_p));

                // c[j] += α'[d][j] ⊗ b[d][j] + β'[d][j] ⊗ a[d][j]
                c[j] = c[j].field_add(broadcast.alpha[d][j].field_mul(b[d][j]));
                c[j] = c[j].field_add(broadcast.beta[d][j].field_mul(a[d][j]));

                if with_offset {
                    // c[j] += -α[d][j] ⊗ β[d][j]
                    c[j] = c[j].field_add(alpha_share.field_neg().field_mul(beta_share));
                }
            }
        }
        return (a, b, c);
    }
}

#[cfg(test)]
mod mpc_tests {
    use crate::{
        arith::gf256::gf256_vector::{gf256_add_vector, gf256_add_vector_with_padding},
        constants::{
            params::{PARAM_DIGEST_SIZE, PARAM_K, PARAM_N, PARAM_SALT_SIZE},
            types::Seed,
        },
        mpc::broadcast::BroadcastShare,
        mpc::challenge::get_powers,
        signature::input::INPUT_SIZE,
        witness::{generate_witness, sample_witness},
    };

    use super::*;

    fn prepare() -> (
        Input,
        Broadcast,
        Challenge,
        [[u8; PARAM_K]; PARAM_M_SUB_K],
        [u8; PARAM_M_SUB_K],
    ) {
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

        let h_prime = witness.h_prime;
        let y = witness.y;
        return (input, broadcast, chal, h_prime, y);
    }

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
        let mut powers_of_r = [FPoint::default(); 2];
        get_powers(r, &mut powers_of_r);

        // Compute the polynomial evaluation
        let result = MPC::polynomial_evaluation(&poly, &powers_of_r);

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
        let mut powers_of_r = [FPoint::default(); 4];
        get_powers(r, &mut powers_of_r);

        // Compute the polynomial evaluation
        let result = MPC::polynomial_evaluation(&poly, &powers_of_r);

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
        let (input, broadcast, chal, h_prime, y) = prepare();

        let party_computation =
            MPC::party_computation(input.serialise(), &chal, h_prime, y, &broadcast, false);

        let inverse_party_computation = MPC::inverse_party_computation(
            Input::truncate_beaver_triples(input.serialise()),
            &party_computation,
            &chal,
            h_prime,
            y,
            &broadcast,
            false,
        );

        let (a, b, c) = inverse_party_computation;

        // Assert that the computed values are the same as the original values

        assert_eq!(a, input.beaver_ab.0);
        assert_eq!(b, input.beaver_ab.1);
        assert_eq!(c, input.beaver_c);
    }

    #[test]
    fn mpc_test_toy_example() {
        let (input, broadcast, chal, h_prime, y) = prepare();
        let random_input_plain: InputSharePlain = [1; INPUT_SIZE];

        // Here N = 1, l = 1 so the shamir secret sharing

        // input + random
        let mut input_share = input.serialise();
        gf256_add_vector(&mut input_share, &random_input_plain);

        // compute shares of the randomness
        let mut broadcast_share =
            MPC::party_computation(random_input_plain, &chal, h_prime, y, &broadcast, false)
                .serialise();

        // recompute shares of the randomness
        // randomness_shares += (alpha, beta, v=0)
        gf256_add_vector_with_padding(&mut broadcast_share, &broadcast.serialise());

        let broadcast_shares = BroadcastShare::parse(broadcast_share);

        let recomputed_input_share_triples = MPC::inverse_party_computation(
            Input::truncate_beaver_triples(input_share),
            &broadcast_shares,
            &chal,
            h_prime,
            y,
            &broadcast,
            true,
        );

        let input_share = Input::parse(input_share);

        assert_eq!(recomputed_input_share_triples.0, input_share.beaver_ab.0);
        assert_eq!(recomputed_input_share_triples.1, input_share.beaver_ab.1);
        assert_eq!(recomputed_input_share_triples.2, input_share.beaver_c);
    }

    /// For the plain broadcast, [`BroadcastShare`].v should always be zero,
    #[test]
    fn test_compute_broadcast_v_is_zero_always() {
        let (input, _broadcast, chal, h_prime, y) = prepare();

        let input_plain = input.serialise();

        // Run MPC::compute_broadcast, but calculate v
        let broadcast_plain_with_v = MPC::_party_computation(
            input_plain,
            &chal,
            h_prime,
            y,
            &Broadcast::default(),
            true,
            true,
        );

        assert_eq!(broadcast_plain_with_v.v, [FPoint::default(); PARAM_T]);
    }

    /// Test that the opened views are unique and within the valid range and are of a correct value
    #[test]
    fn test_expand_view_challenges_threshold_correct_value() {
        let h2: Hash = [
            253, 110, 109, 150, 126, 122, 237, 98, 46, 235, 26, 232, 204, 57, 25, 230, 165, 176,
            207, 174, 32, 137, 6, 253, 110, 92, 165, 196, 229, 37, 219, 3,
        ];
        let view_challenges = MPC::expand_view_challenges_threshold(h2);
        let correct_views = [
            [3, 119, 169],
            [19, 33, 51],
            [50, 63, 86],
            [114, 152, 232],
            [50, 52, 70],
            [6, 88, 249],
        ];
        assert_eq!(view_challenges, correct_views);
    }
}
