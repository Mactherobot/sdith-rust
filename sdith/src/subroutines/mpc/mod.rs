//! # MPC
//!
//! Holds the functions for the MPC protocol

pub mod beaver;
pub mod broadcast;
pub mod challenge;

use crate::{
    constants::{
        params::{
            PARAM_L, PARAM_LOG_N, PARAM_M_SUB_K, PARAM_N, PARAM_SPLITTING_FACTOR, PARAM_T,
            PARAM_TAU,
        },
        types::Hash,
    },
    signature::input::{Input, InputSharePlain, INPUT_SIZE},
    subroutines::{
        arith::{
            gf256::{
                gf256_ext::FPoint,
                gf256_matrices::HPrimeMatrix,
                gf256_vector::{gf256_mul_scalar_add_vector, gf256_mul_vector_by_scalar},
            },
            FieldArith as _,
        },
        marshalling::Marshalling as _,
        prg::PRG,
    },
    utils::iterator::*,
    witness::{complete_q, compute_s, compute_s_poly, Solution, SOLUTION_PLAIN_SIZE},
};

use beaver::{BeaverA, BeaverB, BeaverC};
use broadcast::{Broadcast, BroadcastShare};
use challenge::Challenge;
use clap::error::Result;

/// Expands the view opening challenges based on the h1 hash
pub fn expand_view_challenge_hash(h2: Hash) -> [[u16; PARAM_L]; PARAM_TAU] {
    // Initialize the XOF (extendable output function) context with the second Fiat-Shamir
    // transform hash
    let mut prg = PRG::init_base(&h2);

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
        // Sort the values in the set
        opened_views[i].sort();
    }
    // Return the resulting array of opened views
    opened_views
}

/// Compute `share = plain + sum^ℓ_(j=1) fi^j · rnd_coefs[j]`
/// Returns the computed share
/// # Arguments
/// * `plain` - The plain value to be shared
/// * `rnd_coefs` - The random coefficients
/// * `fi` - The challenge value
/// * `skip_loop` - If true, will return rnd_coefs.last().clone()
pub fn compute_share<const SIZE: usize>(
    plain: &[u8; SIZE],
    rnd_coefs: &[[u8; SIZE]],
    fi: u8,
    skip_loop: bool,
) -> [u8; SIZE] {
    // We need to compute the following:
    // input_share[e][i] = input_plain + sum^ℓ_(j=1) fi^j · input_coef[e][j]
    let mut share = *rnd_coefs.last().unwrap();

    // Compute the inner sum
    // sum^ℓ_(j=1) fi · coef[j]
    // Horner method
    if !skip_loop {
        for j in (0..(rnd_coefs.len() - 1)).rev() {
            gf256_mul_scalar_add_vector(&mut share, &rnd_coefs[j], fi);
        }

        // Add the plain to the share
        gf256_mul_scalar_add_vector(&mut share, plain, fi);
    }

    share
}

/// A struct that holds the result of the [`compute_input_shares`] function.
pub struct ComputeInputSharesResult(
    pub Box<[[[u8; INPUT_SIZE]; PARAM_N]; PARAM_TAU]>,
    pub [[[u8; INPUT_SIZE]; PARAM_L]; PARAM_TAU],
);

#[inline(always)]
/// Compute shamir secret sharing of the [`Input`]'s.
/// Returns (shares, coefficients).
pub fn compute_input_shares(
    input_plain: &[u8; INPUT_SIZE],
    prg: &mut PRG,
) -> ComputeInputSharesResult {
    let mut input_shares = Box::new([[[0u8; INPUT_SIZE]; PARAM_N]; PARAM_TAU]);

    // Generate coefficients
    let mut input_coefs = [[[0u8; INPUT_SIZE]; PARAM_L]; PARAM_TAU];
    input_coefs.iter_mut().for_each(|input_coefs_e| {
        input_coefs_e
            .iter_mut()
            .for_each(|input_coefs_ei| prg.sample_field_fq_elements(input_coefs_ei))
    });

    for e in 0..PARAM_TAU {
        get_iterator(&mut input_shares[e])
            .enumerate()
            .for_each(|(i, share)| {
                *share = compute_share(input_plain, &input_coefs[e], i as u8, i == 0);
            });
    }

    ComputeInputSharesResult(input_shares, input_coefs)
}

/// Evaluate the polynomial at a given point in FPoint. See p. 20 of the specification.
/// Q(r) = Σ_{i=0}^{ℓ-1} q_i · r^i
///
/// # Arguments
/// * `poly_d` - The polynomial to evaluate coefficients in order [1, 2, 3] represents p(x) = 3x^2 + 2x + 1
pub fn polynomial_evaluation(poly_d: &[u8], powers_of_r: &[FPoint]) -> FPoint {
    assert!(powers_of_r.len() >= poly_d.len());
    let mut sum = FPoint::default();
    let degree = poly_d.len();
    for i in 0..degree {
        // sum += r_j^(i-1) * q_poly_d[i]
        let mut r_i = powers_of_r[i];
        gf256_mul_vector_by_scalar(&mut r_i, poly_d[i]);
        sum = sum.field_add(r_i);
    }
    sum
}

/// Computes the publicly recomputed values of the MPC protocol (i.e. the plain
/// values corresponding to the broadcasted shares).
///
/// It takes as input the plain input of the MPC
/// protocol, made of the witness (sA , Q' , P ) and the Beaver triples (a, b, c), the syndrome decoding
/// instance (H' , y), and the MPC challenge (r, ε). From these inputs, it computes and returns the
/// plain broadcast values (α, β). Note that the subroutine does not recompute v which is always
/// zero.
/// Input: (wit plain, beav ab plain, beav c plain), chal, (H', y)
pub fn compute_broadcast(
    input: Input,
    chal: &Challenge,
    h_prime: HPrimeMatrix,
    y: [u8; PARAM_M_SUB_K],
) -> Result<Broadcast, String> {
    let broadcast_result = _party_computation(
        input.serialise(),
        chal,
        h_prime,
        y,
        &Broadcast::default(),
        true,
        false,
    );
    if broadcast_result.is_err() {
        return Err("Failed to compute broadcast".to_string());
    }
    let broadcast = broadcast_result.unwrap();

    Ok(Broadcast {
        alpha: broadcast.alpha,
        beta: broadcast.beta,
    })
}

/// Compute the shares broadcast by a party.
///
/// It takes the input shares of the party `(sA, Q', P )_i` and `(a, b, c)_i`,
/// the syndrome decoding instance `(H', y)`, the MPC challenge `(r, ε)`
/// and the recomputed values `(α, β)` and returns the broadcast shares
/// `(α, β, v)_i` of the party.
pub fn party_computation(
    input_share_plain: InputSharePlain,
    chal: &Challenge,
    h_prime: HPrimeMatrix,
    y: [u8; PARAM_M_SUB_K],
    broadcast: &Broadcast,
    with_offset: bool,
) -> Result<BroadcastShare, String> {
    _party_computation(
        input_share_plain,
        chal,
        h_prime,
        y,
        broadcast,
        with_offset,
        true,
    )
}

fn _party_computation(
    input_share_plain: InputSharePlain,
    chal: &Challenge,
    h_prime: HPrimeMatrix,
    y: [u8; PARAM_M_SUB_K],
    broadcast: &Broadcast,
    with_offset: bool,
    compute_v: bool,
) -> Result<BroadcastShare, String> {
    let input_share = Input::parse(&input_share_plain)?;
    let a = input_share.beaver.a;
    let b = input_share.beaver.b;
    let c = input_share.beaver.c;
    let (s_a, q_poly, p_poly) = (
        input_share.solution.s_a,
        input_share.solution.q_poly,
        input_share.solution.p_poly,
    );

    // Compute S
    let s = compute_s(&s_a, &h_prime, if with_offset { Some(&y) } else { None });
    if s.is_err() {
        return Err("Failed to compute S".to_string());
    }
    let s_poly = compute_s_poly(s.unwrap());

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

        let powers_of_r_j = chal.powers_of_r[j];

        for d in 0..PARAM_SPLITTING_FACTOR {
            let a = a[d][j];
            let b = b[d][j];

            // Challenge values

            // α[d][j] = ε[d][j] ⊗ Evaluate(Q[d], r[j]) + a[d][j]
            let eval_q = polynomial_evaluation(&q_poly_complete[d], &powers_of_r_j);
            alpha_share[d][j] = chal.eps[d][j].field_mul(eval_q).field_add(a);

            // β[d][j] = Evaluate(S[d], r[j]) + b[d][j]
            let eval_s = polynomial_evaluation(&s_poly[d], &powers_of_r_j);
            beta_share[d][j] = eval_s.field_add(b);

            if compute_v {
                // v[j] += ε[d][j] ⊗ Evaluate(F, r[j]) ⊗ Evaluate(P[d], r[j])
                let eval_p = polynomial_evaluation(&p_poly[d], &powers_of_r_j);
                v[j] = v[j].field_add(
                    chal.f_poly_eval[j]
                        .field_mul(eval_p)
                        .field_mul(chal.eps[d][j]),
                );
                // v[j] += α'[d][j] ⊗ b[d][j] + β'[d][j] ⊗ a[d][j]
                v[j] = v[j].field_add(broadcast.alpha[d][j].field_mul(b));
                v[j] = v[j].field_add(broadcast.beta[d][j].field_mul(a));

                if with_offset {
                    // v[j] =+ -α[d][j] ⊗ β[d][j]
                    v[j] =
                        v[j].field_add(alpha_share[d][j].field_neg().field_mul(beta_share[d][j]));
                }
            }
        }
    }
    Ok(BroadcastShare {
        alpha: alpha_share,
        beta: beta_share,
        v,
    })
}

/// Computes the shares of the Beaver triples from the shares of the witness and the broadcast
/// shares of a party.
pub fn inverse_party_computation(
    solution_plain: [u8; SOLUTION_PLAIN_SIZE],
    broadcast_share: &BroadcastShare,
    chal: &Challenge,
    h_prime: HPrimeMatrix,
    y: [u8; PARAM_M_SUB_K],
    broadcast: &Broadcast,
    with_offset: bool,
) -> Result<(BeaverA, BeaverB, BeaverC), String> {
    let solution = Solution::parse(&solution_plain).unwrap();
    let (s_a, q_poly, p_poly) = (solution.s_a, solution.q_poly, solution.p_poly);

    // (α, β, v) The broadcast share values
    let (alpha_share, beta_share, v) = (
        broadcast_share.alpha,
        broadcast_share.beta,
        broadcast_share.v,
    );

    // Compute S
    let s = compute_s(&s_a, &h_prime, if with_offset { Some(&y) } else { None });
    if s.is_err() {
        return Err("Failed to compute S".to_string());
    }
    let s_poly = compute_s_poly(s.unwrap());

    // Complete Q
    let q_poly_complete = complete_q(q_poly, if with_offset { 1u8 } else { 0u8 });

    let mut a = [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR];
    let mut b = [[FPoint::default(); PARAM_T]; PARAM_SPLITTING_FACTOR];
    let mut c = [FPoint::default(); PARAM_T];

    for j in 0..PARAM_T {
        // c[j] = -v[j]
        c[j] = v[j].field_neg();

        let powers_of_r_j = chal.powers_of_r[j];

        for d in 0..PARAM_SPLITTING_FACTOR {
            let alpha_share = alpha_share[d][j];
            let beta_share = beta_share[d][j];

            // Challenge values

            // a[d][j] = α[d][j] - ε[d][j] ⊗ Evaluate(Q[d], r[j])
            let eval_q = polynomial_evaluation(&q_poly_complete[d], &powers_of_r_j);
            a[d][j] = alpha_share.field_sub(chal.eps[d][j].field_mul(eval_q));

            // b[d][j] = β[d][j] - Evaluate(S[d], r[j])
            let eval_s = polynomial_evaluation(&s_poly[d], &powers_of_r_j);
            b[d][j] = beta_share.field_sub(eval_s);

            // c[j] +=  ε[d][j] ⊗ Evaluate(F, r[j]) ⊗ Evaluate(P[d], r[j])
            let eval_p = polynomial_evaluation(&p_poly[d], &powers_of_r_j);
            c[j] = c[j].field_add(
                chal.f_poly_eval[j]
                    .field_mul(eval_p)
                    .field_mul(chal.eps[d][j]),
            );

            // c[j] += α'[d][j] ⊗ b[d][j] + β'[d][j] ⊗ a[d][j]
            c[j] = c[j].field_add(broadcast.alpha[d][j].field_mul(b[d][j]));
            c[j] = c[j].field_add(broadcast.beta[d][j].field_mul(a[d][j]));

            if with_offset {
                // c[j] += -α[d][j] ⊗ β[d][j]
                c[j] = c[j].field_add(
                    broadcast.alpha[d][j]
                        .field_neg()
                        .field_mul(broadcast.beta[d][j]),
                );
            }
        }
    }
    Ok((a, b, c))
}

#[cfg(test)]
mod mpc_tests {
    use beaver::BeaverTriples;

    use crate::{
        constants::{
            params::{
                PARAM_DIGEST_SIZE, PARAM_M, PARAM_N, PARAM_SALT_SIZE, PARAM_SEED_SIZE,
                PRECOMPUTED_F_POLY,
            },
            types::{hash_default, Seed},
        },
        signature::input::INPUT_SIZE,
        subroutines::{
            arith::gf256::gf256_vector::{gf256_add_vector, gf256_add_vector_with_padding},
            mpc::{broadcast::BroadcastShare, challenge::get_powers},
        },
        witness::{generate_witness, sample_polynomial_relation},
    };

    use super::*;

    fn prepare() -> (
        Input,
        Broadcast,
        Challenge,
        HPrimeMatrix,
        [u8; PARAM_M_SUB_K],
    ) {
        let mseed = Seed::from([0; PARAM_SEED_SIZE]);
        let hseed = Seed::from([0; PARAM_SEED_SIZE]);
        let mut prg = PRG::init(&mseed, Some(&[0; PARAM_SALT_SIZE]));

        let (q, s, p, _) = sample_polynomial_relation(&mut prg);
        let witness = generate_witness(hseed, (q, s, p));

        let beaver = BeaverTriples::generate(&mut prg);
        let chal = Challenge::new(hash_default());

        let solution = Solution {
            s_a: witness.s_a,
            q_poly: q,
            p_poly: p,
        };

        let input = Input { solution, beaver };

        let broadcast = compute_broadcast(input.clone(), &chal, witness.h_prime, witness.y);
        if broadcast.is_err() {
            panic!("Failed to compute broadcast");
        } else {
            let broadcast = broadcast.unwrap();
            (input, broadcast, chal, witness.h_prime, witness.y)
        }
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
        let r = [40,106,142, 69];

        let mut powers_of_r = [FPoint::default(); PARAM_M + 1];
        get_powers(r, &mut powers_of_r);

        let q_poly = [vec![1, 2, 3]];

        let q_eval = polynomial_evaluation(&q_poly[0], &powers_of_r); // r_0 =
                                                                      // [1,0,0,0] * 1 + [40, 106, 142, 69] * 2 + [123, 29, 100, 186] * 3 = [220, 243, 171, 95]

        let expected = FPoint::from([220, 243, 171, 95]); // q(r) = 1 + 2r + 3r^2
        assert_eq!(q_eval, expected);
    }

    /// Test that we compute the correct sized broadcast values
    #[test]
    fn test_compute_broadcast() {
        let mseed = Seed::from([0; PARAM_SEED_SIZE]);
        let hseed = Seed::from([0; PARAM_SEED_SIZE]);
        let mut prg = PRG::init(&mseed, Some(&[0; PARAM_SALT_SIZE]));

        let (q, s, p, _) = sample_polynomial_relation(&mut prg);
        let witness = generate_witness(hseed, (q, s, p));
        let beaver = BeaverTriples::generate(&mut prg);

        let hash1 = [0u8; PARAM_DIGEST_SIZE];
        let chal = Challenge::new(hash1);

        let broadcast = compute_broadcast(
            Input {
                solution: Solution {
                    s_a: witness.s_a,
                    q_poly: q,
                    p_poly: p,
                },
                beaver,
            },
            &chal,
            witness.h_prime,
            witness.y,
        )
        .unwrap();

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
            party_computation(input.serialise(), &chal, h_prime, y, &broadcast, false).unwrap();

        let inverse_party_computation = inverse_party_computation(
            Input::truncate_beaver_triples(&input.serialise()),
            &party_computation,
            &chal,
            h_prime,
            y,
            &broadcast,
            false,
        )
        .unwrap();

        let (a, b, c) = inverse_party_computation;

        // Assert that the computed values are the same as the original values

        assert_eq!(a, input.beaver.a);
        assert_eq!(b, input.beaver.b);
        assert_eq!(c, input.beaver.c);
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
            party_computation(random_input_plain, &chal, h_prime, y, &broadcast, false)
                .unwrap()
                .serialise();

        // recompute shares of the randomness
        // randomness_shares += (alpha, beta, v=0)
        gf256_add_vector_with_padding(&mut broadcast_share, &broadcast.serialise());

        let broadcast_shares = BroadcastShare::parse(&broadcast_share).unwrap();

        let recomputed_input_share_triples = inverse_party_computation(
            Input::truncate_beaver_triples(&input_share),
            &broadcast_shares,
            &chal,
            h_prime,
            y,
            &broadcast,
            true,
        )
        .unwrap();

        let input_share = Input::parse(&input_share).unwrap();

        assert_eq!(recomputed_input_share_triples.0, input_share.beaver.a);
        assert_eq!(recomputed_input_share_triples.1, input_share.beaver.b);
        assert_eq!(recomputed_input_share_triples.2, input_share.beaver.c);
    }

    /// Test that for some random point r_k we have that S(r_k) * Q'(r_k) = F * P(r_k)
    #[test]
    fn test_relation_sq_eq_pf() {
        let (input, _broadcast, _chal, h_prime, y) = prepare();
        let mut prg = PRG::init_base(&[2]);
        let r = FPoint::field_sample(&mut prg);
        let mut powers_of_r = [FPoint::default(); PARAM_M + 1];
        get_powers(r, &mut powers_of_r);

        let q_poly = complete_q(input.solution.q_poly, 1);
        let s_poly = compute_s_poly(compute_s(&input.solution.s_a, &h_prime, Some(&y)).unwrap());

        let q_eval = polynomial_evaluation(&q_poly[0], &powers_of_r);
        let s_eval = polynomial_evaluation(&s_poly[0], &powers_of_r);

        let f_eval = polynomial_evaluation(&PRECOMPUTED_F_POLY, &powers_of_r);
        let p_eval = polynomial_evaluation(&input.solution.p_poly[0], &powers_of_r);

        assert_eq!(q_eval.field_mul(s_eval), f_eval.field_mul(p_eval));
    }

    /// For the plain broadcast, [`BroadcastShare`].v should always be zero,
    #[test]
    fn test_compute_broadcast_v_is_zero_always() {
        let (input, broadcast, chal, h_prime, y) = prepare();

        let input_plain = input.serialise();

        // Run compute_broadcast, but calculate v
        let broadcast_plain_with_v =
            _party_computation(input_plain, &chal, h_prime, y, &broadcast, true, true).unwrap();

        assert_eq!(broadcast_plain_with_v.v, [FPoint::default(); PARAM_T]);
    }
}