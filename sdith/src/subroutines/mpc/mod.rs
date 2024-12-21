//! # MPC
//!
//! Holds the functions for the MPC protocol

pub mod beaver;
pub mod broadcast;
pub mod input;

use crate::{
    constants::params::{PARAM_M_SUB_K, PARAM_SPLITTING_FACTOR, PARAM_T},
    subroutines::arith::{
        gf256::{
            gf256_ext::{gf256_polynomial_evaluation_in_point_r, FPoint},
            gf256_matrices::HPrimeMatrix,
        },
        FieldArith as _,
    },
    utils::marshalling::Marshalling,
    witness::{complete_q, compute_s, compute_s_poly, Solution, SOLUTION_PLAIN_SIZE},
};

use beaver::{BeaverA, BeaverB, BeaverC};
use broadcast::{Broadcast, BroadcastShare};
use clap::error::Result;
use input::{Input, InputSharePlain};

use super::challenge::MPCChallenge;

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
    chal: &MPCChallenge,
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
    chal: &MPCChallenge,
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
    chal: &MPCChallenge,
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
            let eval_q =
                gf256_polynomial_evaluation_in_point_r(&q_poly_complete[d], &powers_of_r_j);
            alpha_share[d][j] = chal.eps[d][j].field_mul(eval_q).field_add(a);

            // β[d][j] = Evaluate(S[d], r[j]) + b[d][j]
            let eval_s = gf256_polynomial_evaluation_in_point_r(&s_poly[d], &powers_of_r_j);
            beta_share[d][j] = eval_s.field_add(b);

            if compute_v {
                // v[j] += ε[d][j] ⊗ Evaluate(F, r[j]) ⊗ Evaluate(P[d], r[j])
                let eval_p = gf256_polynomial_evaluation_in_point_r(&p_poly[d], &powers_of_r_j);
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
    chal: &MPCChallenge,
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
            let eval_q =
                gf256_polynomial_evaluation_in_point_r(&q_poly_complete[d], &powers_of_r_j);
            a[d][j] = alpha_share.field_sub(chal.eps[d][j].field_mul(eval_q));

            // b[d][j] = β[d][j] - Evaluate(S[d], r[j])
            let eval_s = gf256_polynomial_evaluation_in_point_r(&s_poly[d], &powers_of_r_j);
            b[d][j] = beta_share.field_sub(eval_s);

            // c[j] +=  ε[d][j] ⊗ Evaluate(F, r[j]) ⊗ Evaluate(P[d], r[j])
            let eval_p = gf256_polynomial_evaluation_in_point_r(&p_poly[d], &powers_of_r_j);
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
                PARAM_DIGEST_SIZE, PARAM_M, PARAM_SALT_SIZE, PARAM_SEED_SIZE, PRECOMPUTED_F_POLY,
            },
            types::{hash_default, Seed},
        },
        subroutines::{
            arith::gf256::gf256_vector::{gf256_add_vector, gf256_add_vector_with_padding},
            challenge::get_powers,
            mpc::broadcast::BroadcastShare,
            prg::PRG,
        },
        witness::{generate_witness, sample_polynomial_relation},
    };

    use super::*;

    fn prepare() -> (
        Input,
        Broadcast,
        MPCChallenge,
        HPrimeMatrix,
        [u8; PARAM_M_SUB_K],
    ) {
        let mseed = Seed::from([0; PARAM_SEED_SIZE]);
        let hseed = Seed::from([0; PARAM_SEED_SIZE]);
        let mut prg = PRG::init(&mseed, Some(&[0; PARAM_SALT_SIZE]));

        let (q, s, p, _) = sample_polynomial_relation(&mut prg);
        let witness = generate_witness(hseed, (q, s, p));

        let beaver = BeaverTriples::generate(&mut prg);
        let chal = MPCChallenge::new(hash_default());

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
        let chal = MPCChallenge::new(hash1);

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
        let random_input_plain: InputSharePlain = [1; input::INPUT_SIZE];

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

        let q_eval = gf256_polynomial_evaluation_in_point_r(&q_poly[0], &powers_of_r);
        let s_eval = gf256_polynomial_evaluation_in_point_r(&s_poly[0], &powers_of_r);

        let f_eval = gf256_polynomial_evaluation_in_point_r(&PRECOMPUTED_F_POLY, &powers_of_r);
        let p_eval =
            gf256_polynomial_evaluation_in_point_r(&input.solution.p_poly[0], &powers_of_r);

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
