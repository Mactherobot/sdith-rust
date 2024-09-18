use crate::{
    arith::gf256::{
        gf256_arith::{gf256_add, gf256_mul, gf256_sub},
        gf256_poly::gf256_remove_one_degree_factor_monic,
        gf256_vector::{gf256_add_vector, gf256_mul_vector_by_scalar},
    },
    constants::{
        params::{
            PARAM_CHUNK_LENGTH, PARAM_CHUNK_WEIGHT, PARAM_K, PARAM_M_SUB_K, PARAM_SEED_SIZE,
            PARAM_SPLITTING_FACTOR,
        },
        precomputed::{PRECOMPUTED_F_POLY, PRECOMPUTED_LEADING_COEFFICIENTS_OF_LJ_FOR_S},
    },
    subroutines::{
        matrices::{split_vector_cpy_into_2, HMatrix, Matrix, MatrixGF256Arith},
        prg::prg::PRG,
    },
};

// Polynomial types
type QPoly = [u8; PARAM_CHUNK_WEIGHT * PARAM_SPLITTING_FACTOR];
impl Matrix<PARAM_CHUNK_WEIGHT, PARAM_SPLITTING_FACTOR> for QPoly {}
type PPoly = [u8; PARAM_CHUNK_WEIGHT * PARAM_SPLITTING_FACTOR];
type SPoly = [u8; PARAM_CHUNK_LENGTH * PARAM_SPLITTING_FACTOR];
impl Matrix<PARAM_CHUNK_LENGTH, PARAM_SPLITTING_FACTOR> for SPoly {}

/// Instance Definition:
///
/// This structure represents an instance of the problem on which the security of the signature scheme relies.
///
/// It corresponds to the public key.
///
/// Some member can be pointers when they are generated at each signing and verification from the others members.
pub(crate) struct Instance {
    seed_h: [u8; PARAM_SEED_SIZE],
    y: [u8; PARAM_M_SUB_K],
    matrix_h_prime: HMatrix,
}

/// Solution Definition:
///
/// This structure represents a solution for an instance presented by "instance_t".
///
/// It is part of the secret key of the signature scheme.
///
/// It corresponds to the extended solution, meaning that it contains all the secret values which can be deterministically built from the solution itself and which are inputs of the underlying MPC protocol.
pub(crate) struct Solution {
    s_a: [u8; PARAM_K],
    s_poly: SPoly,
    q_poly: QPoly,
}

fn generate_instance_with_solution(prg: &mut PRG) -> (Instance, Solution) {
    let (q_poly, s_poly, p_poly) = compute_polynomials(prg);

    // Split s as (s_A | s_B)
    let mut s_a = [0_u8; PARAM_K];
    let mut s_b = [0_u8; PARAM_M_SUB_K];
    split_vector_cpy_into_2(&s_poly, &mut s_a, &mut s_b);

    // Sample a seed for matrix H
    let mut seed_H = [0_u8; PARAM_SEED_SIZE];
    prg.sample(&mut seed_H);

    // Build H
    let matrix_H_prime = HMatrix::random(&mut PRG::init(&seed_H, None));

    // Build y = s_B + H' s_A

    // H' s_A
    let mut y: [u8; PARAM_M_SUB_K] = matrix_H_prime.gf256_mul_vector(&s_a);
    // s_B + ...
    for i in 0..y.len() {
        y[i] = gf256_add(y[i], s_b[i]);
    }

    todo!()
}

/// Computes the polynomials S, Q, and P.
/// SampleWitness from the spec.
///
/// This function generates three polynomials: `SPoly`, `QPoly`, and `PPoly` by sampling positions
/// and non-zero coordinates, computing x vectors, and performing GF(256) arithmetic operations.
///
/// # Arguments
///
/// * `prg` - A mutable reference to a pseudorandom generator (PRG).
///
/// # Returns
///
/// A tuple containing the generated polynomials: `(SPoly, QPoly, PPoly)`.
fn compute_polynomials(prg: &mut PRG) -> (QPoly, SPoly, PPoly) {
    // Initiate variables
    let mut positions = [0_u8; PARAM_CHUNK_WEIGHT];
    let mut non_zero_coordinates = [0_u8; PARAM_CHUNK_WEIGHT];

    let mut q_poly: QPoly = [0_u8; PARAM_CHUNK_WEIGHT * PARAM_SPLITTING_FACTOR];
    let mut p_poly: PPoly = [0_u8; PARAM_CHUNK_WEIGHT * PARAM_SPLITTING_FACTOR];
    let mut s_poly: SPoly = [0_u8; PARAM_CHUNK_LENGTH * PARAM_SPLITTING_FACTOR];

    for n_poly in 0..PARAM_SPLITTING_FACTOR {
        // First, compute the non-redundant positions
        _sample_non_redundant(prg, &mut positions);

        // Then, compute the non-zero evaluations of S
        _sample_non_zero(prg, &mut non_zero_coordinates);

        // Compute x vector
        let mut x_vector = [0_u8; PARAM_CHUNK_WEIGHT];
        for i in 0..PARAM_CHUNK_WEIGHT {
            for j in 0..PARAM_CHUNK_WEIGHT {
                x_vector[i] ^= non_zero_coordinates[j] * (positions[j] == i as u8) as u8;
            }
        }

        // Compute Q' polynomial
        let q_coeffs = q_poly.get_row_mut(n_poly);
        for i in 0..PARAM_CHUNK_WEIGHT {
            // Q' <- Q · (X-w_i)
            let wi = positions[i];
            let minus_wi = gf256_sub(0, wi);
            for j in (1..=i).rev() {
                q_coeffs[j] = gf256_add(q_coeffs[j - 1], gf256_mul(minus_wi, q_coeffs[j]));
            }
            q_coeffs[0] = gf256_mul(minus_wi, q_coeffs[0]);
        }

        // Compute S and P
        let mut tmp_poly = [0_u8; PARAM_CHUNK_LENGTH]; // holder of intermediate results for S and P
        for i in 0..PARAM_CHUNK_LENGTH {
            let scalar = gf256_mul(x_vector[i], PRECOMPUTED_LEADING_COEFFICIENTS_OF_LJ_FOR_S[i]);

            // Compute S polynomial
            gf256_remove_one_degree_factor_monic(&mut tmp_poly, &PRECOMPUTED_F_POLY, i as u8);
            gf256_mul_vector_by_scalar(&mut tmp_poly, scalar);
            gf256_add_vector(s_poly.get_row_mut(n_poly), &tmp_poly);

            // Compute P polynomial
            gf256_remove_one_degree_factor_monic(&mut tmp_poly, &q_poly.get_row(n_poly), i as u8);
            gf256_mul_vector_by_scalar(&mut tmp_poly, scalar);
            gf256_add_vector(p_poly.get_row_mut(n_poly), &tmp_poly);
        }
    }
    return (q_poly, s_poly, p_poly);
}

fn _sample_non_redundant(prg: &mut PRG, result: &mut [u8; PARAM_CHUNK_WEIGHT]) {
    let mut i = 0;
    while i < PARAM_CHUNK_WEIGHT {
        prg.sample(&mut result[i..i + 1]);
        if result[i] >= PARAM_CHUNK_LENGTH as u8 {
            continue;
        }
        let is_redundant = (0..i).any(|j| result[j] == result[i]);
        if is_redundant {
            continue;
        }
        i += 1;
    }
}

fn _sample_non_zero(prg: &mut PRG, result: &mut [u8; PARAM_CHUNK_WEIGHT]) {
    for i in 0..PARAM_CHUNK_WEIGHT {
        prg.sample(&mut result[i..i + 1]);
        if result[i] == 0 {
            result[i] += 1;
        }
    }
}

#[cfg(test)]
mod test_helpers {
    use crate::{
        constants::params::{PARAM_CHUNK_WEIGHT, PARAM_SEED_SIZE},
        subroutines::prg::prg::PRG,
    };

    use super::*;

    #[test]
    fn test_sample_non_redundant_positions() {
        let seed = [0u8; PARAM_SEED_SIZE];
        let mut prg = PRG::init(&seed, None);
        let mut positions = [0u8; PARAM_CHUNK_WEIGHT];
        _sample_non_redundant(&mut prg, &mut positions);
        assert_eq!(positions.len(), PARAM_CHUNK_WEIGHT);
        for (i, pos) in positions.iter().enumerate() {
            for (j, pos2) in positions.iter().enumerate() {
                if i != j {
                    assert_ne!(pos, pos2);
                }
            }
        }
    }

    #[test]
    fn test_sample_non_zero_evaluations() {
        let seed = [0u8; PARAM_SEED_SIZE];
        let mut prg = PRG::init(&seed, None);
        let mut evaluations = [0u8; PARAM_CHUNK_WEIGHT];
        _sample_non_zero(&mut prg, &mut evaluations);
        assert_eq!(evaluations.len(), PARAM_CHUNK_WEIGHT);
        for eval in evaluations.iter() {
            assert_ne!(*eval, 0);
        }
    }
}
