use crate::{
    arith::gf256::{
        gf256_arith::{gf256_add, gf256_mul, gf256_sub},
        gf256_poly::gf256_remove_one_degree_factor_monic,
        gf256_vector::{gf256_add_vector, gf256_mul_vector_by_scalar},
    },
    constants::{
        params::{
            PARAM_CHUNK_LENGTH, PARAM_CHUNK_WEIGHT, PARAM_CODE_DIMENSION, PARAM_PUBLIC_KEY_BYTES,
            PARAM_SECRET_KEY_BYTES, PARAM_SPLITTING_FACTOR,
        },
        precomputed::{PRECOMPUTED_F_POLY, PRECOMPUTED_LEADING_COEFFICIENTS_OF_LJ_FOR_S},
    },
    subroutines::prg::prg::PRG,
};

// Key types
pub(crate) type PublicKey = [u8; PARAM_PUBLIC_KEY_BYTES];
pub(crate) type SecretKey = [u8; PARAM_SECRET_KEY_BYTES];

// Polynomial sizes
type QRow = [u8; PARAM_CHUNK_WEIGHT];
type QPoly = [QRow; PARAM_SPLITTING_FACTOR];
type PRow = [u8; PARAM_CHUNK_WEIGHT];
type PPoly = [PRow; PARAM_SPLITTING_FACTOR];
type SRow = [u8; PARAM_CHUNK_LENGTH];
type SPoly = [SRow; PARAM_SPLITTING_FACTOR];
type SA = [u8; PARAM_CODE_DIMENSION];

// Polynomial degrees
const DEGREE_S: u8 = (PARAM_CHUNK_LENGTH - 1) as u8;
const DEGREE_Q: u8 = PARAM_CHUNK_WEIGHT as u8;
const DEGREE_REDUCED_Q: u8 = (PARAM_CHUNK_WEIGHT - 1) as u8;
const DEGREE_F: u8 = (PARAM_CHUNK_LENGTH) as u8;
const DEGREE_P: u8 = (PARAM_CHUNK_WEIGHT - 1) as u8;

/// Solution struct
struct Solution {
    s_A: SA,
    s_poly: SPoly,
    q_poly: QPoly,
}

/// Computes the polynomials S, Q, and P.
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
    let q_poly: QPoly = [[0_u8; PARAM_CHUNK_WEIGHT]; PARAM_SPLITTING_FACTOR];
    let mut p_poly: PPoly = [[0_u8; PARAM_CHUNK_WEIGHT]; PARAM_SPLITTING_FACTOR];
    let mut s_poly: SPoly = [[0_u8; PARAM_CHUNK_LENGTH]; PARAM_SPLITTING_FACTOR];

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

        // Compute Q polynomial
        let mut q_coeffs = q_poly[n_poly];
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
            gf256_add_vector(&mut s_poly[n_poly], &tmp_poly);

            // Compute P polynomial
            gf256_remove_one_degree_factor_monic(&mut tmp_poly, &q_poly[n_poly], i as u8);
            gf256_mul_vector_by_scalar(&mut tmp_poly, scalar);
            gf256_add_vector(&mut p_poly[n_poly], &tmp_poly);
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
    use crate::constants::params::PARAM_SEED_SIZE;

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
