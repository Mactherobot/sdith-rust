use crate::{
    arith::{
        gf256::{
            gf256_arith::{gf256_add, gf256_mul, gf256_sub},
            gf256_poly::gf256_remove_one_degree_factor_monic,
            gf256_vector::{gf256_add_vector, gf256_mul_vector_by_scalar},
        },
        matrices::{Matrix, MatrixGF256Arith},
        vectors::{concat_vectors, vector_copy_into_2},
    },
    constants::{
        params::{
            PARAM_CHUNK_M, PARAM_CHUNK_W, PARAM_K, PARAM_M_SUB_K, PARAM_SALT_SIZE, PARAM_SEED_SIZE,
            PARAM_SPLITTING_FACTOR,
        },
        precomputed::{PRECOMPUTED_F_POLY, PRECOMPUTED_LEADING_COEFFICIENTS_OF_LJ_FOR_S},
        types::Seed,
    },
    subroutines::prg::prg::PRG,
};

// Polynomial types
const WeightPolyLength: usize = PARAM_CHUNK_W * PARAM_SPLITTING_FACTOR;
/// QPoly is a polynomial of degree PARAM_CHUNK_WEIGHT * PARAM_SPLITTING_FACTOR. Split into a matrix of PARAM_SPLITTING_FACTOR rows and PARAM_CHUNK_WEIGHT columns.
type QPPoly = [u8; WeightPolyLength];
impl Matrix<PARAM_SPLITTING_FACTOR, PARAM_CHUNK_W> for QPPoly {}

const LengthPolyLength: usize = PARAM_CHUNK_M * PARAM_SPLITTING_FACTOR;
type SPoly = [u8; LengthPolyLength];
impl Matrix<PARAM_SPLITTING_FACTOR, PARAM_CHUNK_M> for SPoly {}

type HMatrix = [u8; PARAM_M_SUB_K * PARAM_K];

impl MatrixGF256Arith<{ PARAM_M_SUB_K }, { PARAM_K }> for HMatrix {}
impl Matrix<{ PARAM_M_SUB_K }, { PARAM_K }> for HMatrix {}

/// Instance Definition:
///
/// This structure represents an instance of the problem on which the security of the signature scheme relies.
///
/// It corresponds to the public key.
///
/// Some member can be pointers when they are generated at each signing and verification from the others members.
pub(crate) struct Instance {
    pub(crate) seed_h: Seed,
    pub(crate) y: [u8; PARAM_M_SUB_K],
    pub(crate) matrix_h_prime: HMatrix,
}

/// Solution Definition:
///
/// This structure represents a solution for an instance presented by "instance_t".
///
/// It is part of the secret key of the signature scheme.
///
/// It corresponds to the extended solution, meaning that it contains all the secret values which can be deterministically built from the solution itself and which are inputs of the underlying MPC protocol.
pub(crate) struct Solution {
    pub(crate) s_a: [u8; PARAM_K],
    pub(crate) q_poly: QPPoly,
    pub(crate) p_poly: QPPoly,
}

pub type WitnessPlain = [u8; PARAM_M_SUB_K + WeightPolyLength * 2];
impl Solution {
    pub(crate) fn get_witness_plain(&self) -> WitnessPlain {
        concat_vectors(&[&self.s_a, &self.q_poly, &self.p_poly])
    }
}

struct Witness {
    s_a: [u8; PARAM_K],
    s_b: [u8; PARAM_M_SUB_K],
    y: [u8; PARAM_M_SUB_K],
    seed_h: Seed,
    matrix_h_prime: HMatrix,
}

/// Generate a witness for the instance.
///
/// Inputs:
/// - seed_h: Seed used to generate the H matrix.
/// - polynomials: Tuple containing the polynomials Q', S, and P.
///
/// Note that Q' is the truncated version of Q
fn generate_witness(seed_h: Seed, polynomials: (QPPoly, SPoly, QPPoly)) -> Witness {
    let (_q_poly, s_poly, _p_poly) = polynomials;

    // s is pre serialized as (s_A | s_B) due to the nature of SPoly
    // Split s as (s_A | s_B)
    let mut s_a = [0_u8; PARAM_K];
    let mut s_b = [0_u8; PARAM_M_SUB_K];
    vector_copy_into_2(&s_poly, &mut s_a, &mut s_b);

    // Build H
    let matrix_h_prime = HMatrix::gen_random(&mut PRG::init(&seed_h, None));

    // Build y = s_B + H' s_A

    // H' s_A
    let mut y: [u8; PARAM_M_SUB_K] = matrix_h_prime.gf256_mul_vector(&s_a);
    // s_B + ...
    for i in 0..y.len() {
        y[i] = gf256_add(y[i], s_b[i]);
    }

    Witness {
        s_a,
        s_b,
        y,
        seed_h,
        matrix_h_prime,
    }
}

/// Expand a seed into multiple seeds.
/// (seed_1, seed_2, ..., seed_n) = ExpandSeed(seed_root, salt := 0, n)
fn expand_seed<const SEEDS: usize>(seed_root: Seed) -> [Seed; SEEDS] {
    let mut prg = PRG::init(&seed_root, Some(&[0u8; PARAM_SALT_SIZE]));
    let mut seeds = Vec::<Seed>::with_capacity(SEEDS);
    for _ in 0..SEEDS {
        let mut seed = [0u8; PARAM_SEED_SIZE];
        prg.sample(&mut seed);
        seeds.push(seed);
    }
    seeds.try_into().expect("Failed to convert seeds")
}

pub(crate) fn generate_instance_with_solution(seed_root: Seed) -> (Instance, Solution) {
    let [seed_h, seed_witness] = expand_seed(seed_root);
    let polynomials = sample_witness(seed_witness);
    let witness = generate_witness(seed_h, polynomials);

    let instance = Instance {
        seed_h: witness.seed_h,
        y: witness.y,
        matrix_h_prime: witness.matrix_h_prime,
    };

    let solution = Solution {
        s_a: witness.s_a,
        q_poly: polynomials.0,
        p_poly: polynomials.2,
    };

    (instance, solution)
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
/// A tuple containing the generated polynomials: `(Q', S, P)`.
fn sample_witness(seed_witness: Seed) -> (QPPoly, SPoly, QPPoly) {
    let mut prg = PRG::init(&seed_witness, None);

    // Initiate variables
    let mut positions = [0_u8; PARAM_CHUNK_W];

    let mut q_poly: QPPoly = [0_u8; PARAM_CHUNK_W * PARAM_SPLITTING_FACTOR];
    let mut p_poly: QPPoly = [0_u8; PARAM_CHUNK_W * PARAM_SPLITTING_FACTOR];
    let mut s_poly: SPoly = [0_u8; PARAM_CHUNK_M * PARAM_SPLITTING_FACTOR];

    for n_poly in 0..PARAM_SPLITTING_FACTOR {
        // First, compute the non-redundant positions
        _sample_non_redundant(&mut prg, &mut positions);

        // Sample x vector
        let x_vector = _sample_x_with_hamming_weight_w(&mut prg, &positions);

        // Compute truncated Q -> Q' polynomial
        let q_coeffs = q_poly.get_row_mut(n_poly);
        q_coeffs.fill(1);
        for i in 0..PARAM_CHUNK_W {
            // Q' <- Q · (X-w_i)
            let wi = positions[i];
            let minus_wi = gf256_sub(0, wi);
            for j in (1..=i).rev() {
                let val = gf256_add(q_coeffs[j - 1], gf256_mul(minus_wi, q_coeffs[j]));
                q_coeffs[j] = val;
            }
            q_coeffs[0] = gf256_mul(minus_wi, q_coeffs[0]);
        }

        // Compute S and P
        let mut tmp_poly = [0_u8; PARAM_CHUNK_M]; // holder of intermediate results for S and P
        for i in 0..PARAM_CHUNK_M {
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

#[cfg(test)]
mod test_witness {
    use crate::arith::{gf256::gf256_poly::gf256_evaluate_polynomial_horner, hamming_weight};

    use super::*;

    #[test]
    fn test_generate_witness() {
        let seed_test = [0u8; PARAM_SEED_SIZE];
        let polynomials = sample_witness(seed_test);
        let result = generate_witness(seed_test, polynomials);

        let h_prime = result.matrix_h_prime;
        let y = result.y;
        let s_a = result.s_a;
        let s_b_expect = result.s_b;

        // Check s_b = y - H' s_a
        let mut s_b_result: [u8; PARAM_M_SUB_K] = h_prime.gf256_mul_vector(&s_a);
        for i in 0..s_b_result.len() {
            s_b_result[i] = gf256_sub(y[i], s_b_result[i]);
        }
        assert_eq!(s_b_expect, s_b_result);
    }

    #[test]
    fn test_compute_polynomials() {
        let seed = [0u8; PARAM_SEED_SIZE];
        let polynomials = sample_witness(seed);
        let (q_poly, s_poly, p_poly) = polynomials;

        // Check that the polynomials have the correct length
        assert_eq!(q_poly.len(), WeightPolyLength);
        assert_eq!(s_poly.len(), LengthPolyLength);
        assert_eq!(p_poly.len(), WeightPolyLength);

        // Check that the polynomials are not all zeros
        assert!(q_poly.iter().any(|x| x != &0_u8));
        assert!(s_poly.iter().any(|x| x != &0_u8));
        assert!(p_poly.iter().any(|x| x != &0_u8));

        // Test that the evaluation of the s_poly forms a vector of hamming weight PARAM_CHUNK_W
        for d in 0..PARAM_SPLITTING_FACTOR {
            let s_poly_d = s_poly.get_row(d);
            let mut x_vector = [0_u8; PARAM_CHUNK_M];
            for i in 0..PARAM_CHUNK_M {
                x_vector[i] = gf256_evaluate_polynomial_horner(&s_poly_d.to_vec(), i as u8)
            }

            assert_eq!(hamming_weight(&x_vector), PARAM_CHUNK_W as u64);
        }
    }
}

/// Create a set { f_1, ..., f_{PARAM_CHUNK_WEIGHT} }.
fn _sample_non_redundant(prg: &mut PRG, result: &mut [u8; PARAM_CHUNK_W]) {
    let mut i = 0;
    while i < PARAM_CHUNK_W {
        prg.sample(&mut result[i..i + 1]);
        if result[i] >= PARAM_CHUNK_M as u8 {
            continue;
        }
        let is_redundant = (0..i).any(|j| result[j] == result[i]);
        if is_redundant {
            continue;
        }
        i += 1;
    }
}

fn _sample_x_with_hamming_weight_w(
    prg: &mut PRG,
    positions: &[u8; PARAM_CHUNK_W],
) -> [u8; PARAM_CHUNK_M] {
    let mut x_vector = [0_u8; PARAM_CHUNK_M];
    let non_zero_coordinates = prg.sample_non_zero::<PARAM_CHUNK_W>();
    for i in 0..PARAM_CHUNK_M {
        for j in 0..PARAM_CHUNK_W {
            x_vector[i] ^= non_zero_coordinates[j] * (positions[j] == i as u8) as u8;
        }
    }

    x_vector
}

#[cfg(test)]
mod test_helpers {
    use crate::{
        arith::hamming_weight, constants::params::{PARAM_CHUNK_W, PARAM_SEED_SIZE, PARAM_W}, subroutines::prg::prg::PRG
    };

    use super::*;

    #[test]
    fn test_sample_non_redundant_positions() {
        let seed = [0u8; PARAM_SEED_SIZE];
        let mut prg = PRG::init(&seed, None);
        let mut positions = [0u8; PARAM_CHUNK_W];
        _sample_non_redundant(&mut prg, &mut positions);

        assert_eq!(positions.len(), PARAM_CHUNK_W);
        assert!(positions.iter().any(|x| x != &0_u8));

        for (i, pos) in positions.iter().enumerate() {
            for (j, pos2) in positions.iter().enumerate() {
                if i != j {
                    assert_ne!(pos, pos2);
                }
            }
        }
    }

    #[test]
    fn test_sample_x_with_hamming_weight_w() {
        for i in 0..255 {
            let seed = [i as u8; PARAM_SEED_SIZE];
            let mut prg = PRG::init(&seed, None);
            let mut positions = [0u8; PARAM_CHUNK_W];
            _sample_non_redundant(&mut prg, &mut positions);
            let x_vector = _sample_x_with_hamming_weight_w(&mut prg, &positions);
            assert_eq!(x_vector.len(), PARAM_CHUNK_M);
            assert!(
                hamming_weight(&x_vector) <= PARAM_W as u64,
                "x_vector weight {}, exceeds {}",
                hamming_weight(&x_vector),
                PARAM_W
            );
        }
    }
}
