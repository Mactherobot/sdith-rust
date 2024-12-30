//! # Witness generation
//!
//! The SDitH protocol is based on creating a Zero-Knowlegde proof and turning it into a Signature Scheme using the Fiat-Shamir Heuristic.
//!
//! Witness generation is the process of creating the polynomials `Q`, `S`, and `P` to prove the relation `S * Q = P * F`.
//! This, in turn, is used to generate the [`crate::keygen::PublicKey`] and [`crate::keygen::SecretKey`].
//!
//! The instance is split into [`PARAM_SPLITTING_FACTOR`] according to a variant of the SD problem in the _d-split syndrome decoding problem_.

use crate::{
    constants::{
        params::{
            PARAM_CHUNK_M, PARAM_CHUNK_W, PARAM_K, PARAM_M, PARAM_M_SUB_K, PARAM_SALT_SIZE,
            PARAM_SEED_SIZE, PARAM_SPLITTING_FACTOR, PRECOMPUTED_F_POLY,
            PRECOMPUTED_LAGRANGE_INTERPOLATION_WEIGHTS,
        },
        types::Seed,
    },
    subroutines::arith::{
        gf256::{
            gf256_matrices::{gen_hmatrix, mul_hmatrix_vector, HPrimeMatrix},
            gf256_poly::gf256_monic_polynomial_division,
            gf256_vector::{gf256_add_vector, gf256_mul_vector_by_scalar},
        },
        FieldArith as _,
    },
    subroutines::prg::PRG,
    utils::marshalling::Marshalling,
};

// Polynomial types

/// QPoly is a polynomial of degree [`PARAM_CHUNK_W`].
/// Split into a matrix of PARAM_SPLITTING_FACTOR rows and PARAM_CHUNK_WEIGHT columns.
pub type QPoly = [[u8; PARAM_CHUNK_W]; PARAM_SPLITTING_FACTOR];

/// Completed [`QPoly`] with leading coefficient.
pub type QPolyComplete = [[u8; PARAM_CHUNK_W + 1]; PARAM_SPLITTING_FACTOR];

/// P polynomial is a polynomial of degree [`PARAM_CHUNK_W`]
pub type PPoly = [[u8; PARAM_CHUNK_W]; PARAM_SPLITTING_FACTOR];

/// SPoly is a polynomial of degree [`PARAM_CHUNK_M`]
pub type SPoly = [[u8; PARAM_CHUNK_M]; PARAM_SPLITTING_FACTOR];

/// Syndrom Decoding (SD) Instance struct
///
/// This structure represents an instance of the SD problem on which the security of the signature scheme relies.
///
/// It corresponds to the public key.
///
/// Some member can be pointers when they are generated at each signing and verification from the others members.
pub struct Instance {
    /// Seed used to generate the H' matrix.
    pub seed_h: Seed,
    /// y = H' * x
    pub y: [u8; PARAM_M_SUB_K],
    /// H' matrix
    pub h_prime: HPrimeMatrix,
}

/// Solution Definition: (s_a, Q', P)
///
/// This structure represents a solution for an instance presented by "instance_t".
///
/// It is part of the secret key of the signature scheme.
///
/// It corresponds to the extended solution, meaning that it contains all the secret values
/// which can be deterministically built from the solution itself and which are inputs of the underlying MPC protocol.
///
/// Given the SD polynomial relation: S * Q = P * F
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Solution {
    /// share of the S polynomial. Calculate `s_b = y + H' * s_a` and `s = s_a || s_b`
    pub s_a: [u8; PARAM_K],
    /// Computed witness polynomial Q
    pub q_poly: QPoly,
    /// Computed witness polynomial P
    pub p_poly: PPoly,
}

/// k + 2w
pub const SOLUTION_PLAIN_SIZE: usize = PARAM_K + (PARAM_CHUNK_W * PARAM_SPLITTING_FACTOR * 2);

impl Marshalling<[u8; SOLUTION_PLAIN_SIZE]> for Solution {
    fn serialise(&self) -> [u8; SOLUTION_PLAIN_SIZE] {
        let mut serialised = [0u8; PARAM_K + PARAM_CHUNK_W * PARAM_SPLITTING_FACTOR * 2];
        serialised[..PARAM_K].copy_from_slice(&self.s_a);
        for i in 0..PARAM_SPLITTING_FACTOR {
            serialised[PARAM_K + i * PARAM_CHUNK_W..PARAM_K + (i + 1) * PARAM_CHUNK_W]
                .copy_from_slice(&self.q_poly[i]);
        }
        for i in 0..PARAM_SPLITTING_FACTOR {
            serialised[PARAM_K + PARAM_CHUNK_W * PARAM_SPLITTING_FACTOR + i * PARAM_CHUNK_W
                ..PARAM_K + PARAM_CHUNK_W * PARAM_SPLITTING_FACTOR + (i + 1) * PARAM_CHUNK_W]
                .copy_from_slice(&self.p_poly[i]);
        }
        serialised
    }

    fn parse(solution_plain: &[u8; SOLUTION_PLAIN_SIZE]) -> Result<Self, String> {
        let mut s_a = [0u8; PARAM_K];
        s_a.copy_from_slice(&solution_plain[..PARAM_K]);

        let mut q_poly = [[0u8; PARAM_CHUNK_W]; PARAM_SPLITTING_FACTOR];
        for i in 0..PARAM_SPLITTING_FACTOR {
            q_poly[i].copy_from_slice(
                &solution_plain[PARAM_K + i * PARAM_CHUNK_W..PARAM_K + (i + 1) * PARAM_CHUNK_W],
            );
        }

        let mut p_poly = [[0u8; PARAM_CHUNK_W]; PARAM_SPLITTING_FACTOR];
        for i in 0..PARAM_SPLITTING_FACTOR {
            p_poly[i].copy_from_slice(
                &solution_plain[PARAM_K + PARAM_CHUNK_W * PARAM_SPLITTING_FACTOR + i * PARAM_CHUNK_W
                    ..PARAM_K + PARAM_CHUNK_W * PARAM_SPLITTING_FACTOR + (i + 1) * PARAM_CHUNK_W],
            );
        }

        Ok(Solution {
            s_a,
            q_poly,
            p_poly,
        })
    }
}

/// Zero-Knowledge Proof Witness
///
/// This structure represents the witness of the Zero-Knowledge proof for the SD relation `S * Q = P * F`.
pub struct Witness {
    /// The first share of [`SPoly`], for the SD relation `S * Q = P * F`.
    pub s_a: [u8; PARAM_K],
    /// The second share of [`SPoly`], for the SD relation `S * Q = P * F`.
    ///
    /// This part is only used for testing purposes.
    #[cfg(test)]
    s_b: [u8; PARAM_M_SUB_K],
    /// The value `y = s_b + H' * s_a`.
    pub y: [u8; PARAM_M_SUB_K],
    /// H' matrix
    pub h_prime: HPrimeMatrix,
    /// Seed used to generate the H' matrix.
    pub seed_h: Seed,
    /// Computed witness polynomial Q
    pub q_poly: QPoly,
    /// Computed witness polynomial P
    pub p_poly: PPoly,
}

/// Generate a witness for the instance.
///
/// Inputs:
/// - seed_h: Seed used to generate the H matrix.
/// - polynomials: Tuple containing the polynomials Q', S, and P.
pub fn generate_witness(seed_h: Seed, polynomials: (QPoly, SPoly, PPoly)) -> Witness {
    let (q_poly, s_poly, p_poly) = polynomials;

    // s is pre serialized as (s_A | s_B) due to the nature of SPoly
    // Split s as (s_A | s_B)
    let s_flat = s_poly.as_flattened();
    let s_a: [u8; PARAM_K] = s_flat[..PARAM_K].try_into().expect("Failed to convert s_a");
    let s_b: [u8; PARAM_M_SUB_K] = s_flat[PARAM_K..].try_into().expect("Failed to convert s_b");

    // Generate H
    let h_prime = gen_hmatrix(seed_h);

    // Compute y = s_b + H' s_a
    let y = compute_y(&s_b, &s_a, &h_prime);

    Witness {
        s_a,
        #[cfg(test)]
        s_b,
        y,
        seed_h,
        h_prime,
        q_poly,
        p_poly,
    }
}

/// Compute y = s_b + H' s_a
pub fn compute_y(
    s_b: &[u8; PARAM_M_SUB_K],
    s_a: &[u8; PARAM_K],
    h_prime: &HPrimeMatrix,
) -> [u8; PARAM_M_SUB_K] {
    let mut y = s_b.clone();
    mul_hmatrix_vector(&mut y, &h_prime, s_a);
    y
}

/// Expand a seed into multiple seeds.
/// (seed_1, seed_2, ..., seed_n) = ExpandSeed(seed_root, salt := 0, n)
pub fn expand_seed<const SEEDS: usize>(seed_root: Seed) -> [Seed; SEEDS] {
    let mut prg = PRG::init(&seed_root, Some(&[0u8; PARAM_SALT_SIZE]));
    let mut seeds = Vec::<Seed>::with_capacity(SEEDS);
    for _ in 0..SEEDS {
        let mut seed = [0u8; PARAM_SEED_SIZE];
        prg.sample_field_fq_elements(&mut seed);
        seeds.push(seed);
    }
    seeds.try_into().expect("Failed to convert seeds")
}

/// Generate an instance and a solution for the SD problem given a master [`Seed`].
pub fn generate_instance_with_solution(master_seed: Seed) -> (Instance, Solution) {
    let mut prg = PRG::init(&master_seed, None);

    let (q, s, p, _) = sample_polynomial_relation(&mut prg);

    // Sample a seed for matrix H
    let seed_h = prg.sample_seed();
    let witness = generate_witness(seed_h, (q, s, p));

    let instance = Instance {
        seed_h: witness.seed_h,
        y: witness.y,
        h_prime: witness.h_prime,
    };

    let solution = Solution {
        s_a: witness.s_a,
        q_poly: q,
        p_poly: p,
    };

    (instance, solution)
}

/// Samples the x vector and computes the polynomials S, Q, and P.
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
/// A tuple containing the generated polynomials: `(Q', S, P, x)`.
/// `x` is only used for testing purposes.
pub fn sample_polynomial_relation(
    prg: &mut PRG,
) -> (
    QPoly,
    SPoly,
    PPoly,
    [[u8; PARAM_CHUNK_M]; PARAM_SPLITTING_FACTOR],
) {
    // Initiate variables
    let mut q_poly: QPoly = [[0_u8; PARAM_CHUNK_W]; PARAM_SPLITTING_FACTOR];
    let mut p_poly: PPoly = [[0_u8; PARAM_CHUNK_W]; PARAM_SPLITTING_FACTOR];
    let mut s_poly: SPoly = [[0_u8; PARAM_CHUNK_M]; PARAM_SPLITTING_FACTOR];

    let mut x_vectors: [[u8; PARAM_CHUNK_M]; PARAM_SPLITTING_FACTOR] =
        [[0; PARAM_CHUNK_M]; PARAM_SPLITTING_FACTOR];

    // holder of intermediate results for S and P
    let mut tmp_poly = [0_u8; PARAM_CHUNK_M];

    for n_poly in 0..PARAM_SPLITTING_FACTOR {
        // Sample x vector
        let (x_vector, positions) = sample_x_chunk(prg);
        x_vectors[n_poly] = x_vector;

        // Compute Q
        q_poly[n_poly] = compute_q_prime_chunk(&positions);

        // Compute S and P
        for i in 0..PARAM_CHUNK_M {
            let scalar = x_vector[i].field_mul(PRECOMPUTED_LAGRANGE_INTERPOLATION_WEIGHTS[i]); // Multiply langrangian weight by x_i

            // Compute S polynomial
            gf256_monic_polynomial_division(
                &mut tmp_poly,
                &PRECOMPUTED_F_POLY,
                PARAM_CHUNK_M,
                i as u8,
            ); // Compute quotient polynomial F(X) / (X - alpha_i)
            gf256_mul_vector_by_scalar(&mut tmp_poly, scalar); // Multiply by langrangian weight
            gf256_add_vector(&mut s_poly[n_poly], &tmp_poly); // Transfer to s_poly

            // Compute P polynomial
            gf256_monic_polynomial_division(&mut tmp_poly, &q_poly[n_poly], PARAM_CHUNK_W, i as u8); // Compute the
            gf256_mul_vector_by_scalar(&mut tmp_poly, scalar);
            gf256_add_vector(&mut p_poly[n_poly], &tmp_poly);
        }
    }
    return (q_poly, s_poly, p_poly, x_vectors);
}

#[cfg(test)]
mod test_witness {

    /// Calculate hamming weight of the given vector, which is the number of non-zero elements.
    fn hamming_weight_vector(x: &[u8]) -> u64 {
        x.iter().fold(0, |a, b| a + (*b != 0) as u64)
    }

    use crate::subroutines::arith::gf256::gf256_poly::{
        gf256_evaluate_polynomial_horner, gf256_evaluate_polynomial_horner_monic,
    };

    use super::*;

    #[test]
    fn test_generate_witness() {
        let seed_test = [0u8; PARAM_SEED_SIZE];
        let mut prg = PRG::init(&seed_test, None);
        let (q, s, p, ..) = sample_polynomial_relation(&mut prg);
        let result = generate_witness(seed_test, (q, s, p));

        let h_prime = result.h_prime;
        let s_a = result.s_a;
        let s_b_expect = result.s_b;

        // Check s_b = y - H' s_a
        let mut s_b = [0u8; PARAM_M_SUB_K];
        mul_hmatrix_vector(&mut s_b, &h_prime, &s_a);
        gf256_add_vector(&mut s_b, &result.y);

        assert_eq!(s_b, s_b_expect);
    }

    #[test]
    fn test_compute_polynomials() {
        let seed = [0u8; PARAM_SEED_SIZE];
        let mut prg = PRG::init(&seed, None);
        let (q_poly, s_poly, p_poly, x_vectors) = sample_polynomial_relation(&mut prg);

        assert_eq!(q_poly.len(), PARAM_SPLITTING_FACTOR);
        assert_eq!(s_poly.len(), PARAM_SPLITTING_FACTOR);
        assert_eq!(p_poly.len(), PARAM_SPLITTING_FACTOR);

        // Test that the evaluation of the s_poly forms a vector of hamming weight PARAM_CHUNK_W
        for d in 0..PARAM_SPLITTING_FACTOR {
            let s_poly_d = s_poly[d];
            let q_poly_d = q_poly[d];
            let p_poly_d = p_poly[d];
            let x_vector_d = &x_vectors[d];

            // Check that the polynomials have the correct length
            assert_eq!(q_poly_d.len(), PARAM_CHUNK_W);
            assert_eq!(s_poly_d.len(), PARAM_CHUNK_M);
            assert_eq!(p_poly_d.len(), PARAM_CHUNK_W);

            // Check that the polynomials are not all zeros
            assert!(q_poly_d.iter().any(|x| x != &0_u8));
            assert!(s_poly_d.iter().any(|x| x != &0_u8));
            assert!(p_poly_d.iter().any(|x| x != &0_u8));

            // Test that the hamming weight of the x vector is PARAM_CHUNK_W
            assert_eq!(hamming_weight_vector(x_vector_d), PARAM_CHUNK_W as u64);

            for i in 0..PARAM_CHUNK_M {
                // Test that S(fi) = xi for all xi
                assert_eq!(
                    gf256_evaluate_polynomial_horner(&s_poly_d, i as u8),
                    x_vector_d[i]
                );

                // Test that Q(fi) = 0 for all xi != 0
                if x_vector_d[i] != 0 {
                    assert_eq!(
                        gf256_evaluate_polynomial_horner_monic(&q_poly_d, i as u8),
                        0_u8
                    );
                }
            }

            // Test that S · Q = P · F
            let mut s_q = [0_u8; PARAM_CHUNK_M];
            let mut p_f = [0_u8; PARAM_CHUNK_M];

            // Compute S · Q and P · F
            for i in 0..PARAM_CHUNK_M {
                s_q[i] = gf256_evaluate_polynomial_horner(&s_poly_d, i as u8)
                    .field_mul(gf256_evaluate_polynomial_horner_monic(&q_poly_d, i as u8));
                p_f[i] = gf256_evaluate_polynomial_horner(&p_poly_d, i as u8).field_mul(
                    gf256_evaluate_polynomial_horner(&PRECOMPUTED_F_POLY, i as u8),
                );
            }

            assert_eq!(s_q, p_f);
        }
    }
}

/// Create a set of length PARAM_CHUNK_W of positions in the range [0, PARAM_CHUNK_M).
/// These are the non-zero coordinates of the x vector.
fn sample_non_zero_x_positions(prg: &mut PRG) -> [u8; PARAM_CHUNK_W] {
    let mut positions = [0_u8; PARAM_CHUNK_W];
    let mut i = 0;
    while i < PARAM_CHUNK_W {
        prg.sample_field_fq_elements(&mut positions[i..i + 1]);
        if positions[i] >= PARAM_CHUNK_M as u8 {
            continue;
        }
        let is_redundant = (0..i).any(|j| positions[j] == positions[i]);
        if is_redundant {
            continue;
        }
        i += 1;
    }
    positions
}

/// Create a vector x with hamming weight PARAM_CHUNK_WEIGHT.
/// Returns x_vector and the non-zero positions.
pub fn sample_x_chunk(prg: &mut PRG) -> ([u8; PARAM_CHUNK_M], [u8; PARAM_CHUNK_W]) {
    let positions = sample_non_zero_x_positions(prg);
    let mut x_vector = [0_u8; PARAM_CHUNK_M];

    let mut non_zero_elements = [1u8; PARAM_CHUNK_W];
    prg.sample_field_fq_non_zero(&mut non_zero_elements);

    for (j, pos) in positions.iter().enumerate() {
        x_vector[*pos as usize] ^= non_zero_elements[j]; // Transfor random values to x at hamming weight positions
    }

    (x_vector, positions)
}

/// Compute the polynomial Q' from the non-zero positions, but in reverse order, i.e. [3,2,1] represents x^3 + 2x^2 + 3x.
/// Essentially this computes the monic polynomial from the roots. I.e. Q(root) = 0.
/// Returns truncated polynomial to PARAM_CHUNK_W. (removing the leading coefficient 1)
fn compute_q_prime_chunk<const N: usize>(positions: &[u8; N]) -> [u8; N] {
    let mut coeffs = [1u8; N];

    for (i, fi) in positions.iter().enumerate() {
        for j in (1..=i).rev() {
            coeffs[j] = coeffs[j - 1].field_add(coeffs[j].field_mul(*fi));
        }
        coeffs[0] = coeffs[0].field_mul(*fi);
    }
    coeffs
}

/// Completes the q polynomial by inserting the leading coefficient at the beginning of each d-split
pub fn complete_q(q_poly: QPoly, leading: u8) -> QPolyComplete {
    let mut q_poly_out = [[0_u8; PARAM_CHUNK_W + 1]; PARAM_SPLITTING_FACTOR];

    for d in 0..PARAM_SPLITTING_FACTOR {
        for i in 0..PARAM_CHUNK_W {
            q_poly_out[d][i] = q_poly[d][i];
        }
        q_poly_out[d][PARAM_CHUNK_W] = leading;
    }

    q_poly_out
}

/// Generate `s = (s_a | s_b)` from `s_a`, `H'` and `y`. Optionally add `y` to `H's_a` to get `s_b`.
pub fn compute_s(
    s_a: &[u8; PARAM_K],
    h_prime: &HPrimeMatrix,
    y: Option<&[u8; PARAM_M_SUB_K]>,
) -> Result<[u8; PARAM_M], String> {
    // (s_a | s_b)
    let mut s = [0u8; PARAM_M];

    // Set s_a
    gf256_add_vector(&mut s[..PARAM_K], s_a);

    // If has_offset, compute s_b = y + H's_a
    if let Some(y) = y {
        gf256_add_vector(&mut s[PARAM_K..], y);
    }

    // Add y = s_b - H's_a to the s_b side
    mul_hmatrix_vector(&mut s[PARAM_K..], h_prime, s_a);
    // Check that the h_prime * s_a is not equal to y (if provided)
    // This can happen if the h_prime is the zero matrix or if the s_a is the zero vector
    // And if we want a correct SD instance we need to ensure that the s_b is not equal to y
    if let Some(y) = y {
        if s[PARAM_K..] == *y {
            return Err("s_b is equal to y".to_string());
        }
    }

    Ok(s)
}

/// Compute SPoly from s = Parse((s, F_q^(m/d), F_q^(m/d),...)
pub fn compute_s_poly(s: [u8; PARAM_M]) -> SPoly {
    let mut s_poly: SPoly = [[0u8; PARAM_CHUNK_M]; PARAM_SPLITTING_FACTOR];
    for (i, s_poly_d) in s.chunks(PARAM_CHUNK_M).enumerate() {
        s_poly[i] = s_poly_d.try_into().expect("Invalid chunk size");
    }

    s_poly
}

#[cfg(test)]
mod test_helpers {

    /// Calculate hamming weight of the given vector, which is the number of non-zero elements.
    fn hamming_weight_vector(x: &[u8]) -> u64 {
        x.iter().fold(0, |a, b| a + (*b != 0) as u64)
    }

    use crate::{
        constants::params::{PARAM_CHUNK_W, PARAM_SEED_SIZE, PARAM_W},
        subroutines::{
            arith::gf256::gf256_poly::{
                gf256_evaluate_polynomial_horner, gf256_evaluate_polynomial_horner_monic,
            },
            prg::PRG,
        },
        utils::marshalling::test_marhalling,
    };

    use super::*;

    fn get_solution(seed: Seed) -> Solution {
        let mut prg = PRG::init(&seed, None);
        let (q_poly, s_poly, p_poly, ..) = sample_polynomial_relation(&mut prg);
        let witness = generate_witness(seed, (q_poly, s_poly, p_poly));
        Solution {
            s_a: witness.s_a,
            q_poly: witness.q_poly,
            p_poly: witness.p_poly,
        }
    }

    #[test]
    fn test_positions() {
        let seed = [0u8; PARAM_SEED_SIZE];
        let mut prg = PRG::init(&seed, None);
        let positions = sample_non_zero_x_positions(&mut prg);

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
    fn test_sample_x() {
        for i in 0..255 {
            let seed = [i as u8; PARAM_SEED_SIZE];
            let mut prg = PRG::init(&seed, None);
            let (x_vector, _positions) = sample_x_chunk(&mut prg);

            assert_eq!(x_vector.len(), PARAM_CHUNK_M);
            assert!(
                hamming_weight_vector(&x_vector) <= PARAM_W as u64,
                "x_vector weight {}, exceeds {}",
                hamming_weight_vector(&x_vector),
                PARAM_W
            );

            for pos in _positions.iter() {
                assert_ne!(x_vector[*pos as usize], 0);
            }
        }
    }

    #[test]
    fn test_compute_q_chunk_base() {
        let positions = [1, 2];
        let q = compute_q_prime_chunk(&positions);
        for x in positions.iter() {
            assert_eq!(gf256_evaluate_polynomial_horner_monic(&q, *x), 0);
        }
    }

    #[test]
    fn test_compute_q_chunk_with_sample() {
        let positions = sample_x_chunk(&mut PRG::init(&[0u8; PARAM_SEED_SIZE], None)).1;
        let q = compute_q_prime_chunk(&positions);
        for pos in positions.iter() {
            assert_eq!(gf256_evaluate_polynomial_horner_monic(&q, *pos), 0);
        }
    }

    #[test]
    fn test_compute_s() {
        let seed = [0u8; PARAM_SEED_SIZE];
        let mut prg = PRG::init(&seed, None);
        let (q, s, p, ..) = sample_polynomial_relation(&mut prg);
        let witness = generate_witness(seed, (q, s, p));
        let y = witness.y;
        let h_prime = witness.h_prime;
        let s_a = witness.s_a;
        let s = compute_s(&s_a, &h_prime, Some(&y)).unwrap();

        assert_eq!(s.len(), PARAM_M);
        assert_eq!(s[..PARAM_K], witness.s_a);
        assert_eq!(s[PARAM_K..], witness.s_b);
    }

    #[test]
    fn test_complete_q() {
        let seed = [0u8; PARAM_SEED_SIZE];
        let mut prg = PRG::init(&seed, None);
        let (q_poly, ..) = sample_polynomial_relation(&mut prg);
        let q_complete = complete_q(q_poly, 1);

        for (i, q_comp) in q_complete.iter().enumerate() {
            assert_eq!(q_comp.last(), Some(&1u8));

            // Check that this is the same as using the monic polynomial evaluation on the original q_poly
            assert_eq!(
                gf256_evaluate_polynomial_horner_monic(&q_poly[i], 1),
                gf256_evaluate_polynomial_horner(q_comp, 1)
            )
        }
    }

    #[test]
    fn test_marhalling_solution() {
        let seed1 = [0u8; PARAM_SEED_SIZE];
        let seed2 = [1u8; PARAM_SEED_SIZE];
        let solution1 = get_solution(seed1);
        let solution2 = get_solution(seed2);

        test_marhalling(solution1, solution2);
    }
}
