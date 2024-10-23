use crate::{
    arith::{
        gf256::{
            gf256_poly::gf256_remove_one_degree_factor_monic,
            gf256_vector::{gf256_add_vector, gf256_mul_vector_by_scalar},
            FieldArith,
        },
        matrices::MatrixGF256,
    },
    constants::{
        f_poly::compute_vanishing_polynomial,
        params::{
            PARAM_CHUNK_M, PARAM_CHUNK_W, PARAM_K, PARAM_M, PARAM_M_SUB_K, PARAM_SALT_SIZE,
            PARAM_SEED_SIZE, PARAM_SPLITTING_FACTOR,
        },
        precomputed::{PRECOMPUTED_F_POLY, PRECOMPUTED_LEADING_COEFFICIENTS_OF_LJ_FOR_S},
        types::Seed,
    },
    subroutines::prg::prg::PRG,
};

// Polynomial types
/// QPoly is a polynomial of degree PARAM_CHUNK_WEIGHT * PARAM_SPLITTING_FACTOR. Split into a matrix of PARAM_SPLITTING_FACTOR rows and PARAM_CHUNK_WEIGHT columns.
pub(crate) type QPoly = [[u8; PARAM_CHUNK_W]; PARAM_SPLITTING_FACTOR];
pub(crate) type QPolyComplete = [[u8; PARAM_CHUNK_W + 1]; PARAM_SPLITTING_FACTOR];
type PPoly = [[u8; PARAM_CHUNK_W]; PARAM_SPLITTING_FACTOR];
pub(crate) type SPoly = [[u8; PARAM_CHUNK_M]; PARAM_SPLITTING_FACTOR];

pub(crate) type HPrimeMatrix = [[u8; PARAM_K]; PARAM_M_SUB_K];
impl MatrixGF256<{ PARAM_M_SUB_K }, { PARAM_K }> for HPrimeMatrix {}

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
    pub(crate) h_prime: HPrimeMatrix,
}

/// Solution Definition: (s_a, Q', P)
///
/// This structure represents a solution for an instance presented by "instance_t".
///
/// It is part of the secret key of the signature scheme.
///
/// It corresponds to the extended solution, meaning that it contains all the secret values which can be deterministically built from the solution itself and which are inputs of the underlying MPC protocol.
#[derive(Clone, Copy)]
pub(crate) struct Solution {
    pub(crate) s_a: [u8; PARAM_K],
    pub(crate) q_poly: QPoly,
    pub(crate) p_poly: PPoly,
}

/// k + 2w
pub(crate) const SOLUTION_PLAIN_SIZE: usize =
    PARAM_K + (PARAM_CHUNK_W * PARAM_SPLITTING_FACTOR * 2);

impl Solution {
    pub(crate) fn serialise(&self) -> [u8; SOLUTION_PLAIN_SIZE] {
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

    pub(crate) fn parse(solution_plain: [u8; SOLUTION_PLAIN_SIZE]) -> Self {
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
        Solution {
            s_a,
            q_poly,
            p_poly,
        }
    }
}

pub(crate) struct Witness {
    pub(crate) s_a: [u8; PARAM_K],
    /// s_b is only used for testing purposes
    s_b: [u8; PARAM_M_SUB_K],
    pub(crate) y: [u8; PARAM_M_SUB_K],
    pub(crate) h_prime: HPrimeMatrix,
    pub(crate) seed_h: Seed,
    pub(crate) q_poly: QPoly,
    pub(crate) p_poly: PPoly,
}

/// Generate a witness for the instance.
///
/// Inputs:
/// - seed_h: Seed used to generate the H matrix.
/// - polynomials: Tuple containing the polynomials Q', S, and P.
pub(crate) fn generate_witness(seed_h: Seed, polynomials: (QPoly, SPoly, PPoly)) -> Witness {
    let (_q_poly, s_poly, _p_poly) = polynomials;

    // s is pre serialized as (s_A | s_B) due to the nature of SPoly
    // Split s as (s_A | s_B)
    let s_flat = s_poly.as_flattened();
    let s_a: [u8; PARAM_K] = s_flat[..PARAM_K].try_into().expect("Failed to convert s_a");
    let s_b: [u8; PARAM_M_SUB_K] = s_flat[PARAM_K..].try_into().expect("Failed to convert s_b");

    // Build H
    let h_prime = HPrimeMatrix::gen_random(&mut PRG::init(&seed_h, None));

    // Build y = s_B + H' s_A

    // H' s_A
    let mut y: [u8; PARAM_M_SUB_K] = h_prime.gf256_mul_vector(&s_a);

    // s_B + ...
    for i in 0..y.len() {
        y[i] = y[i].field_add(s_b[i]);
    }

    Witness {
        s_a,
        s_b,
        y,
        seed_h,
        h_prime,
        q_poly: _q_poly,
        p_poly: _p_poly,
    }
}

/// Expand a seed into multiple seeds.
/// (seed_1, seed_2, ..., seed_n) = ExpandSeed(seed_root, salt := 0, n)
pub(crate) fn expand_seed<const SEEDS: usize>(seed_root: Seed) -> [Seed; SEEDS] {
    let mut prg = PRG::init(&seed_root, Some(&[0u8; PARAM_SALT_SIZE]));
    let mut seeds = Vec::<Seed>::with_capacity(SEEDS);
    for _ in 0..SEEDS {
        let mut seed = [0u8; PARAM_SEED_SIZE];
        prg.sample_field_fq_elements(&mut seed);
        seeds.push(seed);
    }
    seeds.try_into().expect("Failed to convert seeds")
}

pub(crate) fn generate_instance_with_solution(seed_root: Seed) -> (Instance, Solution) {
    let [seed_h, seed_witness] = expand_seed(seed_root);
    let (q, s, p, _x) = sample_witness(seed_witness);
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
/// A tuple containing the generated polynomials: `(Q', S, P, x)`.
/// `x` is only used for testing purposes.
pub(crate) fn sample_witness(
    seed_witness: Seed,
) -> (
    QPoly,
    SPoly,
    PPoly,
    [[u8; PARAM_CHUNK_M]; PARAM_SPLITTING_FACTOR],
) {
    let mut prg = PRG::init(&seed_witness, None);

    // Initiate variables
    let mut q_poly: QPoly = [[0_u8; PARAM_CHUNK_W]; PARAM_SPLITTING_FACTOR];
    let mut p_poly: PPoly = [[0_u8; PARAM_CHUNK_W]; PARAM_SPLITTING_FACTOR];
    let mut s_poly: SPoly = [[0_u8; PARAM_CHUNK_M]; PARAM_SPLITTING_FACTOR];

    let mut x_vectors: [[u8; PARAM_CHUNK_M]; PARAM_SPLITTING_FACTOR] =
        [[0; PARAM_CHUNK_M]; PARAM_SPLITTING_FACTOR];

    for n_poly in 0..PARAM_SPLITTING_FACTOR {
        // Sample x vector
        let (x_vector, positions) = sample_x(&mut prg);
        x_vectors[n_poly] = x_vector;

        // Compute Q
        q_poly[n_poly] = compute_q_prime_chunk(&positions);

        // Compute S and P
        let mut tmp_poly = [0_u8; PARAM_CHUNK_M]; // holder of intermediate results for S and P
        for i in 0..PARAM_CHUNK_M {
            let scalar = x_vector[i].field_mul(PRECOMPUTED_LEADING_COEFFICIENTS_OF_LJ_FOR_S[i]);

            // Compute S polynomial
            gf256_remove_one_degree_factor_monic(
                &mut tmp_poly,
                &PRECOMPUTED_F_POLY,
                PARAM_M,
                i as u8,
            );
            gf256_mul_vector_by_scalar(&mut tmp_poly, scalar);
            gf256_add_vector(&mut s_poly[n_poly], &tmp_poly);

            // Compute P polynomial
            gf256_remove_one_degree_factor_monic(
                &mut tmp_poly,
                &q_poly[n_poly],
                PARAM_CHUNK_W,
                i as u8,
            );
            gf256_mul_vector_by_scalar(&mut tmp_poly, scalar);
            gf256_add_vector(&mut p_poly[n_poly], &tmp_poly);
        }
    }
    return (q_poly, s_poly, p_poly, x_vectors);
}

#[cfg(test)]
mod test_witness {
    use crate::arith::{
        gf256::{
            gf256_poly::{
                gf256_evaluate_polynomial_horner, gf256_evaluate_polynomial_horner_monic,
            },
            FieldArith,
        },
        hamming_weight_vector,
    };

    use super::*;

    #[test]
    fn test_generate_witness() {
        let seed_test = [0u8; PARAM_SEED_SIZE];
        let (q, s, p, ..) = sample_witness(seed_test);
        let result = generate_witness(seed_test, (q, s, p));

        let h_prime = result.h_prime;
        let y = result.y;
        let s_a = result.s_a;
        let s_b_expect = result.s_b;

        // Check s_b = y - H' s_a
        let mut s_b_result: [u8; PARAM_M_SUB_K] = h_prime.gf256_mul_vector(&s_a);
        for i in 0..s_b_result.len() {
            s_b_result[i].field_sub_mut(y[i]);
        }
        assert_eq!(s_b_expect, s_b_result);
    }

    #[test]
    fn test_compute_polynomials() {
        let seed = [0u8; PARAM_SEED_SIZE];
        let (q_poly, s_poly, p_poly, x_vectors) = sample_witness(seed);

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
                // TODO: This currently does not work. Seems it might not be Q, but Q'? However, we dont know as of yet
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

    #[test]
    fn test_serialise() {
        let seed = [0u8; PARAM_SEED_SIZE];
        let (q_poly, s_poly, p_poly, ..) = sample_witness(seed);
        let witness = generate_witness(seed, (q_poly, s_poly, p_poly));
        let solution = Solution {
            s_a: witness.s_a,
            q_poly: witness.q_poly,
            p_poly: witness.p_poly,
        };

        let serialised = solution.serialise();

        assert_eq!(
            serialised.len(),
            PARAM_K + PARAM_CHUNK_W * PARAM_SPLITTING_FACTOR * 2
        );

        let deserialised = Solution::parse(serialised);

        assert_eq!(solution.s_a, deserialised.s_a);
        assert_eq!(solution.q_poly, deserialised.q_poly);
        assert_eq!(solution.p_poly, deserialised.p_poly);
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
fn sample_x(prg: &mut PRG) -> ([u8; PARAM_CHUNK_M], [u8; PARAM_CHUNK_W]) {
    let positions = sample_non_zero_x_positions(prg);
    let mut x_vector = [0_u8; PARAM_CHUNK_M];
    let mut non_zero_coordinates = [1u8; PARAM_CHUNK_W];

    // Sample non-zero coordinates for x
    prg.sample_field_fq_non_zero(&mut non_zero_coordinates);

    for (j, pos) in positions.iter().enumerate() {
        x_vector[*pos as usize] ^= non_zero_coordinates[j];
    }

    (x_vector, positions)
}

/// Compute the polynomial Q' from the non-zero positions, but in reverse order, i.e. [3,2,1] represents x^3 + 2x^2 + 3x.
/// Essentially this computes the monic polynomial from the roots. I.e. Q(root) = 0.
/// Returns truncated polynomial to PARAM_CHUNK_W. (removing the leading coefficient 1)
fn compute_q_prime_chunk<const N: usize>(positions: &[u8; N]) -> [u8; N] {
    compute_vanishing_polynomial(positions)
}

/// Completes the q polynomial by inserting the leading coefficient at the beginning of each d-split
pub(crate) fn complete_q(q_poly: QPoly, leading: u8) -> QPolyComplete {
    let mut q_poly_out = [[0_u8; PARAM_CHUNK_W + 1]; PARAM_SPLITTING_FACTOR];

    for d in 0..PARAM_SPLITTING_FACTOR {
        q_poly_out[d][0] = leading;
        for i in 0..PARAM_CHUNK_W {
            q_poly_out[d][i + 1] = q_poly[d][i];
        }
    }

    q_poly_out
}

/// Generate `s = (s_a | s_b)` from `s_a`, `H'` and `y`. Optionally add `y` to `H's_a`.
/// ```
/// if has_offset is true:
///     s_b = y + H's_a
/// else s_b = H's_a
/// ```
pub(crate) fn compute_s(
    s_a: &[u8; PARAM_K],
    h_prime: &HPrimeMatrix,
    y: Option<&[u8; PARAM_M_SUB_K]>,
) -> [u8; PARAM_M] {
    // (s_a | s_b)
    let mut s = [0u8; PARAM_M];

    // Set s_a
    gf256_add_vector(&mut s[..PARAM_K], s_a);

    // If has_offset, compute s_b = y + H's_a
    if let Some(y) = y {
        gf256_add_vector(&mut s[PARAM_K..], y);
    }

    // s_b += H's_a
    let h_prime_s_a: [u8; PARAM_M_SUB_K] = h_prime.gf256_mul_vector(s_a);
    gf256_add_vector(&mut s[PARAM_K..], &h_prime_s_a);
    s
}

/// Compute SPoly from s = Parse((s, F_q^(m/d), F_q^(m/d),...)
pub(crate) fn compute_s_poly(s: [u8; PARAM_M]) -> SPoly {
    let mut s_poly: SPoly = [[0u8; PARAM_CHUNK_M]; PARAM_SPLITTING_FACTOR];
    for (i, s_poly_d) in s.chunks(PARAM_CHUNK_M).enumerate() {
        s_poly[i] = s_poly_d.try_into().expect("Invalid chunk size");
    }

    s_poly
}

#[cfg(test)]
mod test_helpers {

    const SPEC_MASTER_SEED: Seed = [
        124, 153, 53, 160, 176, 118, 148, 170, 12, 109, 16, 228, 219, 107, 26, 221,
    ];

    use crate::{
        arith::{
            gf256::gf256_poly::{
                gf256_evaluate_polynomial_horner, gf256_evaluate_polynomial_horner_monic,
            },
            hamming_weight_vector,
        },
        constants::params::{PARAM_CHUNK_W, PARAM_SEED_SIZE, PARAM_W},
        subroutines::prg::prg::PRG,
    };

    use super::*;

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
            let (x_vector, _positions) = sample_x(&mut prg);

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
        let positions = sample_x(&mut PRG::init(&[0u8; PARAM_SEED_SIZE], None)).1;
        let q = compute_q_prime_chunk(&positions);
        for pos in positions.iter() {
            assert_eq!(gf256_evaluate_polynomial_horner_monic(&q, *pos), 0);
        }
    }

    #[test]
    fn test_compute_s() {
        let seed = [0u8; PARAM_SEED_SIZE];
        let (q, s, p, ..) = sample_witness(seed);
        let witness = generate_witness(seed, (q, s, p));
        let y = witness.y;
        let h_prime = witness.h_prime;
        let s_a = witness.s_a;
        let s = compute_s(&s_a, &h_prime, Some(&y));

        assert_eq!(s.len(), PARAM_M);
        assert_eq!(s[..PARAM_K], witness.s_a);
        assert_eq!(s[PARAM_K..], witness.s_b);
    }

    #[test]
    fn test_complete_q() {
        let seed = [0u8; PARAM_SEED_SIZE];
        let (q_poly, ..) = sample_witness(seed);
        let q_complete = complete_q(q_poly, 1);

        for (i, q_comp) in q_complete.iter().enumerate() {
            assert_eq!(q_comp[0], 1);

            // Check that this is the same as using the monic polynomial evaluation on the original q_poly
            assert_eq!(
                gf256_evaluate_polynomial_horner_monic(&q_poly[i], 1),
                gf256_evaluate_polynomial_horner(q_comp, 1)
            )
        }
    }

    #[test]
    fn test_sample_x_compare_to_spec() {
        let spec_positions = [
            80u8, 29, 172, 114, 94, 50, 84, 16, 79, 159, 112, 3, 163, 6, 147, 170, 36, 91, 161,
            119, 139, 228, 24, 128, 136, 153, 169, 87, 64, 67, 143, 61, 167, 160, 218, 193, 78, 27,
            180, 205, 115, 39, 51, 240, 179, 210, 183, 133, 131, 127, 10, 0, 149, 130, 134, 85, 22,
            188, 232, 200, 151, 223, 93, 162, 178, 118, 7, 58, 144, 25, 213, 20, 141, 106, 207, 47,
            185, 109, 212, 132, 215, 231, 230, 135, 49, 108, 192,
        ];

        let spec_x_vectors = [
            91u8, 0, 0, 163, 0, 0, 254, 143, 0, 0, 252, 0, 0, 0, 0, 0, 94, 0, 0, 0, 249, 0, 103, 0,
            222, 73, 0, 69, 0, 241, 0, 0, 0, 0, 0, 0, 244, 0, 0, 76, 0, 0, 0, 0, 0, 0, 0, 234, 0,
            177, 90, 97, 0, 0, 0, 0, 0, 0, 97, 0, 0, 108, 0, 0, 141, 0, 0, 29, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 3, 4, 65, 0, 0, 0, 92, 156, 0, 11, 0, 0, 0, 215, 0, 89, 158, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 21, 0, 177, 192, 0, 0, 15, 0, 254, 142, 0, 0, 116, 16, 0, 0, 0, 0, 0, 0,
            0, 142, 195, 0, 146, 211, 190, 13, 205, 77, 239, 0, 0, 199, 0, 60, 0, 149, 189, 0, 0,
            210, 0, 95, 0, 217, 0, 12, 0, 0, 0, 0, 0, 157, 79, 32, 104, 89, 0, 0, 0, 56, 0, 183,
            67, 0, 108, 0, 0, 0, 0, 0, 147, 113, 237, 0, 0, 9, 0, 20, 0, 0, 177, 0, 0, 0, 170, 253,
            0, 0, 0, 0, 0, 0, 205, 0, 0, 0, 0, 225, 0, 113, 0, 0, 26, 0, 121, 194, 0, 121, 0, 0,
            41, 0, 0, 0, 0, 26, 0, 0, 0, 0, 163, 0, 83, 125, 36, 0, 0, 0, 0, 0, 0, 0, 99, 0,
        ];

        let mut prg = PRG::init(&SPEC_MASTER_SEED, None);
        let (x_vectors, positions) = sample_x(&mut prg);

        assert_eq!(positions, spec_positions);
        assert_eq!(x_vectors, spec_x_vectors);
    }

    #[test]
    fn test_sample_witness_compare_to_spec() {
        let spec_s_poly: SPoly = [[
            91, 53, 217, 202, 126, 3, 149, 65, 146, 123, 138, 232, 106, 201, 191, 25, 243, 241,
            209, 152, 211, 231, 185, 90, 175, 251, 122, 42, 110, 56, 1, 75, 56, 224, 253, 138, 252,
            154, 185, 33, 209, 25, 9, 53, 19, 122, 136, 239, 182, 204, 98, 77, 116, 61, 52, 30,
            133, 230, 25, 180, 121, 180, 19, 118, 175, 159, 14, 246, 149, 4, 163, 34, 192, 143, 73,
            80, 85, 169, 241, 40, 77, 238, 197, 237, 225, 137, 134, 44, 24, 48, 117, 201, 148, 153,
            159, 127, 126, 139, 225, 97, 10, 228, 123, 196, 96, 240, 49, 157, 83, 218, 30, 110,
            114, 135, 244, 49, 0, 43, 252, 110, 34, 146, 111, 32, 65, 151, 104, 196, 8, 103, 73,
            229, 64, 230, 114, 214, 120, 227, 196, 165, 170, 187, 139, 13, 78, 83, 73, 201, 218,
            77, 219, 208, 90, 175, 213, 150, 66, 104, 28, 91, 57, 225, 51, 23, 27, 53, 24, 159, 34,
            144, 6, 226, 241, 142, 225, 86, 12, 114, 16, 140, 1, 175, 185, 132, 159, 161, 198, 229,
            230, 186, 84, 91, 50, 120, 254, 51, 76, 127, 42, 211, 190, 239, 144, 112, 20, 194, 44,
            65, 124, 253, 42, 184, 251, 26, 3, 37, 238, 53, 113, 130, 1, 37, 242, 34, 133, 114, 87,
            145, 115, 130, 158, 195, 151, 41, 169, 39, 100, 15, 213, 48, 76, 241,
        ]];
        let spec_q_poly: QPoly = [[
            0, 187, 197, 184, 32, 206, 57, 42, 32, 37, 59, 37, 73, 179, 15, 43, 105, 228, 191, 78,
            179, 154, 225, 14, 158, 50, 71, 43, 47, 156, 136, 214, 59, 39, 254, 59, 62, 147, 238,
            67, 218, 170, 177, 117, 118, 179, 210, 138, 90, 43, 188, 214, 50, 195, 144, 97, 17,
            178, 126, 80, 168, 193, 121, 5, 87, 252, 64, 107, 200, 109, 83, 36, 182, 206, 220, 57,
            89, 121, 127, 54, 48, 244, 250, 205, 68, 142, 129,
        ]];
        let spec_p_poly: PPoly = [[
            21, 59, 220, 229, 93, 93, 142, 156, 72, 108, 14, 154, 237, 244, 236, 231, 193, 241,
            205, 36, 255, 58, 89, 151, 250, 221, 247, 221, 202, 116, 100, 158, 88, 50, 56, 19, 5,
            185, 223, 43, 121, 192, 58, 160, 180, 225, 193, 206, 177, 63, 10, 127, 105, 87, 135,
            210, 71, 200, 103, 141, 201, 111, 251, 66, 26, 52, 232, 34, 246, 250, 206, 33, 82, 14,
            32, 228, 204, 11, 176, 204, 203, 93, 242, 65, 74, 104, 241,
        ]];

        let (q, s, p, ..) = sample_witness(SPEC_MASTER_SEED);

        assert_eq!(q, spec_q_poly, "q_poly does not match spec");
        assert_eq!(s, spec_s_poly, "s_poly does not match spec");
        assert_eq!(p, spec_p_poly, "p_poly does not match spec");
    }
}
