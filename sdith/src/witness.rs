use crate::{
    arith::{
        gf256::{
            gf256_arith::{gf256_add, gf256_mul, gf256_sub},
            gf256_poly::gf256_remove_one_degree_factor_monic,
            gf256_vector::{gf256_add_vector, gf256_mul_vector_by_scalar},
        },
        matrices::MatrixGF256,
        vectors::{parse, parse_vec, serialize, serialize_vec, vector_copy_into_2},
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
/// QPoly is a polynomial of degree PARAM_CHUNK_WEIGHT * PARAM_SPLITTING_FACTOR. Split into a matrix of PARAM_SPLITTING_FACTOR rows and PARAM_CHUNK_WEIGHT columns.
type QPoly = [[u8; PARAM_CHUNK_W]; PARAM_SPLITTING_FACTOR];
type PPoly = [[u8; PARAM_CHUNK_W]; PARAM_SPLITTING_FACTOR];
type SPoly = [[u8; PARAM_CHUNK_M]; PARAM_SPLITTING_FACTOR];

type HPrimeMatrix = [[u8; PARAM_K]; PARAM_M_SUB_K];
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
    pub(crate) matrix_h_prime: HPrimeMatrix,
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
    pub(crate) q_poly: QPoly,
    pub(crate) p_poly: PPoly,
}

pub(crate) type WitnessPlain = Vec<u8>;

impl Solution {
    pub(crate) fn get_witness_plain(&self) -> WitnessPlain {
        let mut q_poly = Vec::with_capacity(PARAM_CHUNK_W * PARAM_SPLITTING_FACTOR);
        let mut p_poly = Vec::with_capacity(PARAM_CHUNK_W * PARAM_SPLITTING_FACTOR);
        for d in 0..PARAM_SPLITTING_FACTOR {
            q_poly.extend(self.q_poly[d].to_vec());
            p_poly.extend(self.p_poly[d].to_vec());
        }

        serialize_vec(vec![self.s_a.to_vec(), q_poly, p_poly])
    }

    pub(crate) fn parse_witness_plain(wit_plain: Vec<u8>) -> Self {
        let [s_a, q_poly, p_poly] = parse_vec(
            &wit_plain,
            vec![
                PARAM_K,
                PARAM_CHUNK_W * PARAM_SPLITTING_FACTOR,
                PARAM_CHUNK_W * PARAM_SPLITTING_FACTOR,
            ],
        );

        let q_poly = parse::<PARAM_SPLITTING_FACTOR, PARAM_CHUNK_W>(
            &q_poly,
            [PARAM_CHUNK_W; PARAM_SPLITTING_FACTOR].to_vec(),
        );

        let p_poly = parse::<PARAM_SPLITTING_FACTOR, PARAM_CHUNK_W>(
            &p_poly,
            vec![PARAM_CHUNK_W; PARAM_SPLITTING_FACTOR],
        );

        Solution {
            s_a: s_a.try_into().expect("Failed to convert s_a"),
            q_poly,
            p_poly,
        }
    }
}

#[cfg(test)]
mod test_solution {
    use crate::constants::params::{
        PARAM_CHUNK_W, PARAM_K, PARAM_SEED_SIZE, PARAM_SPLITTING_FACTOR,
    };

    use super::generate_instance_with_solution;

    #[test]
    fn test_serialize() {
        let solution = generate_instance_with_solution([0u8; PARAM_SEED_SIZE]).1;
        let wit_plain = solution.get_witness_plain();

        assert!(wit_plain.len() == PARAM_K + PARAM_CHUNK_W * PARAM_SPLITTING_FACTOR * 2);
    }

    #[test]
    fn test_parse() {
        let solution = generate_instance_with_solution([0u8; PARAM_SEED_SIZE]).1;
        let wit_plain = solution.get_witness_plain();
        let solution_parsed = super::Solution::parse_witness_plain(wit_plain);

        assert_eq!(solution.s_a, solution_parsed.s_a);
        assert_eq!(solution.q_poly, solution_parsed.q_poly);
        assert_eq!(solution.p_poly, solution_parsed.p_poly);
    }
}

struct Witness {
    s_a: [u8; PARAM_K],
    s_b: [u8; PARAM_M_SUB_K],
    y: [u8; PARAM_M_SUB_K],
    seed_h: Seed,
    matrix_h_prime: HPrimeMatrix,
}

/// Generate a witness for the instance.
///
/// Inputs:
/// - seed_h: Seed used to generate the H matrix.
/// - polynomials: Tuple containing the polynomials Q', S, and P.
fn generate_witness(seed_h: Seed, polynomials: (QPoly, SPoly, PPoly)) -> Witness {
    let (_q_poly, s_poly, _p_poly) = polynomials;

    // s is pre serialized as (s_A | s_B) due to the nature of SPoly
    // Split s as (s_A | s_B)
    let mut s_a = [0_u8; PARAM_K];
    let mut s_b = [0_u8; PARAM_M_SUB_K];
    let s_serialized =
        serialize::<{ PARAM_CHUNK_M * PARAM_SPLITTING_FACTOR }, PARAM_CHUNK_M>(s_poly.to_vec());
    vector_copy_into_2(&s_serialized, &mut s_a, &mut s_b);

    // Build H
    let matrix_h_prime = HPrimeMatrix::gen_random(&mut PRG::init(&seed_h, None));

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
        matrix_h_prime: witness.matrix_h_prime,
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
fn sample_witness(
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
    return (q_poly, s_poly, p_poly, x_vectors);
}

#[cfg(test)]
mod test_witness {
    use crate::arith::{
        gf256::gf256_poly::{
            gf256_evaluate_polynomial_horner, gf256_evaluate_polynomial_horner_monic,
        },
        hamming_weight_vector,
    };

    use super::*;

    #[test]
    fn test_generate_witness() {
        let seed_test = [0u8; PARAM_SEED_SIZE];
        let (q, s, p, ..) = sample_witness(seed_test);
        let result = generate_witness(seed_test, (q, s, p));

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
                    gf256_evaluate_polynomial_horner(&s_poly_d.to_vec(), i as u8),
                    x_vector_d[i]
                );

                // Test that Q(fi) = 0 for all xi != 0
                // TODO: This currently does not work. Seems it might not be Q, but Q'? However, we dont know as of yet
                if x_vector_d[i] != 0 {
                    assert_eq!(
                        gf256_evaluate_polynomial_horner_monic(&q_poly_d.to_vec(), i as u8),
                        0_u8
                    );
                }
            }

            // Test that S · Q = P · F
            let mut s_q = [0_u8; PARAM_CHUNK_M];
            let mut p_f = [0_u8; PARAM_CHUNK_M];

            // Compute S · Q and P · F
            for i in 0..PARAM_CHUNK_M {
                s_q[i] = gf256_mul(
                    gf256_evaluate_polynomial_horner(&s_poly_d.to_vec(), i as u8),
                    gf256_evaluate_polynomial_horner_monic(&q_poly_d.to_vec(), i as u8),
                );
                p_f[i] = gf256_mul(
                    gf256_evaluate_polynomial_horner(&p_poly_d.to_vec(), i as u8),
                    gf256_evaluate_polynomial_horner(&PRECOMPUTED_F_POLY.to_vec(), i as u8),
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
fn sample_x(prg: &mut PRG) -> ([u8; PARAM_CHUNK_M], [u8; PARAM_CHUNK_W]) {
    let positions = sample_non_zero_x_positions(prg);
    let mut x_vector = [0_u8; PARAM_CHUNK_M];
    let mut non_zero_coordinates = [1u8; PARAM_CHUNK_W];
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
    let mut q_coeffs = [1u8; N];

    for (i, pos) in positions.iter().enumerate() {
        for j in (1..=i).rev() {
            q_coeffs[j] = gf256_add(q_coeffs[j - 1], gf256_mul(q_coeffs[j], *pos));
        }
        q_coeffs[0] = gf256_mul(q_coeffs[0], *pos);
    }
    q_coeffs
}

#[cfg(test)]
mod test_helpers {
    use crate::{
        arith::{gf256::gf256_poly::gf256_evaluate_polynomial_horner_monic, hamming_weight_vector},
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
            assert_eq!(gf256_evaluate_polynomial_horner_monic(&q.to_vec(), *x), 0);
        }
    }

    #[test]
    fn test_compute_q_chunk_with_sample() {
        let positions = sample_x(&mut PRG::init(&[0u8; PARAM_SEED_SIZE], None)).1;
        let q = compute_q_prime_chunk(&positions);
        for pos in positions.iter() {
            assert_eq!(gf256_evaluate_polynomial_horner_monic(&q.to_vec(), *pos), 0);
        }
    }
}
