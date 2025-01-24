//! # Input
//!
//! Input shares are used in the MPC protocol to share the solution.
//! And are used in the inverse party computation.

#[cfg(feature = "parallel")]
use rayon::iter::{IndexedParallelIterator as _, ParallelIterator as _};

use crate::{
    constants::params::{
        PARAM_CHUNK_W, PARAM_K, PARAM_L, PARAM_N, PARAM_SPLITTING_FACTOR, PARAM_TAU,
    },
    keygen::witness::{Solution, SOLUTION_PLAIN_SIZE},
    subroutines::{
        arithmetics::gf256::vectors::gf256_mul_scalar_add_vector,
        mpc::beaver::{BeaverTriples, BEAVER_ABPLAIN_SIZE, BEAVER_CPLAIN_SIZE},
        prg::PRG,
    },
    utils::{iterator::get_iterator_mut, marshalling::Marshalling},
};

#[derive(Clone, PartialEq, Eq)]
/// Input shares for the signature protocol
pub struct Input {
    /// Solution shares
    pub solution: Solution,
    /// Beaver triples
    pub beaver: BeaverTriples,
}

/// k+2w+t(2d+1)η
pub const INPUT_SIZE: usize = SOLUTION_PLAIN_SIZE + BEAVER_ABPLAIN_SIZE + BEAVER_CPLAIN_SIZE;

/// Input share plain, the singular input share
pub type InputSharePlain = [u8; INPUT_SIZE];
/// Input shares plain, a collectino of input shares
pub type InputSharesPlain = [[InputSharePlain; PARAM_N]; PARAM_TAU];

impl Marshalling<InputSharePlain> for Input {
    // Turn the input into a byte array for mpc of `F_q^(k+2w+t(2d+1)η)`
    fn serialise(&self) -> InputSharePlain {
        let mut serialised = [0u8; INPUT_SIZE];
        serialised[..SOLUTION_PLAIN_SIZE].copy_from_slice(&self.solution.serialise());
        #[cfg(feature = "kat")]
        serialised[..SOLUTION_PLAIN_SIZE].copy_from_slice(&kat_serialise_function(self.solution));
        serialised[SOLUTION_PLAIN_SIZE..].copy_from_slice(&self.beaver.serialise());
        serialised
    }

    fn parse(input_plain: &InputSharePlain) -> Result<Input, String> {
        #[cfg(not(feature = "kat"))]
        let solution = Solution::parse(&input_plain[..SOLUTION_PLAIN_SIZE].try_into().unwrap())?;
        #[cfg(feature = "kat")]
        let solution = kat_parse_function(&input_plain[..SOLUTION_PLAIN_SIZE].try_into().unwrap());
        let beaver = BeaverTriples::parse(&input_plain[SOLUTION_PLAIN_SIZE..].try_into().unwrap())?;

        Ok(Input { solution, beaver })
    }
}

#[cfg(feature = "kat")]
fn kat_serialise_function(solution: Solution) -> [u8; SOLUTION_PLAIN_SIZE] {
    let mut offset = 0;
    let mut serialised = [0u8; SOLUTION_PLAIN_SIZE];
    serialised[..PARAM_K].copy_from_slice(&solution.s_a);
    offset += PARAM_K;
    for i in 0..PARAM_SPLITTING_FACTOR {
        serialised[offset..offset + PARAM_CHUNK_W].copy_from_slice(&solution.q_poly[i]);
        offset += PARAM_CHUNK_W;
        serialised[offset..offset + PARAM_CHUNK_W].copy_from_slice(&solution.p_poly[i]);
        offset += PARAM_CHUNK_W;
    }
    serialised
}

#[cfg(feature = "kat")]
fn kat_parse_function(solution_plain: &[u8; SOLUTION_PLAIN_SIZE]) -> Solution {
    let mut offset = 0;
    let mut s_a = [0u8; PARAM_K];
    s_a.copy_from_slice(&solution_plain[..PARAM_K]);
    offset += PARAM_K;

    let mut q_poly = [[0u8; PARAM_CHUNK_W]; PARAM_SPLITTING_FACTOR];
    let mut p_poly = [[0u8; PARAM_CHUNK_W]; PARAM_SPLITTING_FACTOR];
    for i in 0..PARAM_SPLITTING_FACTOR {
        q_poly[i].copy_from_slice(&solution_plain[offset..offset + PARAM_CHUNK_W]);
        offset += PARAM_CHUNK_W;
        p_poly[i].copy_from_slice(&solution_plain[offset..offset + PARAM_CHUNK_W]);
        offset += PARAM_CHUNK_W;
    }

    Solution {
        s_a,
        q_poly,
        p_poly,
    }
}

impl Input {
    /// Remove the Beaver triples from the input shares as they can be derived from the Solution shares
    /// {\[x_A\]_i, \[P\]_i, \[Q\]_i}_(i \in I) and broadcast shares {\[α\]_i, \[β\]_i, \[v\]_i}_(i \in I).
    pub fn truncate_beaver_triples(input_share: &[u8; INPUT_SIZE]) -> [u8; SOLUTION_PLAIN_SIZE] {
        input_share[..SOLUTION_PLAIN_SIZE].try_into().unwrap()
    }

    /// Append the Beaver triples from the input shares as they can be derived from the Solution shares
    pub fn append_beaver_triples(
        solution_share: [u8; SOLUTION_PLAIN_SIZE],
        beaver_triples: BeaverTriples,
    ) -> [u8; INPUT_SIZE] {
        let mut input = [0u8; INPUT_SIZE];
        input[..SOLUTION_PLAIN_SIZE].copy_from_slice(&solution_share);
        input[SOLUTION_PLAIN_SIZE..].copy_from_slice(&beaver_triples.serialise());
        input
    }

    /// Only used for demoing of KAT
    pub fn parse_kat(input_plain: &InputSharePlain) -> Result<Input, String> {
        let solution_plain: [u8; SOLUTION_PLAIN_SIZE] =
            input_plain[..SOLUTION_PLAIN_SIZE].try_into().unwrap();
        let mut offset = 0;
        let mut s_a = [0u8; PARAM_K];
        s_a.copy_from_slice(&solution_plain[..PARAM_K]);
        offset += PARAM_K;

        let mut q_poly = [[0u8; PARAM_CHUNK_W]; PARAM_SPLITTING_FACTOR];
        let mut p_poly = [[0u8; PARAM_CHUNK_W]; PARAM_SPLITTING_FACTOR];
        for i in 0..PARAM_SPLITTING_FACTOR {
            q_poly[i].copy_from_slice(&solution_plain[offset..offset + PARAM_CHUNK_W]);
            offset += PARAM_CHUNK_W;
        }
        for i in 0..PARAM_SPLITTING_FACTOR {
            p_poly[i].copy_from_slice(&solution_plain[offset..offset + PARAM_CHUNK_W]);
            offset += PARAM_CHUNK_W;
        }

        let solution = Solution {
            s_a,
            q_poly,
            p_poly,
        };
        let beaver = BeaverTriples::parse(&input_plain[SOLUTION_PLAIN_SIZE..].try_into().unwrap())?;

        Ok(Input { solution, beaver })
    }
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
        get_iterator_mut(&mut input_shares[e])
            .enumerate()
            .for_each(|(i, share)| {
                *share = compute_share(input_plain, &input_coefs[e], i as u8, i == 0);
            });
    }

    ComputeInputSharesResult(input_shares, input_coefs)
}

#[cfg(test)]
mod input_tests {
    use crate::{
        constants::params::{PARAM_SALT_SIZE, PARAM_SEED_SIZE},
        keygen::keygen,
        subroutines::prg::PRG,
    };

    use super::*;

    #[test]
    fn test_serialise_deserialise_input() {
        let (_pk, sk) = keygen([0u8; PARAM_SEED_SIZE]);
        let mut prg = PRG::init(&[0u8; PARAM_SEED_SIZE], Some(&[0u8; PARAM_SALT_SIZE]));
        let beaver = BeaverTriples::generate(&mut prg);

        let input = Input {
            solution: sk.solution,
            beaver,
        };

        let input_plain = input.serialise();
        assert!(input_plain.len() == INPUT_SIZE);

        let solution_plain = Input::truncate_beaver_triples(&input_plain);
        assert!(solution_plain.len() == SOLUTION_PLAIN_SIZE);

        let deserialised_solution = Solution::parse(&solution_plain).unwrap();

        assert_eq!(input.solution.s_a, deserialised_solution.s_a);
        assert_eq!(input.solution.q_poly, deserialised_solution.q_poly);
        assert_eq!(input.solution.p_poly, deserialised_solution.p_poly);
    }

    #[test]
    fn test_append_beaver_triples() {
        let (_pk, sk) = keygen([0u8; PARAM_SEED_SIZE]);
        let mut prg = PRG::init(&[0u8; PARAM_SEED_SIZE], Some(&[0u8; PARAM_SALT_SIZE]));
        let beaver = BeaverTriples::generate(&mut prg);

        let input = Input {
            solution: sk.solution,
            beaver: beaver.clone(),
        };

        let input_plain = input.serialise();
        let solution_plain = Input::truncate_beaver_triples(&input_plain);
        let input_with_beaver_triples = Input::append_beaver_triples(solution_plain, beaver);

        assert_eq!(input_plain, input_with_beaver_triples);
    }
}
