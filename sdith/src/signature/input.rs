//! # Input
//!
//! Input shares are used in the MPC protocol to share the solution.
//! And are used in the inverse party computation.

use crate::{
    constants::params::{PARAM_N, PARAM_TAU},
    mpc::beaver::{BeaverTriples, BEAVER_ABPLAIN_SIZE, BEAVER_CPLAIN_SIZE},
    subroutines::marshalling::Marshalling,
    witness::{Solution, SOLUTION_PLAIN_SIZE},
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
        serialised[SOLUTION_PLAIN_SIZE..].copy_from_slice(&self.beaver.serialise());
        serialised
    }

    fn parse(input_plain: &InputSharePlain) -> Result<Input, String> {
        let solution = Solution::parse(input_plain[..SOLUTION_PLAIN_SIZE].try_into().unwrap())?;
        let beaver = BeaverTriples::parse(&input_plain[SOLUTION_PLAIN_SIZE..].try_into().unwrap())?;

        Ok(Input { solution, beaver })
    }
}

impl Input {
    /// Remove the Beaver triples from the input shares as they can be derived from the Solution shares
    /// {\begin{align*}x_A\end{align*}_i, \begin{align*}P\end{align*}_i, \begin{align*}Q\end{align*}_i}_(i \in I) and broadcast shares {\begin{align*}α\end{align*}_i, \begin{align*}β\end{align*}_i, \begin{align*}v\end{align*}_i}_(i \in I).
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
