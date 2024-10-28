use crate::{
    constants::params::{PARAM_N, PARAM_TAU},
    mpc::beaver::{Beaver, BeaverA, BeaverB, BeaverC, BEAVER_ABPLAIN_SIZE, BEAVER_CPLAIN_SIZE},
    witness::{Solution, SOLUTION_PLAIN_SIZE},
};

#[derive(Clone)]
pub(crate) struct Input {
    pub(crate) solution: Solution,
    pub(crate) beaver_ab: (BeaverA, BeaverB),
    pub(crate) beaver_c: BeaverC,
}

/// k+2w+t(2d+1)η
pub(crate) const INPUT_SIZE: usize = SOLUTION_PLAIN_SIZE + BEAVER_ABPLAIN_SIZE + BEAVER_CPLAIN_SIZE;

pub(crate) type InputSharePlain = [u8; INPUT_SIZE];
pub(crate) type InputSharesPlain = [[InputSharePlain; PARAM_N]; PARAM_TAU];

impl Input {
    // Turn the input into a byte array for mpc of `F_q^(k+2w+t(2d+1)η)`
    pub(crate) fn serialise(&self) -> [u8; INPUT_SIZE] {
        let mut serialised = [0u8; INPUT_SIZE];
        serialised[..SOLUTION_PLAIN_SIZE].copy_from_slice(&self.solution.serialise());
        serialised[SOLUTION_PLAIN_SIZE..].copy_from_slice(&Beaver::serialise(
            self.beaver_ab.0,
            self.beaver_ab.1,
            self.beaver_c,
        ));
        serialised
    }

    pub(crate) fn deserialise_solution(
        truncated_input_plain: [u8; SOLUTION_PLAIN_SIZE],
    ) -> Solution {
        let solution = Solution::parse(truncated_input_plain);
        solution
    }

    pub(crate) fn parse(input_plain: InputSharePlain) -> Input {
        let solution = Solution::parse(input_plain[..SOLUTION_PLAIN_SIZE].try_into().unwrap());
        let (a, b, c) = Beaver::parse(input_plain[SOLUTION_PLAIN_SIZE..].try_into().unwrap());

        Input {
            solution,
            beaver_ab: (a, b),
            beaver_c: c,
        }
    }

    /// Remove the Beaver triples from the input shares as they can be derived from the Solution shares
    /// {[x_A]_i, [P]_i, [Q]_i}_(i \in I) and broadcast shares {[α]_i, [β]_i, [v]_i}_(i \in I).
    pub(crate) fn truncate_beaver_triples(
        input_share: [u8; INPUT_SIZE],
    ) -> [u8; SOLUTION_PLAIN_SIZE] {
        return input_share[..SOLUTION_PLAIN_SIZE].try_into().unwrap();
    }

    /// Append the Beaver triples from the input shares as they can be derived from the Solution shares
    pub(crate) fn append_beaver_triples(
        solution_share: [u8; SOLUTION_PLAIN_SIZE],
        beaver_triples: (BeaverA, BeaverB, BeaverC),
    ) -> [u8; INPUT_SIZE] {
        let mut input = [0u8; INPUT_SIZE];
        input[..SOLUTION_PLAIN_SIZE].copy_from_slice(&solution_share);
        input[SOLUTION_PLAIN_SIZE..].copy_from_slice(&Beaver::serialise(
            beaver_triples.0,
            beaver_triples.1,
            beaver_triples.2,
        ));
        input
    }
}

#[cfg(test)]
mod input_tests {
    use crate::{
        constants::params::{PARAM_SALT_SIZE, PARAM_SEED_SIZE},
        keygen::keygen, subroutines::prg::prg::PRG,
    };

    use super::*;

    #[test]
    fn test_serialise_deserialise_input() {
        let (_pk, sk) = keygen([0u8; PARAM_SEED_SIZE]);
        let mut prg = PRG::init(&[0u8; PARAM_SEED_SIZE], Some(&[0u8; PARAM_SALT_SIZE]));
        let (a, b, c) = Beaver::generate_beaver_triples(&mut prg);

        let input = Input {
            solution: sk.solution,
            beaver_ab: (a, b),
            beaver_c: c,
        };

        let input_plain = input.serialise();
        assert!(input_plain.len() == INPUT_SIZE);

        let solution_plain = Input::truncate_beaver_triples(input_plain);
        assert!(solution_plain.len() == SOLUTION_PLAIN_SIZE);

        let deserialised_solution = Input::deserialise_solution(solution_plain);

        assert_eq!(input.solution.s_a, deserialised_solution.s_a);
        assert_eq!(input.solution.q_poly, deserialised_solution.q_poly);
        assert_eq!(input.solution.p_poly, deserialised_solution.p_poly);
    }

    #[test]
    fn test_append_beaver_triples() {
        let (_pk, sk) = keygen([0u8; PARAM_SEED_SIZE]);
        let mut prg = PRG::init(&[0u8; PARAM_SEED_SIZE], Some(&[0u8; PARAM_SALT_SIZE]));
        let (a, b, c) = Beaver::generate_beaver_triples(&mut prg);

        let input = Input {
            solution: sk.solution,
            beaver_ab: (a, b),
            beaver_c: c,
        };

        let input_plain = input.serialise();
        let solution_plain = Input::truncate_beaver_triples(input_plain);

        let beaver_triples = (a, b, c);
        let input_with_beaver_triples =
            Input::append_beaver_triples(solution_plain, beaver_triples);

        assert_eq!(input_plain, input_with_beaver_triples);
    }
}
