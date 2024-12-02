use crate::{
    constants::params::{PARAM_N, PARAM_TAU},
    mpc::beaver::{
        parse, serialise, BeaverA, BeaverB, BeaverC, BEAVER_ABPLAIN_SIZE, BEAVER_CPLAIN_SIZE,
    },
    subroutines::marshalling::Marshalling,
    witness::{Solution, SOLUTION_PLAIN_SIZE},
};

#[derive(Clone, PartialEq, Eq)]
pub struct Input {
    pub solution: Solution,
    pub beaver_ab: (BeaverA, BeaverB),
    pub beaver_c: BeaverC,
}

/// k+2w+t(2d+1)η
pub const INPUT_SIZE: usize = SOLUTION_PLAIN_SIZE + BEAVER_ABPLAIN_SIZE + BEAVER_CPLAIN_SIZE;

pub type InputSharePlain = [u8; INPUT_SIZE];
pub type InputSharesPlain = [[InputSharePlain; PARAM_N]; PARAM_TAU];

impl Marshalling<InputSharePlain> for Input {
    // Turn the input into a byte array for mpc of `F_q^(k+2w+t(2d+1)η)`
    fn serialise(&self) -> InputSharePlain {
        let mut serialised = [0u8; INPUT_SIZE];
        serialised[..SOLUTION_PLAIN_SIZE].copy_from_slice(&self.solution.serialise());
        serialised[SOLUTION_PLAIN_SIZE..].copy_from_slice(&serialise(
            self.beaver_ab.0,
            self.beaver_ab.1,
            self.beaver_c,
        ));
        serialised
    }

    fn parse(input_plain: &InputSharePlain) -> Result<Input, String> {
        let solution = Solution::parse(input_plain[..SOLUTION_PLAIN_SIZE].try_into().unwrap())?;
        let (a, b, c) = parse(input_plain[SOLUTION_PLAIN_SIZE..].try_into().unwrap());

        Ok(Input {
            solution,
            beaver_ab: (a, b),
            beaver_c: c,
        })
    }
}

impl Input {
    /// Remove the Beaver triples from the input shares as they can be derived from the Solution shares
    /// {[x_A]_i, [P]_i, [Q]_i}_(i \in I) and broadcast shares {[α]_i, [β]_i, [v]_i}_(i \in I).
    pub fn truncate_beaver_triples(input_share: &[u8; INPUT_SIZE]) -> [u8; SOLUTION_PLAIN_SIZE] {
        return input_share[..SOLUTION_PLAIN_SIZE].try_into().unwrap();
    }

    /// Append the Beaver triples from the input shares as they can be derived from the Solution shares
    pub fn append_beaver_triples(
        solution_share: [u8; SOLUTION_PLAIN_SIZE],
        beaver_triples: (BeaverA, BeaverB, BeaverC),
    ) -> [u8; INPUT_SIZE] {
        let mut input = [0u8; INPUT_SIZE];
        input[..SOLUTION_PLAIN_SIZE].copy_from_slice(&solution_share);
        input[SOLUTION_PLAIN_SIZE..].copy_from_slice(&serialise(
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
        keygen::keygen,
        mpc::beaver::generate_beaver_triples,
        subroutines::prg::PRG,
    };

    use super::*;

    #[test]
    fn test_serialise_deserialise_input() {
        let (_pk, sk) = keygen([0u8; PARAM_SEED_SIZE]);
        let mut prg = PRG::init(&[0u8; PARAM_SEED_SIZE], Some(&[0u8; PARAM_SALT_SIZE]));
        let (a, b, c) = generate_beaver_triples(&mut prg);

        let input = Input {
            solution: sk.solution,
            beaver_ab: (a, b),
            beaver_c: c,
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
        let (a, b, c) = generate_beaver_triples(&mut prg);

        let input = Input {
            solution: sk.solution,
            beaver_ab: (a, b),
            beaver_c: c,
        };

        let input_plain = input.serialise();
        let solution_plain = Input::truncate_beaver_triples(&input_plain);

        let beaver_triples = (a, b, c);
        let input_with_beaver_triples =
            Input::append_beaver_triples(solution_plain, beaver_triples);

        assert_eq!(input_plain, input_with_beaver_triples);
    }
}
