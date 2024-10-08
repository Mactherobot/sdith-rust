use crate::{
    arith::gf256::{
        gf256_vector::{gf256_add_vector, gf256_add_vector_mul_scalar},
        FieldArith,
    },
    constants::params::{PARAM_L, PARAM_N, PARAM_TAU},
    mpc::beaver::{Beaver, BeaverA, BeaverB, BeaverC, BEAVER_ABPLAIN_SIZE, BEAVER_CPLAIN_SIZE},
    subroutines::prg::prg::PRG,
    witness::{Solution, SOLUTION_PLAIN_SIZE},
};

pub(crate) struct Input {
    pub(crate) solution: Solution,
    pub(crate) beaver_ab: (BeaverA, BeaverB),
    pub(crate) beaver_c: BeaverC,
}

/// k+2w+t(2d+1)η
pub(super) const INPUT_SIZE: usize = SOLUTION_PLAIN_SIZE + BEAVER_ABPLAIN_SIZE + BEAVER_CPLAIN_SIZE;

impl Input {
    // Turn the input into a byte array for mpc of `F_q^(k+2w+t(2d+1)η)`
    pub(super) fn serialise(&self) -> [u8; INPUT_SIZE] {
        let mut serialised = [0u8; INPUT_SIZE];
        serialised[..SOLUTION_PLAIN_SIZE].copy_from_slice(&self.solution.serialise());
        serialised[SOLUTION_PLAIN_SIZE..].copy_from_slice(&Beaver::serialise(
            self.beaver_ab.0,
            self.beaver_ab.1,
            self.beaver_c,
        ));
        serialised
    }

    fn deserialise_solution(input: [u8; SOLUTION_PLAIN_SIZE]) -> Solution {
        let solution = Solution::deserialise(input[..SOLUTION_PLAIN_SIZE].try_into().unwrap());
        solution
    }

    /// Remove the Beaver triples from the input shares as they can be derived from the Solution shares
    /// {[x_A]_i, [P]_i, [Q]_i}_(i \in I) and broadcast shares {[α]_i, [β]_i, [v]_i}_(i \in I).
    pub(super) fn truncate_beaver_triples(input_share: [u8; INPUT_SIZE]) -> [u8; SOLUTION_PLAIN_SIZE] {
        return input_share[..SOLUTION_PLAIN_SIZE].try_into().unwrap();
    }

    /// Compute the input shares for Algorithm 12, p. 38
    ///
    /// ```
    /// for e in [1, τ] and i in [1, N]
    ///   input_share[e][i] = input_plain + sum^l_(j=1) fij · input coef[e][j]    if i != N
    ///                       input_coef[e][l]                                    if i == N
    /// ```
    pub(super) fn compute_input_shares(&self, prg: &mut PRG) -> [[[u8; INPUT_SIZE]; PARAM_N]; PARAM_TAU] {
        let input_plain = self.serialise();
        let mut input_shares = [[[0u8; INPUT_SIZE]; PARAM_N]; PARAM_TAU];

        // Generate coefficients
        let mut input_coef = [[[0u8; INPUT_SIZE]; PARAM_L]; PARAM_TAU];
        for e in 0..PARAM_TAU {
            for i in 0..PARAM_L {
                prg.sample_field_fq_elements(&mut input_coef[e][i]);
            }
        }

        for e in 0..PARAM_TAU {
            for i in 0..(PARAM_N - 1) {
                // We need to compute the following:
                // input_share[e][i] = input_plain + sum^ℓ_(j=1) fij · input coef[e][j]
                let f_i = u8::try_from(i).unwrap();
                let mut eval_sum = [0u8; INPUT_SIZE];

                // Compute the inner sum
                // sum^ℓ_(j=1) fij · input coef[e][j]
                for j in 0..PARAM_L {
                    gf256_add_vector_mul_scalar(
                        &mut eval_sum,
                        &input_coef[e][j],
                        f_i.field_pow((j + 1) as u8),
                    );
                }

                // Add the input_plain to the sum
                // input_plain + eval_sum
                gf256_add_vector(&mut eval_sum, &input_plain);

                // input_shares[e][i] = ...
                gf256_add_vector(&mut input_shares[e][i], &eval_sum);
            }

            // From line 13 in Algorithm 12
            // input[e][N-1] = input_coef[e][L-1]
            input_shares[e][PARAM_N - 1] = input_coef[e][PARAM_L - 1];
        }

        input_shares
    }
}

#[cfg(test)]
mod input_tests {
    use crate::{
        constants::params::{PARAM_SALT_SIZE, PARAM_SEED_SIZE},
        keygen::keygen,
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
}
