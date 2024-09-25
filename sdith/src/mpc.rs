use crate::{
    arith::{
        gf256::gf256_ext::{gf256_ext32_mul, gf256_ext32_sample},
        vectors::{self, serialize},
    },
    constants::params::{PARAM_EXT_DEGREE, PARAM_NB_EVALS_PER_POLY, PARAM_SPLITTING_FACTOR},
    subroutines::prg::prg::PRG,
};

#[derive(Debug)]
pub(crate) struct Mpc {
    pub(crate) a: [[[u8; PARAM_EXT_DEGREE]; PARAM_NB_EVALS_PER_POLY]; PARAM_SPLITTING_FACTOR],
    pub(crate) b: [[[u8; PARAM_EXT_DEGREE]; PARAM_NB_EVALS_PER_POLY]; PARAM_SPLITTING_FACTOR],
    pub(crate) c: [[u8; PARAM_EXT_DEGREE]; PARAM_NB_EVALS_PER_POLY],
}

impl Mpc {
    pub(crate) fn new() -> Self {
        let a = [[[0; PARAM_EXT_DEGREE]; PARAM_NB_EVALS_PER_POLY]; PARAM_SPLITTING_FACTOR];
        let b = [[[0; PARAM_EXT_DEGREE]; PARAM_NB_EVALS_PER_POLY]; PARAM_SPLITTING_FACTOR];
        let c = [[0; PARAM_EXT_DEGREE]; PARAM_NB_EVALS_PER_POLY];

        Mpc { a, b, c }
    }

    /// Computes the beaver triples to be sacrificed in the mpc protocol
    pub(crate) fn compute_correlated(&self) -> [[u8; PARAM_EXT_DEGREE]; PARAM_NB_EVALS_PER_POLY] {
        // Iterate over all the a b values
        let mut c = self.c;
        (0..PARAM_NB_EVALS_PER_POLY).for_each(|i| {
            // Update the c value
            for j in 0..PARAM_SPLITTING_FACTOR {
                c[i] = gf256_ext32_mul(self.a[j][i], self.b[j][i]);
            }
        });
        c
    }
}
