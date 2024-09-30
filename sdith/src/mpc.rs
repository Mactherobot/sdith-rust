use crate::{
    arith::{
        gf256::gf256_ext::{gf256_ext32_mul, gf256_ext32_sample},
        vectors::{self, serialize},
    },
    constants::params::{
        PARAM_EXT_DEGREE, PARAM_NB_EVALS_PER_POLY, PARAM_SEED_SIZE, PARAM_SPLITTING_FACTOR,
    },
    subroutines::prg::prg::PRG,
};

#[derive(Debug)]
pub(crate) struct MPC {
    pub(crate) a: [[[u8; PARAM_EXT_DEGREE]; PARAM_NB_EVALS_PER_POLY]; PARAM_SPLITTING_FACTOR],
    pub(crate) b: [[[u8; PARAM_EXT_DEGREE]; PARAM_NB_EVALS_PER_POLY]; PARAM_SPLITTING_FACTOR],
    pub(crate) c: [[u8; PARAM_EXT_DEGREE]; PARAM_NB_EVALS_PER_POLY],
}

impl MPC {
    pub(crate) fn new() -> Self {
        let a = [[gf256_ext32_sample(&mut PRG::init(&[0u8; PARAM_SEED_SIZE], None));
            PARAM_NB_EVALS_PER_POLY]; PARAM_SPLITTING_FACTOR];
        let b = [[gf256_ext32_sample(&mut PRG::init(&[0u8; PARAM_SEED_SIZE], None));
            PARAM_NB_EVALS_PER_POLY]; PARAM_SPLITTING_FACTOR];
        let mut c = [[0u8; PARAM_EXT_DEGREE]; PARAM_NB_EVALS_PER_POLY];
        (0..PARAM_NB_EVALS_PER_POLY).for_each(|i| {
            // Update the c value
            for j in 0..PARAM_SPLITTING_FACTOR {
                c[i] = gf256_ext32_mul(a[j][i], b[j][i]);
            }
        });

        MPC { a, b, c }
    }
}

#[cfg(test)]
mod mpc_tests {
    use super::*;

    #[test]
    fn test_mpc() {
        let mpc = MPC::new();
        assert_ne!(
            mpc.a,
            [[[0u8; PARAM_EXT_DEGREE]; PARAM_NB_EVALS_PER_POLY]; PARAM_SPLITTING_FACTOR]
        );
        assert_ne!(
            mpc.b,
            [[[0u8; PARAM_EXT_DEGREE]; PARAM_NB_EVALS_PER_POLY]; PARAM_SPLITTING_FACTOR]
        );
        assert_ne!(mpc.c, [[0u8; PARAM_EXT_DEGREE]; PARAM_NB_EVALS_PER_POLY]);
        assert_eq!(mpc.c[0], gf256_ext32_mul(mpc.a[0][0], mpc.b[0][0]));
    }
}
