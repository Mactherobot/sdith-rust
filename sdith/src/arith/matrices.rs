use crate::{
    arith::gf256::FieldArith,
    constants::{
        params::{PARAM_K, PARAM_M_SUB_K, PARAM_M_SUB_K_CEIL32},
        types::Seed,
    },
    subroutines::prg::prg::PRG,
};

pub type Matrix<const COLS: usize, const ROWS: usize> = [u8; ROWS * COLS];

/// H' matrix with dimensions `k * m_sub_k_length_ceil32`. The ceil value is only do accommodate the way the spec creates the matrix.
/// TODO: revert back to [`PARAM_M_SUB_K`]
pub(crate) type HPrimeMatrix = Matrix<{ PARAM_K }, { PARAM_M_SUB_K_CEIL32 }>;

#[cfg(not(feature = "simd"))]
/// Multiply H' matrix with a vector `y` of length [`PARAM_K`].
pub(crate) fn mul_hprime_vector(vz: &mut [u8], matrix: &HPrimeMatrix, y: &[u8; PARAM_K]) {
    let mut unreduced_vz = [0u8; PARAM_M_SUB_K];
    let mut index = 0;
    for j in 0..PARAM_K {
        for i in 0..PARAM_M_SUB_K {
            unreduced_vz[i] ^= matrix[index].field_mul(y[j]);
            index += 1;
        }
    }

    for i in 0..PARAM_M_SUB_K {
        vz[i] ^= unreduced_vz[i];
    }
}

/// Multiply H' matrix with a vector `y` of length [`PARAM_K`].
#[cfg(feature = "simd")]
pub(crate) fn mul_hprime_vector(vz: &mut [u8], matrix: &HPrimeMatrix, y: &[u8; PARAM_K]) {
    use crate::arith::gf256::gf256_vector::{self, gf256_add_vector, gf256_mul_vector_by_scalar};

    let mut unreduced_vz = [0u8; PARAM_M_SUB_K];
    let mut offset = 0;
    for y in y.iter() {
        let mut matrix_part: [u8; PARAM_M_SUB_K] =
            matrix[offset..offset + PARAM_M_SUB_K].try_into().unwrap();
        gf256_mul_vector_by_scalar(&mut matrix_part, *y);
        gf256_add_vector(&mut unreduced_vz, &matrix_part);
    }

    for i in 0..PARAM_M_SUB_K {
        vz[i] ^= unreduced_vz[i];
    }
}

/// Generate H' matrix from a seed.
pub(crate) fn gen_hmatrix(seed: Seed) -> HPrimeMatrix {
    let mut prg = PRG::init(&seed, None);
    gen_random(&mut prg)
}

/// Generate a random matrix of size `ROWS * COLS` using the provided PRG.
/// Same as ExpandH function in the reference implementation.
fn gen_random<const COLS: usize, const ROWS: usize>(prg: &mut PRG) -> Matrix<COLS, ROWS>
where
    [(); ROWS * COLS]:,
{
    let mut elements: Matrix<COLS, ROWS> = [0u8; ROWS * COLS];
    prg.sample_field_fq_elements(&mut elements);
    elements
}

#[cfg(test)]
mod tests {
    use crate::constants::params::PARAM_SEED_SIZE;

    use super::*;

    const TEST_COLS: usize = 3;
    const TEST_ROWS: usize = 4;

    type TestMatrix = Matrix<{ TEST_COLS }, { TEST_ROWS }>;

    #[test]
    fn test_random_gen() {
        let matrix: TestMatrix = gen_random(&mut PRG::init(&[0u8; PARAM_SEED_SIZE], None));
        assert!(matrix.len() == TEST_COLS * TEST_ROWS);
    }
}
