use crate::{
    arith::gf256::FieldArith,
    constants::{
        params::{PARAM_K, PARAM_M_SUB_K, PARAM_M_SUB_K_CEIL32},
        types::Seed,
    },
    subroutines::prg::prg::PRG,
};

use super::arrays::{Array2D, Array2DTrait};

/// H' matrix with dimensions `k * m_sub_k_length_ceil32`. The ceil value is only do accommodate the way the spec creates the matrix.
/// Matrix sizes are `PARAM_K * PARAM_M_SUB_K_CEIL32`.
pub(crate) type HPrimeMatrix = Array2D<u8>;

/// Multiply H' matrix with a vector `y` of length [`PARAM_K`].
pub(crate) fn mul_hprime_vector(vz: &mut [u8], matrix: &HPrimeMatrix, y: &Vec<u8>) {
    let mut unreduced_vz = [0u8; PARAM_M_SUB_K];
    let mut index = 0;
    for j in 0..PARAM_K {
        for i in 0..PARAM_M_SUB_K {
            unreduced_vz[i] ^= matrix.data[index].field_mul(y[j]);
            index += 1;
        }
    }

    for i in 0..PARAM_M_SUB_K {
        vz[i] ^= unreduced_vz[i];
    }
}

/// Generate H' matrix from a seed.
/// The matrix is of size `PARAM_K * PARAM_M_SUB_K_CEIL32`.
/// TODO: revert back to [`PARAM_M_SUB_K`]
pub(crate) fn gen_hmatrix(seed: &Seed) -> HPrimeMatrix {
    let mut prg = PRG::init(seed, None);
    gen_random(&mut prg, PARAM_K, PARAM_M_SUB_K_CEIL32)
}

/// Generate a random matrix of size `ROWS * COLS` using the provided PRG.
/// Same as ExpandH function in the reference implementation.
fn gen_random(prg: &mut PRG, cols: usize, rows: usize) -> Array2D<u8> {
    let mut elements: Array2D<u8> = Array2D::new(cols, rows);
    prg.sample_field_fq_elements(&mut elements.data);
    elements
}

#[cfg(test)]
mod tests {
    use crate::constants::params::PARAM_SEED_SIZE;

    use super::*;

    const TEST_COLS: usize = 3;
    const TEST_ROWS: usize = 4;

    type TestMatrix = Array2D<u8>;

    #[test]
    fn test_random_gen() {
        let matrix: TestMatrix = gen_random(
            &mut PRG::init(&vec![0u8; PARAM_SEED_SIZE], None),
            TEST_COLS,
            TEST_ROWS,
        );
        assert!(matrix.data.len() == TEST_COLS * TEST_ROWS);
    }
}
