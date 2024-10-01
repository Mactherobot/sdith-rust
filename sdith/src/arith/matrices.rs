use std::ops::{Index, IndexMut, Range};

use crate::{
    arith::gf256::gf256_arith::{gf256_add, gf256_mul},
    constants::params::{PARAM_K, PARAM_M_SUB_K},
    subroutines::prg::prg::PRG,
};

pub trait MatrixGF256<const ROWS: usize, const COLS: usize>:
    Index<usize, Output = [u8; COLS]>
{
    /// Multiply the matrix self `A` by a vector `x` in GF(256).
    ///
    /// `y[i] = A[i][0] * x[0] + A[i][1] * x[1] + ... + A[i][n-1] * x[n-1]`
    fn gf256_mul_vector<const XLEN: usize, const OUTLEN: usize>(
        &self,
        x: &[u8; XLEN],
    ) -> [u8; OUTLEN] {
        assert!(
            XLEN >= ROWS,
            "Input vector x of length {} is too short. Should be at least {}",
            x.len(),
            ROWS
        );

        assert!(
            OUTLEN == ROWS,
            "Output vector y should be the same length as the ROWS of the matrix. Expected {}, got {}",
            OUTLEN,
            ROWS
        );

        let mut result = [0u8; OUTLEN];

        // y_i sum_{j=0}^{n-1} A[i][j] * x[j]
        for i in 0..ROWS {
            let mut sum = 0u8;
            for j in 0..COLS {
                sum = gf256_add(sum, gf256_mul(self[i][j], x[i]));
            }
            result[i] = sum;
        }
        return result;
    }

    /// Generate a random matrix of size `ROWS * COLS` using the provided PRG.
    /// Same as ExpandH function in the reference implementation.
    fn gen_random(prg: &mut PRG) -> [[u8; COLS]; ROWS] {
        let mut elements: [[u8; COLS]; ROWS] = [[0u8; COLS]; ROWS];
        for i in 0..ROWS {
            elements[i] = prg
                .sample_field_elements_gf256_vec(COLS)
                .try_into()
                .unwrap();
        }
        elements
    }
}

#[cfg(test)]
mod tests {
    use crate::constants::params::PARAM_SEED_SIZE;

    use super::*;

    const TEST_COLS: usize = 4;
    const TEST_ROWS: usize = 4;

    type TestMatrix = [[u8; TEST_COLS]; TEST_ROWS];
    impl MatrixGF256<TEST_ROWS, TEST_COLS> for TestMatrix {}

    #[test]
    fn test_random_gen() {
        let matrix = TestMatrix::gen_random(&mut PRG::init(&[0u8; PARAM_SEED_SIZE], None));
        assert!(matrix.len() == TEST_COLS);
        for i in 0..TEST_ROWS {
            assert!(matrix[i].len() == TEST_COLS);
        }
    }

    #[test]
    fn test_multiply_vector() {
        let matrix: TestMatrix = [[2u8; TEST_COLS]; TEST_ROWS];
        let x = [2u8; TEST_COLS];
        let y: [u8; TEST_ROWS] = matrix.gf256_mul_vector(&x);

        assert!(y.len() == TEST_ROWS);
        for i in 0..TEST_ROWS {
            assert_eq!(y[i], 0); // Each sum x is the same, and gf256_add(x, x) = 0. So the result is 0.
        }

        // Test assert len panics
        let x = [2u8; TEST_COLS - 1];
        let result = std::panic::catch_unwind(|| {
            matrix.gf256_mul_vector::<{ TEST_COLS - 1 }, { TEST_ROWS }>(&x)
        });
        assert!(result.is_err());

        let x = [2u8; TEST_COLS];
        let result = std::panic::catch_unwind(|| {
            matrix.gf256_mul_vector::<{ TEST_COLS }, { TEST_ROWS - 1 }>(&x)
        });
        assert!(result.is_err());
    }
}
