use std::ops::{Index, IndexMut, Range};

use crate::{
    arith::gf256::gf256_arith::{gf256_add, gf256_mul},
    constants::params::{PARAM_K, PARAM_M_SUB_K},
    subroutines::prg::prg::PRG,
};

pub trait MatrixGF256Arith<const ROWS: usize, const COLS: usize>:
    Index<usize, Output = u8>
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
                sum = gf256_add(sum, gf256_mul(self[i * ROWS + j], x[i]));
            }
            result[i] = sum;
        }
        return result;
    }
}

pub trait Matrix<const ROWS: usize, const COLS: usize>:
    Index<usize, Output = u8>
    + IndexMut<usize, Output = u8>
    + Index<Range<usize>, Output = [u8]>
    + IndexMut<Range<usize>, Output = [u8]>
{
    /// Generate a random matrix of size `ROWS * COLS` using the provided PRG.
    /// Same as ExpandH function in the reference implementation.
    fn gen_random(prg: &mut PRG) -> [u8; ROWS * COLS] {
        let elements: [u8; ROWS * COLS] = prg
            .sample_field_elements_gf256(ROWS * COLS)
            .as_slice()
            .try_into()
            .expect("PRG did not return correct number of elements for H matrix");
        elements
    }

    fn set(&mut self, i: usize, j: usize, value: u8) {
        assert!(i < ROWS);
        assert!(j < COLS);
        self[i * COLS + j] = value;
    }

    /// Get the element at row `i` and column `j`. From matrix `A^(m * n)` for i <= m and j <= n.
    fn get(&self, i: usize, j: usize) -> u8 {
        assert!(i < ROWS);
        assert!(j < COLS);
        self[i * COLS + j]
    }

    fn get_row(&self, i: usize) -> &[u8] {
        assert!(i < ROWS);
        &self[i * COLS..(i + 1) * COLS]
    }

    fn get_row_mut(&mut self, i: usize) -> &mut [u8] {
        assert!(i < ROWS);
        let start = i * COLS;
        let end = (i + 1) * COLS;
        &mut self[start..end]
    }

    fn elements(&self) -> &Self {
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::constants::params::PARAM_SEED_SIZE;

    use super::*;

    type TestMatrix = [u8; 4 * 4];
    impl MatrixGF256Arith<4, 4> for TestMatrix {}
    impl Matrix<4, 4> for TestMatrix {}

    #[test]
    fn test_random_gen() {
        let matrix = TestMatrix::gen_random(&mut PRG::init(&[0u8; PARAM_SEED_SIZE], None));
        assert!(matrix.len() == PARAM_M_SUB_K * PARAM_K);
    }

    #[test]
    fn test_multiply_vector() {
        let matrix: TestMatrix = [2u8; 4 * 4];
        let x = [2u8; PARAM_M_SUB_K];
        let y: [u8; PARAM_K] = matrix.gf256_mul_vector(&x);

        assert!(y.len() == PARAM_K);
        for i in 0..PARAM_K {
            assert_eq!(y[i], 0); // Each sum x is the same, and gf256_add(x, x) = 0. So the result is 0.
        }

        // Test assert len panics
        let x = [2u8; PARAM_M_SUB_K - 1];
        let result = std::panic::catch_unwind(|| {
            matrix.gf256_mul_vector::<{ PARAM_M_SUB_K - 1 }, { PARAM_K }>(&x)
        });
        assert!(result.is_err());

        let x = [2u8; PARAM_M_SUB_K];
        let result = std::panic::catch_unwind(|| {
            matrix.gf256_mul_vector::<{ PARAM_M_SUB_K }, { PARAM_K - 1 }>(&x)
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_set_get_element() {
        let mut matrix: TestMatrix = [0u8; 4 * 4];
        matrix.set(0, 0, 1);
        matrix.set(0, 1, 2);
        matrix.set(1, 0, 3);
        matrix.set(1, 1, 4);

        assert_eq!(matrix.get(0, 0), 1);
        assert_eq!(matrix.get(0, 1), 2);
        assert_eq!(matrix.get(1, 0), 3);
        assert_eq!(matrix.get(1, 1), 4);
    }

    #[test]
    fn test_get_row() {
        let mut matrix: TestMatrix = [0u8; 4 * 4];
        matrix.set(0, 0, 1);
        matrix.set(0, 1, 2);
        matrix.set(1, 0, 3);
        matrix.set(1, 1, 4);

        assert_eq!(matrix.get_row(0), [1, 2, 0, 0]);
        assert_eq!(matrix.get_row(1), [3, 4, 0, 0]);
    }

    #[test]
    fn test_get_row_mut() {
        let mut matrix: TestMatrix = [0u8; 4 * 4];
        matrix.set(0, 0, 1);
        matrix.set(0, 1, 2);
        matrix.set(1, 0, 3);
        matrix.set(1, 1, 4);

        let row = matrix.get_row_mut(0);
        row[0] = 5;
        row[1] = 6;

        assert_eq!(matrix.get_row(0), [5, 6, 0, 0]);
    }

    #[test]
    fn test_elements() {
        let matrix: TestMatrix = [0u8; 4 * 4];
        assert_eq!(matrix.elements(), &matrix);
    }
}
