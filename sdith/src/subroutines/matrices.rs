use std::ops::{Index, IndexMut, Range};

use crate::{
    arith::gf256::gf256_arith::{gf256_add, gf256_mul},
    constants::params::{PARAM_K, PARAM_M_SUB_K},
};

use super::prg::prg::PRG;

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
            OUTLEN == COLS,
            "Output vector y should be the same length as the COLS of the matrix. Expected {}, got {}",
            OUTLEN,
            COLS
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
    Index<usize, Output = u8> + Index<Range<usize>, Output = [u8]> + IndexMut<Range<usize>, Output = [u8]>
{
    fn random(prg: &mut PRG) -> [u8; ROWS * COLS] {
        let elements: [u8; ROWS * COLS] = prg
            .sample_field_elements_gf256(ROWS * COLS)
            .as_slice()
            .try_into()
            .expect("PRG did not return correct number of elements for H matrix");
        elements
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
        &mut self[i * COLS..(i + 1) * COLS]
    }

    fn elements(&self) -> &Self {
        self
    }
}

fn copy_from_vec_ptrs(src: &[u8], dst: &mut [u8]) {
    for i in 0..src.len() {
        dst[i] = src[i].clone();
    }
}

/// Copies and splits a vector of pointers into two arrays
pub(crate) fn split_vector_cpy_into_2<const A: usize, const B: usize>(
    v: &[u8],
    out1: &mut [u8; A],
    out2: &mut [u8; B],
) {
    assert!(A + B == v.len());
    let mut offset = 0;
    copy_from_vec_ptrs(&v[offset..offset + A], out1);
    offset += A;
    copy_from_vec_ptrs(&v[offset..offset + B], out2);
}

pub type HMatrix = [u8; PARAM_M_SUB_K * PARAM_K];

impl MatrixGF256Arith<{ PARAM_M_SUB_K }, { PARAM_K }> for HMatrix {}
impl Matrix<{ PARAM_M_SUB_K }, { PARAM_K }> for HMatrix {}

#[cfg(test)]
mod tests {
    use crate::constants::params::PARAM_SEED_SIZE;

    use super::*;

    #[test]
    fn test_expand_h_matrix() {
        let hmatrix = HMatrix::random(&mut PRG::init(&[0u8; PARAM_SEED_SIZE], None));
        assert!(hmatrix.len() == PARAM_M_SUB_K * PARAM_K);
    }

    #[test]
    fn test_multiply_vector() {
        let hmatrix: HMatrix = [2u8; PARAM_M_SUB_K * PARAM_K];
        let x = [2u8; PARAM_M_SUB_K];
        let y: [u8; PARAM_K] = hmatrix.gf256_mul_vector(&x);

        assert!(y.len() == PARAM_K);
        for i in 0..PARAM_K {
            assert_eq!(y[i], 0); // Each sum x is the same, and gf256_add(x, x) = 0. So the result is 0.
        }

        // Test assert len panics
        let x = [2u8; PARAM_M_SUB_K - 1];
        let result = std::panic::catch_unwind(|| {
            hmatrix.gf256_mul_vector::<{ PARAM_M_SUB_K - 1 }, { PARAM_K }>(&x)
        });
        assert!(result.is_err());

        let x = [2u8; PARAM_M_SUB_K];
        let result = std::panic::catch_unwind(|| {
            hmatrix.gf256_mul_vector::<{ PARAM_M_SUB_K }, { PARAM_K - 1 }>(&x)
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_split_vector_cpy_into_2() {
        let mut v: Vec<u8> = vec![1, 2, 3, 4, 5, 6];
        let mut out1 = [0; 2];
        let mut out2 = [0; 4];
        split_vector_cpy_into_2(&v, &mut out1, &mut out2);
        assert_eq!(out1, [1, 2]);
        assert_eq!(out2, [3, 4, 5, 6]);

        v[0] = 10;
        assert_eq!(out1, [1, 2]);
    }
}
