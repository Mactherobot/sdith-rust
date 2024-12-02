use crate::{
    constants::{
        params::{PARAM_K, PARAM_M_SUB_K},
        types::Seed,
    },
    subroutines::prg::PRG,
};

/// H' matrix with dimensions `m-k * k`. The ceil value is only do accommodate the way the spec creates the matrix.
pub type HPrimeMatrix = [u8; PARAM_M_SUB_K * PARAM_K];

/// Multiply a matrix with a vector `y`. Outputs the result in `vz`.
pub fn mul_hmatrix_vector(vz: &mut [u8], hp: &HPrimeMatrix, v: &[u8; PARAM_K]) {
    field_mul_matrix_vector::<PARAM_M_SUB_K, PARAM_K>(vz, hp, PARAM_M_SUB_K, PARAM_K, v);
}

/// Multiply a matrix `h^(m x n)` with a vector `y` of length `n`. Outputs the result in `out` of at least length `n`.
/// Arithmetic is done in the finite field GF256.
/// The matrix is represented as a slice of bytes with `m` rows and `n` columns.
/// Due to the way we want to iterate over the matrix, columns are stored contiguously. I.e. the first `m` bytes are the first column.
/// Or visually for a 2x3 matrix:
///
/// ```text
/// | 1 2 3 |
/// | 4 5 6 | = [1, 4, 2, 5, 3, 6]
/// ```
///
/// This is done to allow for SIMD operations with the feature `simd` enabled.
pub fn field_mul_matrix_vector<const M: usize, const N: usize>(
    out: &mut [u8],
    h: &[u8],
    m: usize,
    _n: usize,
    v: &[u8; N],
) {
    use crate::arith::gf256::gf256_vector::{gf256_add_vector, gf256_mul_vector_by_scalar};

    let mut offset = 0;
    for vi in v.iter() {
        let mut h_col: [u8; M] = h[offset..offset + m].try_into().unwrap();
        gf256_mul_vector_by_scalar(&mut h_col, *vi);
        gf256_add_vector(out, &h_col);
        offset += m;
    }
}

/// Generate H' matrix from a seed.
pub fn gen_hmatrix(seed: Seed) -> HPrimeMatrix {
    let mut prg = PRG::init(&seed, None);
    let mut h_prime: HPrimeMatrix = [0u8; PARAM_K * PARAM_M_SUB_K];
    prg.sample_field_fq_elements(&mut h_prime);
    h_prime
}

#[cfg(test)]
mod tests {
    use crate::arith::gf256::FieldArith as _;

    use super::*;

    #[test]
    fn test_field_mul_matrix_vector_2() {
        let mut out = [0u8; 2];
        let y: [u8; 3] = [2, 3, 4];

        // Identity matrix
        let i: [u8; 2 * 3] = [1, 0, 0, 1, 0, 0];
        field_mul_matrix_vector::<2, 3>(&mut out, &i, 2, 3, &y);
        assert_eq!(out, y[0..2]);

        let mut out = [0u8; 2];
        let mat: [u8; 2 * 3] = [40, 203, 210, 253, 50, 23];
        field_mul_matrix_vector::<2, 3>(&mut out, &mat, 2, 3, &y);
        assert_eq!(
            out,
            [
                mat[0]
                    .field_mul(y[0])
                    .field_add(mat[2].field_mul(y[1]))
                    .field_add(mat[4].field_mul(y[2])),
                mat[1]
                    .field_mul(y[0])
                    .field_add(mat[3].field_mul(y[1]))
                    .field_add(mat[5].field_mul(y[2])),
            ]
        );
    }

    #[test]
    fn test_field_mul_matrix_vector_32() {
        // Testing for simd
        let mut out = [0u8; 32];
        // Matrix is a 32x3 matrix
        let matrix: [u8; 32 * 3] = [
            40, 203, 210, 253, 50, 23, 192, 187, 103, 8, 200, 163, 86, 118, 177, 244, 181, 224, 27,
            79, 167, 251, 133, 10, 217, 92, 190, 105, 242, 174, 3, 63, 37, 32, 246, 182, 80, 82,
            14, 99, 144, 24, 2, 165, 238, 215, 150, 62, 194, 115, 75, 34, 201, 159, 202, 219, 49,
            216, 241, 101, 209, 77, 29, 85, 96, 91, 58, 56, 11, 71, 69, 16, 47, 93, 36, 126, 38,
            248, 118, 70, 1, 13, 4, 57, 45, 107, 98, 5, 84, 76, 68, 78, 19, 9, 21, 112,
        ];
        let y: [u8; 3] = [2, 3, 4];
        field_mul_matrix_vector::<32, 3>(&mut out, &matrix, 32, 3, &y);
        assert_eq!(
            out,
            [
                164, 154, 86, 192, 184, 223, 134, 136, 217, 87, 29, 74, 29, 67, 27, 178, 40, 122,
                251, 28, 161, 224, 199, 118, 177, 224, 100, 94, 219, 180, 117, 90
            ]
        );
    }
}
