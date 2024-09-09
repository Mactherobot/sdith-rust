use matrix::{format::Compressed, Matrix};

use crate::constants::{PARAM_CODE_DIMENSION, PARAM_CODE_LENGTH, PARAM_SEED_SIZE};

use super::prg::prg::PRG;

/// The number of field elements to sample in the H matrix (m - k) * k
const FIELD_ELEMENTS_TO_SAMPLE: usize =
    (PARAM_CODE_LENGTH - PARAM_CODE_DIMENSION) * PARAM_CODE_DIMENSION;

/// takes as input λ-bit seed seed_H and returns an (m − k) × k matrix of elements of Fq . This generated matrix is the random
/// part H′ of the parity-check matrix in standard form H = (H ′ |Im−k ).
pub(crate) fn expand_H_matrix(seed: &[u8; PARAM_SEED_SIZE]) -> Compressed<u8> {
    let mut prg = PRG::init(seed, None);
    let elements = prg.sample_field_elements_gf256(FIELD_ELEMENTS_TO_SAMPLE);

    let mut matrix = Compressed::<u8>::zero((
        PARAM_CODE_LENGTH - PARAM_CODE_DIMENSION,
        PARAM_CODE_DIMENSION,
    ));

    for i in 1..(PARAM_CODE_LENGTH - PARAM_CODE_DIMENSION) {
        let offset = (i - 1) * PARAM_CODE_DIMENSION;
        for j in 1..PARAM_CODE_DIMENSION {
            matrix.set((i - 1, j - 1), elements[offset + j - 1]);
        }
    }

    return matrix;
}

#[cfg(test)]
mod tests {
    use matrix::Size;

    use super::*;

    #[test]
    fn test_expand_H_matrix() {
        let seed = &[0u8; PARAM_SEED_SIZE];
        let m = expand_H_matrix(seed);

        assert!(m.rows() == PARAM_CODE_LENGTH - PARAM_CODE_DIMENSION);
        assert!(m.columns() == PARAM_CODE_DIMENSION);
    }
}
