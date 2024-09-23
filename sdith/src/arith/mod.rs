// pub (crate) mod modular_arithmetics;
pub(crate) mod beaver_triples;
pub(crate) mod gf256;
pub(crate) mod matrices;
pub(crate) mod vectors;

/// Calculate hamming weight of the given vector, which is the number of non-zero elements.
pub(crate) fn hamming_weight_vector(x: &[u8]) -> u64 {
    x.iter().fold(0, |a, b| a + (*b != 0) as u64)
}
