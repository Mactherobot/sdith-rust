// pub (crate) mod modular_arithmetics;
pub(crate) mod beaver_triples;
pub(crate) mod gf256;
pub(crate) mod matrices;
pub(crate) mod vectors;

/// Sum of ones in a byte array
pub(crate) fn hamming_weight(x: &[u8]) -> u64 {
    x.iter().fold(0, |a, b| a + b.count_ones() as u64)
}
