use super::gf256;

pub(crate) fn generate_beaver_triple_gf256() -> (u8, u8, u8) {
    let a = rand::random::<u8>();
    let b = rand::random::<u8>();
    let c = gf256::gf256_arith::gf256_mul(a, b);
    (a, b, c)
}

pub(crate) fn generate_beaver_triples_ext32() -> ([u8; 4], [u8; 4], [u8; 4]) {
    let a = rand::random::<[u8; 4]>();
    let b = rand::random::<[u8; 4]>();
    let c = gf256::gf256_ext::gf256_ext32_mul(a, b);
    (a, b, c)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_generate_beaver_triple_gf256() {
        let (a, b, c) = generate_beaver_triple_gf256();
        assert_eq!(c, gf256::gf256_arith::gf256_mul(a, b));
    }

    #[test]
    fn test_generate_beaver_triples_ext32() {
        let (a, b, c) = generate_beaver_triples_ext32();
        assert_eq!(c, gf256::gf256_ext::gf256_ext32_mul(a, b));
    }
}
