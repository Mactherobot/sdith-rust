use crate::subroutines::prg::prg::PRG;

use super::gf256;

pub(crate) fn generate_beaver_triple_gf256(prg: &mut PRG) -> (u8, u8, u8) {
    let [a, b] = prg.sample_field_elements_gf256(2).try_into().unwrap();
    let c = gf256::gf256_arith::gf256_mul(a, b);
    (a, b, c)
}

pub(crate) fn generate_beaver_triples_ext32(prg: &mut PRG) -> ([u8; 4], [u8; 4], [u8; 4]) {
    let a: [u8; 4] = prg.sample_field_elements_gf256(4).try_into().unwrap();
    let b: [u8; 4] = prg.sample_field_elements_gf256(4).try_into().unwrap();
    let c = gf256::gf256_ext::gf256_ext32_mul(a, b);
    (a, b, c)
}

#[cfg(test)]
mod tests {
    use crate::constants::params::PARAM_SEED_SIZE;

    use super::*;
    #[test]
    fn test_generate_beaver_triple_gf256() {
        let (a, b, c) = generate_beaver_triple_gf256(&mut PRG::init(&[0u8; PARAM_SEED_SIZE], None));
        assert_eq!(c, gf256::gf256_arith::gf256_mul(a, b));
    }

    #[test]
    fn test_generate_beaver_triples_ext32() {
        let (a, b, c) =
            generate_beaver_triples_ext32(&mut PRG::init(&[0u8; PARAM_SEED_SIZE], None));
        assert_eq!(c, gf256::gf256_ext::gf256_ext32_mul(a, b));
    }
}
