use crate::subroutines::prg::prg::PRG;

use super::gf256::{
    self,
    gf256_ext::{gf256_ext32_mul, FPoint},
};

pub(crate) fn generate_beaver_triple_gf256(prg: &mut PRG) -> (u8, u8, u8) {
    let mut ab = [0u8; 2];
    prg.sample_field_fq_elements(&mut ab);
    let [a, b] = ab;
    let c = gf256::gf256_arith::gf256_mul(a, b);
    (a, b, c)
}

pub(crate) fn generate_beaver_triples_ext32(prg: &mut PRG) -> ([u8; 4], [u8; 4], [u8; 4]) {
    let mut ab = [FPoint::default(); 2];
    prg.sample_field_fpoint_elements(&mut ab);
    let [a, b] = ab;

    let c = gf256_ext32_mul(a, b);
    (a, b, c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::params::PARAM_SEED_SIZE;
    use gf256::gf256_arith::gf256_mul;

    #[test]
    fn test_generate_beaver_triple_gf256() {
        let (a, b, c) = generate_beaver_triple_gf256(&mut PRG::init(&[0u8; PARAM_SEED_SIZE], None));
        assert_eq!(c, gf256_mul(a, b));
    }

    #[test]
    fn test_generate_beaver_triples_ext32() {
        let (a, b, c) =
            generate_beaver_triples_ext32(&mut PRG::init(&[0u8; PARAM_SEED_SIZE], None));
        assert_eq!(c, gf256_ext32_mul(a, b));
    }
}
