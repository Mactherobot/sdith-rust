use crate::{
    arith::{
        arrays::{Array2D, Array2DTrait},
        gf256::{gf256_ext::FPoint, FieldArith},
    },
    constants::params::{PARAM_ETA, PARAM_SPLITTING_FACTOR, PARAM_T},
    subroutines::prg::prg::PRG,
};

/// (t * 2d)η
pub(crate) const BEAVER_ABPLAIN_SIZE: usize = PARAM_ETA * PARAM_T * PARAM_SPLITTING_FACTOR * 2;
/// tη
pub(crate) const BEAVER_CPLAIN_SIZE: usize = PARAM_ETA * PARAM_T;

/// Beaver triples implementation
#[derive(Debug, PartialEq, Clone)]
pub(crate) struct Beaver {
    /// Point x PARAM_T x PARAM_SPLITTING_FACTOR
    pub(super) a: Array2D<FPoint>,
    pub(super) b: Array2D<FPoint>,
    pub(super) c: Vec<FPoint>,
}

impl Default for Beaver {
    fn default() -> Self {
        Self {
            a: Array2D::new(PARAM_T, PARAM_SPLITTING_FACTOR),
            b: Array2D::new(PARAM_T, PARAM_SPLITTING_FACTOR),
            c: vec![FPoint::default(); PARAM_T],
        }
    }
}

impl Beaver {
    /// Generate serialised beaver a and b values
    pub(crate) fn generate_beaver_triples(prg: &mut PRG) -> Self {
        let mut beaver: Self = Default::default();

        for d in 0..PARAM_SPLITTING_FACTOR {
            prg.sample_field_fpoint_elements(&mut beaver.a.get_row_mut(d));
            prg.sample_field_fpoint_elements(&mut beaver.b.get_row_mut(d));
        }

        beaver.calc_inner_product();
        beaver
    }

    pub(crate) fn calc_inner_product(&mut self) {
        for d in 0..PARAM_SPLITTING_FACTOR {
            for j in 0..PARAM_T {
                self.c[j] = self.c[j].field_add(self.a.get(d, j).field_mul(self.b.get(d, j)));
            }
        }
    }

    /// Serialise beaver a and b values
    pub(crate) fn serialise(&self) -> Vec<u8> {
        let mut plain = Vec::with_capacity(BEAVER_ABPLAIN_SIZE + BEAVER_CPLAIN_SIZE);

        // Serialise a
        for d in 0..PARAM_SPLITTING_FACTOR {
            for i in 0..PARAM_T {
                plain.extend_from_slice(&self.a.get(d, i));
            }
        }

        // Serialise b
        for d in 0..PARAM_SPLITTING_FACTOR {
            for i in 0..PARAM_T {
                plain.extend_from_slice(&self.b.get(d, i));
            }
        }

        // Serialise c
        for i in 0..PARAM_T {
            plain.extend_from_slice(&self.c[i]);
        }

        plain
    }

    pub(crate) fn parse(beaver_plain: Vec<u8>) -> Self {
        let mut offset = 0;
        let mut beaver: Self = Default::default();

        // Deserialise a
        for d in 0..PARAM_SPLITTING_FACTOR {
            for i in 0..PARAM_T {
                beaver.a.set(
                    d,
                    i,
                    beaver_plain[offset..(offset + PARAM_ETA)]
                        .try_into()
                        .unwrap(),
                );
                offset += PARAM_ETA;
            }
        }

        // Deserialise b
        for d in 0..PARAM_SPLITTING_FACTOR {
            for i in 0..PARAM_T {
                beaver.b.set(
                    d,
                    i,
                    beaver_plain[offset..(offset + PARAM_ETA)]
                        .try_into()
                        .unwrap(),
                );
                offset += PARAM_ETA;
            }
        }

        // Deserialise c
        for i in 0..PARAM_T {
            beaver.c[i] = beaver_plain[offset..(offset + PARAM_ETA)]
                .try_into()
                .unwrap();
            offset += PARAM_ETA;
        }

        beaver
    }
}

#[cfg(test)]
mod beaver_tests {
    use super::*;
    use crate::constants::params::{PARAM_SALT_SIZE, PARAM_SEED_SIZE};

    #[test]
    fn test_generate() {
        let mseed = [0u8; PARAM_SEED_SIZE];
        let salt = [0u8; PARAM_SALT_SIZE];
        let mut prg = PRG::init(&mseed, Some(&salt));
        let mut beaver = Beaver::generate_beaver_triples(&mut prg);

        for d in 0..PARAM_SPLITTING_FACTOR {
            for j in 0..PARAM_T {
                assert_eq!(beaver.a.get(d, j).len(), PARAM_ETA);
                assert_eq!(beaver.b.get(d, j).len(), PARAM_ETA);

                // Check that c = sum_d(a[d] * b[d]). Add is the same as substract
                beaver.c[j] =
                    beaver.c[j].field_add(beaver.a.get(d, j).field_mul(beaver.b.get(d, j)));
            }
        }

        for j in 0..PARAM_T {
            // Should be zero
            assert_eq!(beaver.c[j], [0u8; 4]);
        }
    }

    #[test]
    fn test_serialise() {
        let mut prg = PRG::init(&[0u8; PARAM_SEED_SIZE], Some(&[0u8; PARAM_SALT_SIZE]));
        let beaver = Beaver::generate_beaver_triples(&mut prg);

        let plain = beaver.serialise();

        assert_eq!(plain.len(), BEAVER_ABPLAIN_SIZE + BEAVER_CPLAIN_SIZE);

        let beaver_des = Beaver::parse(plain);

        assert_eq!(beaver, beaver_des);
    }
}
