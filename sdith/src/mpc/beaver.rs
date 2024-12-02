use crate::{
    arith::gf256::{gf256_ext::FPoint, FieldArith},
    constants::params::{PARAM_ETA, PARAM_SPLITTING_FACTOR, PARAM_T},
    subroutines::prg::PRG,
};

pub type BeaverA = [[FPoint; PARAM_T]; PARAM_SPLITTING_FACTOR];
pub type BeaverB = [[FPoint; PARAM_T]; PARAM_SPLITTING_FACTOR];
pub type BeaverC = [FPoint; PARAM_T];

/// (t * 2d)η
pub const BEAVER_ABPLAIN_SIZE: usize = PARAM_ETA * PARAM_T * PARAM_SPLITTING_FACTOR * 2;
/// tη
pub const BEAVER_CPLAIN_SIZE: usize = PARAM_ETA * PARAM_T;

/// Beaver triples implementation
pub struct Beaver {}

impl Beaver {
    /// Generate serialised beaver a and b values
    pub fn generate_beaver_triples(prg: &mut PRG) -> (BeaverA, BeaverB, BeaverC) {
        let mut a: BeaverA = Default::default();
        let mut b: BeaverA = Default::default();

        for d in 0..PARAM_SPLITTING_FACTOR {
            prg.sample_field_fpoint_elements(&mut a[d]);
            prg.sample_field_fpoint_elements(&mut b[d]);
        }

        (a, b, Beaver::inner_product(a, b))
    }

    pub fn inner_product(a: BeaverA, b: BeaverB) -> BeaverC {
        let mut c: BeaverC = [FPoint::default(); PARAM_T];

        for d in 0..PARAM_SPLITTING_FACTOR {
            for j in 0..PARAM_T {
                c[j] = c[j].field_add(a[d][j].field_mul(b[d][j]));
            }
        }

        c
    }

    /// Serialise beaver a and b values
    pub fn serialise(
        a: BeaverA,
        b: BeaverB,
        c: BeaverC,
    ) -> [u8; BEAVER_ABPLAIN_SIZE + BEAVER_CPLAIN_SIZE] {
        let mut plain = [0u8; BEAVER_ABPLAIN_SIZE + BEAVER_CPLAIN_SIZE];
        let mut offset = 0;

        // Serialise a
        for d in 0..PARAM_SPLITTING_FACTOR {
            for i in 0..PARAM_T {
                for j in 0..PARAM_ETA {
                    plain[offset] = a[d][i][j];
                    offset += 1;
                }
            }
        }

        // Serialise b
        for d in 0..PARAM_SPLITTING_FACTOR {
            for i in 0..PARAM_T {
                for j in 0..PARAM_ETA {
                    plain[offset] = b[d][i][j];
                    offset += 1;
                }
            }
        }

        // Serialise c
        for i in 0..PARAM_T {
            for j in 0..PARAM_ETA {
                plain[offset] = c[i][j];
                offset += 1;
            }
        }

        plain
    }

    pub fn parse(
        beaver_abc_plain: [u8; BEAVER_ABPLAIN_SIZE + BEAVER_CPLAIN_SIZE],
    ) -> (BeaverA, BeaverB, BeaverC) {
        let mut offset = 0;
        let mut a: BeaverA = Default::default();
        let mut b: BeaverB = Default::default();
        let mut c: BeaverC = [FPoint::default(); PARAM_T];

        // Deserialise a
        for d in 0..PARAM_SPLITTING_FACTOR {
            for i in 0..PARAM_T {
                for j in 0..PARAM_ETA {
                    a[d][i][j] = beaver_abc_plain[offset];
                    offset += 1;
                }
            }
        }

        // Deserialise b
        for d in 0..PARAM_SPLITTING_FACTOR {
            for i in 0..PARAM_T {
                for j in 0..PARAM_ETA {
                    b[d][i][j] = beaver_abc_plain[offset];
                    offset += 1;
                }
            }
        }

        // Deserialise c
        for i in 0..PARAM_T {
            for j in 0..PARAM_ETA {
                c[i][j] = beaver_abc_plain[offset];
                offset += 1;
            }
        }

        (a, b, c)
    }
}

#[cfg(test)]
mod beaver_tests {
    use super::*;
    use crate::constants::{
        params::{PARAM_SALT_SIZE, PARAM_SEED_SIZE},
        types::hash_default,
    };

    #[test]
    fn test_inner_product() {
        let mut prg = PRG::init_base(&hash_default());
        let mut a: BeaverA = Default::default();
        let mut b: BeaverB = Default::default();

        for d in 0..PARAM_SPLITTING_FACTOR {
            prg.sample_field_fpoint_elements(&mut a[d]);
            prg.sample_field_fpoint_elements(&mut b[d]);
        }

        let mut c = Beaver::inner_product(a, b);

        for d in 0..PARAM_SPLITTING_FACTOR {
            for j in 0..PARAM_T {
                assert_eq!(a[d][j].len(), PARAM_ETA);
                assert_eq!(b[d][j].len(), PARAM_ETA);

                // Check that c = sum_d(a[d] * b[d]). Add is the same as substract
                c[j] = c[j].field_add(a[d][j].field_mul(b[d][j]));
            }
        }

        for j in 0..PARAM_T {
            // Should be zero
            assert_eq!(c[j], [0u8; 4]);
        }
    }

    #[test]
    fn test_generate() {
        let mseed = [0u8; PARAM_SEED_SIZE];
        let salt = [0u8; PARAM_SALT_SIZE];
        let mut prg = PRG::init(&mseed, Some(&salt));
        let (a, b, c) = Beaver::generate_beaver_triples(&mut prg);

        assert_eq!(a.len(), PARAM_SPLITTING_FACTOR);
        assert_eq!(b.len(), PARAM_SPLITTING_FACTOR);
        assert_eq!(c.len(), PARAM_T);

        for i in 0..PARAM_T {
            assert_eq!(c[i].len(), PARAM_ETA);
        }
    }

    #[test]
    fn test_serialise() {
        let mut prg = PRG::init(&[0u8; PARAM_SEED_SIZE], Some(&[0u8; PARAM_SALT_SIZE]));
        let (a, b, c) = Beaver::generate_beaver_triples(&mut prg);

        let plain = Beaver::serialise(a, b, c);

        assert_eq!(plain.len(), BEAVER_ABPLAIN_SIZE + BEAVER_CPLAIN_SIZE);

        let (a_des, b_des, c_des) = Beaver::parse(plain);

        assert_eq!(a, a_des);
        assert_eq!(b, b_des);
        assert_eq!(c, c_des);
    }
}
