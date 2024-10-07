use crate::{
    arith::gf256::gf256_ext::{gf256_ext32_add, gf256_ext32_mul, FPoint},
    constants::{
        params::{PARAM_ETA, PARAM_SPLITTING_FACTOR, PARAM_T},
        types::{Salt, Seed},
    },
    subroutines::prg::prg::PRG,
};

pub(crate) type BeaverA = [[FPoint; PARAM_T]; PARAM_SPLITTING_FACTOR];
pub(crate) type BeaverB = [[FPoint; PARAM_T]; PARAM_SPLITTING_FACTOR];

pub(crate) type BeaverC = [FPoint; PARAM_T];

pub(super) const BeaverABPlainSize: usize = PARAM_ETA * PARAM_T * PARAM_SPLITTING_FACTOR * 2;
pub(super) type BeaverABPlain = [u8; BeaverABPlainSize];
pub(super) const BeaverCPlainSize: usize = PARAM_ETA * PARAM_T;
pub(super) type BeaverCPlain = [u8; BeaverCPlainSize];

/// Beaver triples implementation
pub(super) struct Beaver {}

impl Beaver {
    /// Generate serialised beaver a and b values
    pub(super) fn generate_beaver_triples(mseed: Seed, salt: Salt) -> (BeaverA, BeaverB, BeaverC) {
        let mut prg = PRG::init(&mseed, Some(&salt));
        let mut a: BeaverA = Default::default();
        let mut b: BeaverA = Default::default();
        let mut c: BeaverC = [FPoint::default(); PARAM_T];

        for d in 0..PARAM_SPLITTING_FACTOR {
            prg.sample_field_fpoint_elements(&mut a[d]);
            prg.sample_field_fpoint_elements(&mut b[d]);

            for i in 0..PARAM_T {
                c[i] = gf256_ext32_add(c[i], gf256_ext32_mul(a[d][i], b[d][i]));
            }
        }

        (a, b, c)
    }

    /// Serialise beaver a and b values
    pub(crate) fn serialise_beaver_triples(
        a: BeaverA,
        b: BeaverB,
        c: BeaverC,
    ) -> [u8; BeaverABPlainSize + BeaverCPlainSize] {
        let mut plain = [0u8; BeaverABPlainSize + BeaverCPlainSize];
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

    pub(crate) fn deserialise(
        beaver_abc_plain: [u8; BeaverABPlainSize + BeaverCPlainSize],
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
    use crate::constants::params::{PARAM_SALT_SIZE, PARAM_SEED_SIZE};

    #[test]
    fn test_generate() {
        let mseed = [0u8; PARAM_SEED_SIZE];
        let salt = [0u8; PARAM_SALT_SIZE];
        let (a, b, mut c) = Beaver::generate_beaver_triples(mseed, salt);

        assert_eq!(a.len(), PARAM_SPLITTING_FACTOR);
        assert_eq!(b.len(), PARAM_SPLITTING_FACTOR);
        assert_eq!(c.len(), PARAM_T);

        for i in 0..PARAM_T {
            assert_eq!(c[i].len(), PARAM_ETA);
        }

        for d in 0..PARAM_SPLITTING_FACTOR {
            for i in 0..PARAM_T {
                assert_eq!(a[d][i].len(), PARAM_ETA);
                assert_eq!(b[d][i].len(), PARAM_ETA);

                // Check that c = sum_d(a[d] * b[d]). Add is the same as substract
                c[i] = gf256_ext32_add(c[i], gf256_ext32_mul(a[d][i], b[d][i]));
            }
        }

        for i in 0..PARAM_T {
            // Should be zero
            assert_eq!(c[i], [0u8; 4]);
        }
    }

    #[test]
    fn test_serialise() {
        let (a, b, c) =
            Beaver::generate_beaver_triples([0u8; PARAM_SEED_SIZE], [0u8; PARAM_SALT_SIZE]);

        let plain = Beaver::serialise_beaver_triples(a, b, c);

        assert_eq!(plain.len(), BeaverABPlainSize + BeaverCPlainSize);

        let (a_des, b_des, c_des) = Beaver::deserialise(plain);

        assert_eq!(a, a_des);
        assert_eq!(b, b_des);
        assert_eq!(c, c_des);
    }
}
