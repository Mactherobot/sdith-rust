//! # Beaver
//!
//! Computes the beaver triples a and b and the inner product c
//! Beaver triples are used in the MPC computation as precomputed multiplication triples.
//! They are sacrificed in the broadcasting phase to save on communication costs.

use std::iter::zip;

use crate::{
    arith::gf256::{gf256_ext::FPoint, FieldArith},
    constants::params::{PARAM_ETA, PARAM_SPLITTING_FACTOR, PARAM_T},
    subroutines::prg::PRG,
};

/// Beaver triple a
pub type BeaverA = [[FPoint; PARAM_T]; PARAM_SPLITTING_FACTOR];
/// Beaver triple b
pub type BeaverB = [[FPoint; PARAM_T]; PARAM_SPLITTING_FACTOR];
/// Beaver triple c = a * b
pub type BeaverC = [FPoint; PARAM_T];

/// (t * 2d)η
pub const BEAVER_ABPLAIN_SIZE: usize = PARAM_ETA * PARAM_T * PARAM_SPLITTING_FACTOR * 2;
/// tη
pub const BEAVER_CPLAIN_SIZE: usize = PARAM_ETA * PARAM_T;

/// Generate serialised beaver a and b values
pub fn generate_beaver_triples(prg: &mut PRG) -> (BeaverA, BeaverB, BeaverC) {
    let mut a: BeaverA = Default::default();
    let mut b: BeaverA = Default::default();

    for d in 0..PARAM_SPLITTING_FACTOR {
        prg.sample_field_fpoint_elements(&mut a[d]);
        prg.sample_field_fpoint_elements(&mut b[d]);
    }

    (a, b, inner_product(a, b))
}

/// Computes the inner procuct of two gf256 points
pub fn inner_product(a: BeaverA, b: BeaverB) -> BeaverC {
    let mut c: BeaverC = [FPoint::default(); PARAM_T];

    for d in 0..PARAM_SPLITTING_FACTOR {
        let ab = zip(a[d], b[d]);
        for (j, (aj, bj)) in ab.enumerate() {
            c[j] = c[j].field_add(aj.field_mul(bj));
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

    a.iter().for_each(|ad| {
        ad.iter().for_each(|adi| {
            adi.iter().for_each(|adij| {
                plain[offset] = *adij;
                offset += 1;
            });
        });
    });

    // Serialise b
    b.iter().for_each(|bd| {
        bd.iter().for_each(|bdi| {
            bdi.iter().for_each(|bdij| {
                plain[offset] = *bdij;
                offset += 1;
            })
        })
    });

    // Serialise c
    c.iter().for_each(|ci| {
        ci.iter().for_each(|cij| {
            plain[offset] = *cij;
            offset += 1;
        })
    });

    plain
}

/// Parses the beaver triples from a byte array
pub fn parse(
    beaver_abc_plain: [u8; BEAVER_ABPLAIN_SIZE + BEAVER_CPLAIN_SIZE],
) -> (BeaverA, BeaverB, BeaverC) {
    let mut offset = 0;
    let mut a: BeaverA = Default::default();
    let mut b: BeaverB = Default::default();
    let mut c: BeaverC = [FPoint::default(); PARAM_T];

    // Deserialise a
    (0..PARAM_SPLITTING_FACTOR).for_each(|d| {
        for i in 0..PARAM_T {
            for j in 0..PARAM_ETA {
                a[d][i][j] = beaver_abc_plain[offset];
                offset += 1;
            }
        }
    });

    // Deserialise b
    (0..PARAM_SPLITTING_FACTOR).for_each(|d| {
        for i in 0..PARAM_T {
            for j in 0..PARAM_ETA {
                b[d][i][j] = beaver_abc_plain[offset];
                offset += 1;
            }
        }
    });

    // Deserialise c
    (0..PARAM_T).for_each(|i| {
        for j in 0..PARAM_ETA {
            c[i][j] = beaver_abc_plain[offset];
            offset += 1;
        }
    });

    (a, b, c)
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

        let mut c = inner_product(a, b);

        for d in 0..PARAM_SPLITTING_FACTOR {
            (0..PARAM_T).for_each(|j| {
                assert_eq!(a[d][j].len(), PARAM_ETA);
                assert_eq!(b[d][j].len(), PARAM_ETA);

                // Check that c = sum_d(a[d] * b[d]). Add is the same as substract
                c[j] = c[j].field_add(a[d][j].field_mul(b[d][j]));
            });
        }

        (0..PARAM_T).for_each(|j| {
            // Should be zero
            assert_eq!(c[j], [0u8; 4]);
        });
    }

    #[test]
    fn test_generate() {
        let mseed = [0u8; PARAM_SEED_SIZE];
        let salt = [0u8; PARAM_SALT_SIZE];
        let mut prg = PRG::init(&mseed, Some(&salt));
        let (a, b, c) = generate_beaver_triples(&mut prg);

        assert_eq!(a.len(), PARAM_SPLITTING_FACTOR);
        assert_eq!(b.len(), PARAM_SPLITTING_FACTOR);
        assert_eq!(c.len(), PARAM_T);

        c.iter().for_each(|ci| {
            assert_eq!(ci.len(), PARAM_ETA);
        });
    }

    #[test]
    fn test_serialise() {
        let mut prg = PRG::init(&[0u8; PARAM_SEED_SIZE], Some(&[0u8; PARAM_SALT_SIZE]));
        let (a, b, c) = generate_beaver_triples(&mut prg);

        let plain = serialise(a, b, c);

        assert_eq!(plain.len(), BEAVER_ABPLAIN_SIZE + BEAVER_CPLAIN_SIZE);

        let (a_des, b_des, c_des) = parse(plain);

        assert_eq!(a, a_des);
        assert_eq!(b, b_des);
        assert_eq!(c, c_des);
    }
}
