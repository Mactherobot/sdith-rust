use crate::{
    arith::{
        gf256::gf256_ext::{gf256_ext32_add, gf256_ext32_mul},
        vectors::{parse, serialize},
    },
    constants::{
        params::{PARAM_ETA, PARAM_SPLITTING_FACTOR, PARAM_T},
        types::{Salt, Seed},
    },
    subroutines::prg::prg::PRG,
};

pub(super) type BeaverA = [[[u8; PARAM_ETA]; PARAM_T]; PARAM_SPLITTING_FACTOR];
pub(super) type BeaverB = [[[u8; PARAM_ETA]; PARAM_T]; PARAM_SPLITTING_FACTOR];

pub(super) type BeaverC = [[u8; PARAM_ETA]; PARAM_T];

pub(super) const BeaverABPlainSize: usize = PARAM_ETA * PARAM_T * PARAM_SPLITTING_FACTOR * 2;
pub(super) type BeaverABPlain = [u8; BeaverABPlainSize];
pub(super) const BeaverCPlainSize: usize = PARAM_ETA * PARAM_T;
pub(super) type BeaverCPlain = [u8; BeaverCPlainSize];

/// Beaver triples implementation
pub(super) struct Beaver {}

impl Beaver {
    /// Generate serialised beaver a and b values
    pub(super) fn generate_beaver_ab_plain(mseed: Seed, salt: Salt) -> BeaverABPlain {
        let mut prg = PRG::init(&mseed, Some(&salt));
        let beaver_ab_plain: [u8; BeaverABPlainSize] = prg
            .sample_field_elements_gf256_vec(BeaverABPlainSize)
            .try_into()
            .unwrap();
        beaver_ab_plain
    }

    /// Generate serialised beaver triples. The beaver triples are generated as follows:
    /// 1. Generate the beaver a and b values
    /// 2. Compute the beaver c values
    /// 3. Serialize the beaver c values
    pub(super) fn generate_beaver_plain(mseed: Seed, salt: Salt) -> (BeaverABPlain, BeaverCPlain) {
        // Generate the beaver a and b values
        let beaver_ab_plain = Beaver::generate_beaver_ab_plain(mseed, salt);
        // Parse the beaver a and b values
        let (a, b) = Beaver::parse_ab_plain(beaver_ab_plain);

        // Compute the beaver c values
        let mut c = [[0u8; PARAM_ETA]; PARAM_T];
        for i in 0..PARAM_T {
            // Update the c value
            for j in 0..PARAM_SPLITTING_FACTOR {
                c[i] = gf256_ext32_add(c[i], gf256_ext32_mul(a[j][i], b[j][i]));
            }
        }

        // Serialize the beaver c values
        let beaver_c_plain = serialize::<{ PARAM_ETA * PARAM_T }, PARAM_ETA>(c.to_vec());

        (beaver_ab_plain, beaver_c_plain)
    }

    /// Parse the serialised beaver a and b values
    pub(crate) fn parse_ab_plain(ab_plain: BeaverABPlain) -> (BeaverA, BeaverB) {
        {
            let [a, b] = parse::<2, { PARAM_ETA * PARAM_T * PARAM_SPLITTING_FACTOR }>(
                &ab_plain.to_vec(),
                vec![
                    PARAM_ETA * PARAM_T * PARAM_SPLITTING_FACTOR,
                    PARAM_ETA * PARAM_T * PARAM_SPLITTING_FACTOR,
                ],
            );

            let mut a_out: BeaverA = [[[0u8; PARAM_ETA]; PARAM_T]; PARAM_SPLITTING_FACTOR];
            let mut b_out: BeaverB = [[[0u8; PARAM_ETA]; PARAM_T]; PARAM_SPLITTING_FACTOR];

            let mut d_off = 0;
            for d in 0..PARAM_SPLITTING_FACTOR {
                let length = PARAM_ETA * PARAM_T;
                let _a = parse::<PARAM_T, PARAM_ETA>(
                    &a[(d + d_off)..(d + d_off + length)].to_vec(),
                    vec![PARAM_ETA; PARAM_T],
                );
                let _b = parse::<PARAM_T, PARAM_ETA>(
                    &b[(d + d_off)..(d + d_off + length)].to_vec(),
                    vec![PARAM_ETA; PARAM_T],
                );

                for i in 0..PARAM_T {
                    a_out[d][i] = _a[i];
                    b_out[d][i] = _b[i];
                }
                d_off += length;
            }

            return (a_out, b_out);
        }
    }

    /// Parse the serialised beaver c values
    pub(crate) fn parse_c_plain(c_plain: BeaverCPlain) -> BeaverC {
        parse::<PARAM_T, PARAM_ETA>(&c_plain.to_vec(), vec![PARAM_ETA; PARAM_T])
    }
}

#[cfg(test)]
mod beaver_tests {
    use super::*;
    use crate::constants::params::{PARAM_SALT_SIZE, PARAM_SEED_SIZE};

    #[test]
    fn test_beaver_ab_marshalling() {
        let mseed = [0u8; PARAM_SEED_SIZE];
        let salt = [0u8; PARAM_SALT_SIZE];
        let (ab_plain, c_plain) = Beaver::generate_beaver_plain(mseed, salt);

        assert!(ab_plain.len() == BeaverABPlainSize);
        assert!(c_plain.len() == BeaverCPlainSize);

        // Test parse ab_plain
        let (a, b) = Beaver::parse_ab_plain(ab_plain);

        // Assert that the marshalled values are not all zero
        assert_ne!(a, [[[0u8; PARAM_ETA]; PARAM_T]; PARAM_SPLITTING_FACTOR]);
        assert_ne!(b, [[[0u8; PARAM_ETA]; PARAM_T]; PARAM_SPLITTING_FACTOR]);

        assert!(a.len() == PARAM_SPLITTING_FACTOR);
        assert!(b.len() == PARAM_SPLITTING_FACTOR);

        assert!(a[0].len() == PARAM_T);
        assert!(b[0].len() == PARAM_T);

        assert!(a[0][0].len() == PARAM_ETA);
        assert!(b[0][0].len() == PARAM_ETA);

        // Test parse c_plain
        let mut c = Beaver::parse_c_plain(c_plain);

        // Assert that the marshalled values are not all zero
        assert_ne!(c, [[0u8; PARAM_ETA]; PARAM_T]);

        assert!(c.len() == PARAM_T);
        assert!(c[0].len() == PARAM_ETA);

        // Test that the values are consistent
        for d in 0..PARAM_SPLITTING_FACTOR {
            for i in 0..PARAM_T {
                c[i] = gf256_ext32_add(c[i], gf256_ext32_mul(a[d][i], b[d][i]));
            }
        }

        assert_eq!(c, [[0u8; PARAM_ETA]; PARAM_T]);
    }
}
