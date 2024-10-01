use core::hash;

use crate::{
    arith::{
        gf256::gf256_ext::{gf256_ext32_add, gf256_ext32_mul},
        vectors::{parse, serialize},
    },
    constants::{
        params::{PARAM_EXT_DEGREE, PARAM_NB_EVALS_PER_POLY, PARAM_SPLITTING_FACTOR},
        types::{Hash, Salt, Seed},
    },
    subroutines::prg::prg::PRG,
    witness::WitnessPlain,
};

#[derive(Debug)]
pub(crate) struct MPC {}

type BeaverA = [[[u8; PARAM_EXT_DEGREE]; PARAM_NB_EVALS_PER_POLY]; PARAM_SPLITTING_FACTOR];
type BeaverB = [[[u8; PARAM_EXT_DEGREE]; PARAM_NB_EVALS_PER_POLY]; PARAM_SPLITTING_FACTOR];

const BeaverABPlainSize: usize =
    PARAM_EXT_DEGREE * PARAM_NB_EVALS_PER_POLY * PARAM_SPLITTING_FACTOR * 2;
type BeaverABPlain = [u8; BeaverABPlainSize];
const BeaverCPlainSize: usize = PARAM_EXT_DEGREE * PARAM_NB_EVALS_PER_POLY;
type BeaverCPlain = [u8; BeaverCPlainSize];

impl MPC {
    fn generate_beaver_ab_plain(mseed: Seed, salt: Salt) -> BeaverABPlain {
        let mut prg = PRG::init(&mseed, Some(&salt));
        let beaver_ab_plain: [u8; BeaverABPlainSize] = prg
            .sample_field_elements_gf256(BeaverABPlainSize)
            .try_into()
            .unwrap();
        beaver_ab_plain
    }

    pub(crate) fn generate_beaver_plain(mseed: Seed, salt: Salt) -> (BeaverABPlain, BeaverCPlain) {
        let beaver_ab_plain = MPC::generate_beaver_ab_plain(mseed, salt);
        let (a, b) = MPC::parse_ab_plain(beaver_ab_plain);

        let mut c = [[0u8; PARAM_EXT_DEGREE]; PARAM_NB_EVALS_PER_POLY];

        for i in 0..PARAM_NB_EVALS_PER_POLY {
            // Update the c value
            for j in 0..PARAM_SPLITTING_FACTOR {
                c[i] = gf256_ext32_add(c[i], gf256_ext32_mul(a[j][i], b[j][i]));
            }
        }

        let beaver_c_plain = serialize::<
            { PARAM_EXT_DEGREE * PARAM_NB_EVALS_PER_POLY },
            PARAM_EXT_DEGREE,
        >(c.to_vec());

        (beaver_ab_plain, beaver_c_plain)
    }

    pub(crate) fn parse_ab_plain(ab_plain: BeaverABPlain) -> (BeaverA, BeaverB) {
        {
            let [a, b] = parse::<
                2,
                { PARAM_EXT_DEGREE * PARAM_NB_EVALS_PER_POLY * PARAM_SPLITTING_FACTOR },
            >(
                &ab_plain.to_vec(),
                vec![
                    PARAM_EXT_DEGREE * PARAM_NB_EVALS_PER_POLY * PARAM_SPLITTING_FACTOR,
                    PARAM_EXT_DEGREE * PARAM_NB_EVALS_PER_POLY * PARAM_SPLITTING_FACTOR,
                ],
            );

            let mut a_out: BeaverA =
                [[[0u8; PARAM_EXT_DEGREE]; PARAM_NB_EVALS_PER_POLY]; PARAM_SPLITTING_FACTOR];
            let mut b_out: BeaverB =
                [[[0u8; PARAM_EXT_DEGREE]; PARAM_NB_EVALS_PER_POLY]; PARAM_SPLITTING_FACTOR];

            let mut d_off = 0;
            for d in 0..PARAM_SPLITTING_FACTOR {
                let length = PARAM_EXT_DEGREE * PARAM_NB_EVALS_PER_POLY;
                let _a = parse::<PARAM_NB_EVALS_PER_POLY, PARAM_EXT_DEGREE>(
                    &a[(d + d_off)..(d + d_off + length)].to_vec(),
                    vec![PARAM_EXT_DEGREE; PARAM_NB_EVALS_PER_POLY],
                );
                let _b = parse::<PARAM_NB_EVALS_PER_POLY, PARAM_EXT_DEGREE>(
                    &b[(d + d_off)..(d + d_off + length)].to_vec(),
                    vec![PARAM_EXT_DEGREE; PARAM_NB_EVALS_PER_POLY],
                );

                for i in 0..PARAM_NB_EVALS_PER_POLY {
                    a_out[d][i] = _a[i];
                    b_out[d][i] = _b[i];
                }
                d_off += length;
            }

            return (a_out, b_out);
        }
    }

    pub(crate) fn parse_c_plain(
        c_plain: BeaverCPlain,
    ) -> [[u8; PARAM_EXT_DEGREE]; PARAM_NB_EVALS_PER_POLY] {
        parse::<PARAM_NB_EVALS_PER_POLY, PARAM_EXT_DEGREE>(
            &c_plain.to_vec(),
            vec![PARAM_EXT_DEGREE; PARAM_NB_EVALS_PER_POLY],
        )
    }

    pub(crate) fn expanc_mpc_challenge(
        hash: Hash,
        number_of_pairs: usize,
    ) -> (
        [u8; PARAM_EXT_DEGREE * PARAM_NB_EVALS_PER_POLY],
        [u8; PARAM_EXT_DEGREE * PARAM_NB_EVALS_PER_POLY * PARAM_SPLITTING_FACTOR],
    ) {
        let mut prg = PRG::init(&hash, None);
        let v = prg.sample_field_elements_gf256(
            number_of_pairs
                * PARAM_EXT_DEGREE
                * PARAM_NB_EVALS_PER_POLY
                * (PARAM_SPLITTING_FACTOR + 1),
        );

        todo!("Implement the expanc MPC challenge")
    }

    /// computes the publicly recomputed values of the MPC protocol (i.e. the plain
    /// values corresponding to the broadcasted shares). It takes as input the plain input of the MPC
    /// protocol, made of the witness (sA , Q′ , P ) and the Beaver triples (a, b, c), the syndrome decoding
    /// instance (H ′ , y), and the MPC challenge (r, ε). From these inputs, it computes and returns the
    /// plain broadcast values (α, β). Note that the subroutine does not recompute v which is always
    /// zero.
    pub(crate) fn compute_plain_broadcast(witness: WitnessPlain) -> (Vec<u8>, Vec<u8>) {
        // TODO: implement marshalling of the beaver triples
        todo!("Implement the marshalling of the beaver triples")
    }

    pub(crate) fn party_computation() {
        todo!("Implement the party computation")
    }

    pub(crate) fn inverse_party_computation() {
        todo!("Implement the inverse party computation")
    }
}

#[cfg(test)]
mod mpc_tests {
    use super::*;
    use crate::constants::params::{PARAM_SALT_SIZE, PARAM_SEED_SIZE};

    #[test]
    fn test_beaver_ab_marshalling() {
        let mseed = [0u8; PARAM_SEED_SIZE];
        let salt = [0u8; PARAM_SALT_SIZE];
        let (ab_plain, c_plain) = MPC::generate_beaver_plain(mseed, salt);

        assert!(ab_plain.len() == BeaverABPlainSize);
        assert!(c_plain.len() == BeaverCPlainSize);

        // Test parse ab_plain
        let (a, b) = MPC::parse_ab_plain(ab_plain);

        // Assert that the marshalled values are not all zero
        assert_ne!(
            a,
            [[[0u8; PARAM_EXT_DEGREE]; PARAM_NB_EVALS_PER_POLY]; PARAM_SPLITTING_FACTOR]
        );
        assert_ne!(
            b,
            [[[0u8; PARAM_EXT_DEGREE]; PARAM_NB_EVALS_PER_POLY]; PARAM_SPLITTING_FACTOR]
        );

        assert!(a.len() == PARAM_SPLITTING_FACTOR);
        assert!(b.len() == PARAM_SPLITTING_FACTOR);

        assert!(a[0].len() == PARAM_NB_EVALS_PER_POLY);
        assert!(b[0].len() == PARAM_NB_EVALS_PER_POLY);

        assert!(a[0][0].len() == PARAM_EXT_DEGREE);
        assert!(b[0][0].len() == PARAM_EXT_DEGREE);

        // Test parse c_plain
        let mut c = MPC::parse_c_plain(c_plain);

        // Assert that the marshalled values are not all zero
        assert_ne!(c, [[0u8; PARAM_EXT_DEGREE]; PARAM_NB_EVALS_PER_POLY]);

        assert!(c.len() == PARAM_NB_EVALS_PER_POLY);
        assert!(c[0].len() == PARAM_EXT_DEGREE);

        // Test that the values are consistent
        for d in 0..PARAM_SPLITTING_FACTOR {
            for i in 0..PARAM_NB_EVALS_PER_POLY {
                c[i] = gf256_ext32_add(c[i], gf256_ext32_mul(a[d][i], b[d][i]));
            }
        }

        assert_eq!(c, [[0u8; PARAM_EXT_DEGREE]; PARAM_NB_EVALS_PER_POLY]);
    }
}
