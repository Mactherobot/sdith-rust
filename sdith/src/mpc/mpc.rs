use crate::{
    constants::{
        params::{PARAM_ETA, PARAM_L, PARAM_LOG_N, PARAM_SPLITTING_FACTOR, PARAM_T, PARAM_TAU},
        types::{Hash, Salt, Seed},
    },
    subroutines::prg::prg::PRG,
    witness::WitnessPlain,
};

use super::{
    beaver::{Beaver, BeaverABPlain, BeaverCPlain},
    challenge::Challenge,
};

#[derive(Debug)]
pub(crate) struct MPC {}

/// A bit mask that ensures the value generated in expand_view_challenges is within 1:PARAM_N
const MASK: u16 = (1 << PARAM_LOG_N) - 1;

const BROAD_PLAIN_LENGTH = 2 * PARAM_SPLITTING_FACTOR * PARAM_T * PARAM_ETA;

impl MPC {
    pub(crate) fn generate_beaver_plain(mseed: Seed, salt: Salt) -> (BeaverABPlain, BeaverCPlain) {
        Beaver::generate_beaver_plain(mseed, salt)
    }

    pub(crate) fn expand_mpc_challenges(n: usize) -> Vec<Challenge> {
        Challenge::generate_plain(n)
    }

    /// Sample the view challenges for the MPC protocol. The view challenges are sampled from a set {}
    pub(crate) fn expand_view_challenges_threshold(h2: Hash) -> [[u16; PARAM_L]; PARAM_TAU] {
        let mut prg = PRG::init_base(&h2);
        let mut view_challenges = [[0u16; PARAM_L]; PARAM_TAU];
        let mut tmp = [0u8; 2];
        for i in 0..PARAM_TAU {
            for j in 0..PARAM_L {
                prg.sample_field_fq_non_zero(&mut tmp);
                let mut value: u16 = u16::from_le_bytes(tmp);
                value &= MASK;
                view_challenges[i][j] = value
            }
        }

        view_challenges
    }

    /// computes the publicly recomputed values of the MPC protocol (i.e. the plain
    /// values corresponding to the broadcasted shares). It takes as input the plain input of the MPC
    /// protocol, made of the witness (sA , Q′ , P ) and the Beaver triples (a, b, c), the syndrome decoding
    /// instance (H ′ , y), and the MPC challenge (r, ε). From these inputs, it computes and returns the
    /// plain broadcast values (α, β). Note that the subroutine does not recompute v which is always
    /// zero.
    /// Input: (wit plain, beav ab plain, beav c plain), chal, (H′, y)
    pub(crate) fn compute_plain_broadcast(
        wit_plain: WitnessPlain,
        beav_plain: (BeaverABPlain, BeaverCPlain),
        chal_plain: Challenge,
        (h_prime, y): (Vec<u8>, Vec<u8>),
    ) -> [u8; BROAD_PLAIN_LENGTH] {
        let 
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
    use crate::constants::params::{PARAM_DIGEST_SIZE, PARAM_N};

    use super::*;

    #[test]
    fn test_expand_view_challenges_threshold() {
        let mut prg = PRG::init_base(&[0]);
        let mut h2 = [0u8; PARAM_DIGEST_SIZE];
        for _ in 0..1000 {
            prg.sample_field_fq_elements(&mut h2);
            let view_challenges = MPC::expand_view_challenges_threshold(h2);
            assert_eq!(view_challenges.len(), PARAM_TAU);
            for view_challenge in view_challenges {
                assert_eq!(view_challenge.len(), PARAM_L);
                for &x in view_challenge.iter() {
                    assert_ne!(x, 0, "View challenge should not be zero: {}", x);
                    assert!(
                        x as usize <= PARAM_N,
                        "View challenge should be less than N: {} <= {}",
                        x,
                        PARAM_N as u8
                    );
                }
            }
        }
    }
}
