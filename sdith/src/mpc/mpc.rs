use crate::{
    arith::{
        gf256::gf256_ext::{gf256_ext32_add, gf256_ext32_mul},
        vectors::serialize,
    },
    constants::{
        params::{PARAM_ETA, PARAM_L, PARAM_SPLITTING_FACTOR, PARAM_T, PARAM_TAU},
        types::{Salt, Seed},
    },
    subroutines::prg::{hashing::HASH_PREFIX_CHALLENGE_2, prg::PRG},
    witness::WitnessPlain,
};

use super::{
    beaver::{Beaver, BeaverABPlain, BeaverCPlain},
    challenge::Challenge,
};

#[derive(Debug)]
pub(crate) struct MPC {}

impl MPC {
    pub(crate) fn generate_beaver_plain(mseed: Seed, salt: Salt) -> (BeaverABPlain, BeaverCPlain) {
        Beaver::generate_beaver_plain(mseed, salt)
    }

    pub(crate) fn expand_mpc_challenges(n: usize) -> Vec<Challenge> {
        Challenge::generate_n(n)
    }

    pub(crate) fn expand_view_challenges_threshold() -> [[u8; PARAM_L]; PARAM_TAU] {
        let mut prg = PRG::init_base(&HASH_PREFIX_CHALLENGE_2);
        let mut view_challenges = [[0u8; PARAM_L]; PARAM_TAU];
        for i in 0..PARAM_TAU {
            view_challenges[i] = prg.sample_field_elements_gf256::<PARAM_L>();
        }
        view_challenges
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
