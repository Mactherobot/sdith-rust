use crate::arith::gf256::gf256_matrices::{gen_hmatrix, HPrimeMatrix};
use crate::constants::params::PARAM_DIGEST_SIZE;
use crate::keygen::PublicKey;
use crate::mpc::beaver::BeaverTriples;
use crate::mpc::broadcast::{Broadcast, BroadcastShare, BROADCAST_SHARE_PLAIN_SIZE_AB};
use crate::mpc::{compute_share, inverse_party_computation};
use crate::subroutines::marshalling::Marshalling;
use crate::subroutines::merkle_tree::get_merkle_root_from_auth;
use crate::{
    constants::{
        params::{PARAM_L, PARAM_TAU},
        types::Hash,
    },
    mpc::{broadcast::BROADCAST_SHARE_PLAIN_SIZE, challenge::Challenge},
    subroutines::commitments::commit_share,
};

use super::{input::Input, signature::Signature};

impl Signature {
    pub fn verify_signature(public_key: &PublicKey, signature: &Vec<u8>) -> Result<bool, String> {
        // Expansion of parity-check matrix
        let h_prime: HPrimeMatrix = gen_hmatrix(public_key.seed_h);

        // Signature parsing
        let signature = Signature::parse(signature)?;
        let (salt, h1, broad_plain, broadcast_shares, wit_share, mut auth, view_opening_challenges) = (
            signature.salt,
            signature.h1,
            signature.broadcast_plain,
            signature.broadcast_shares,
            signature.solution_share,
            signature.auth,
            signature.view_opening_challenges,
        );

        // First challenge (MPC challenge) Only generate one in the case of threshold variant
        let chal = Challenge::new(h1);

        let broadcast = Broadcast::parse(&broad_plain)?;
        let mut sh_broadcast = [[[0u8; BROADCAST_SHARE_PLAIN_SIZE]; PARAM_L]; PARAM_TAU];
        let mut commitments: [Hash; PARAM_TAU] = [[0u8; PARAM_DIGEST_SIZE]; PARAM_TAU];

        // Party computation and regeneration of Merkle commitments
        let mut plain = [0u8; BROADCAST_SHARE_PLAIN_SIZE];
        plain[..BROADCAST_SHARE_PLAIN_SIZE_AB].copy_from_slice(&broad_plain);
        for e in 0..PARAM_TAU {
            let mut commitments_prime = [[0u8; PARAM_DIGEST_SIZE]; PARAM_L];
            for (li, i) in view_opening_challenges[e].iter().enumerate() {
                let with_offset = (*i as usize) != 0;

                // We need to compute the following:
                // sh_broadcast[e][i] = (broad_plain, 0) + sum^ℓ_(j=1) fi^j · broad_share[e][j]
                let f_i = i.to_le_bytes()[0];

                sh_broadcast[e][li] = compute_share(&plain, &broadcast_shares[e], f_i, *i == 0u16);

                // Verify the Merkle path
                let broadcast_share = BroadcastShare::parse(&sh_broadcast[e][li])?;
                let beaver_triples = inverse_party_computation(
                    wit_share[e][li],
                    &broadcast_share,
                    &chal,
                    h_prime,
                    public_key.y,
                    &broadcast,
                    with_offset,
                );

                let input_share = Input::append_beaver_triples(
                    wit_share[e][li],
                    BeaverTriples::new(beaver_triples.0, beaver_triples.1, beaver_triples.2),
                );

                // Commit to the shares
                commitments_prime[li] = commit_share(&salt, e as u16, *i, &input_share);
            }

            let Ok(root) = get_merkle_root_from_auth(
                &mut auth[e],
                &commitments_prime,
                &view_opening_challenges[e],
                None, // TODO: In spec there is a salt here. In implementation there is not.
            ) else {
                return Err("Merkle root verification failed".to_string());
            };
            commitments[e] = root;
        }

        // Compute h1' and compare with h1
        if h1 == Signature::gen_h1(&public_key.seed_h, &public_key.y, salt, commitments) {
            Ok(true)
        } else {
            Err("Hashes do not match".to_string())
        }
    }
}
