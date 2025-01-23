//! # Verification
//!
//! Verifies a signature using the message and the public key.
//!
//! The verification process involves:
//! 1. Computing the commitments_prime by running the [`inverse_party_computation`].
//! 2. Computing the Merkle root from the computed commitments_prime and the authentication path using [`get_merkle_root_from_auth`].
//! 3. Verifying the signature using the Merkle root.

use crate::{
    constants::{
        params::{PARAM_DIGEST_SIZE, PARAM_L, PARAM_TAU},
        types::Hash,
    },
    keygen::PublicKey,
    subroutines::{
        arithmetics::gf256::matrices::{gen_hmatrix, HPrimeMatrix},
        challenge::MPCChallenge,
        commitments::{self},
        merkle_tree::{MerkleTree, MerkleTreeTrait as _},
        mpc::{
            self,
            beaver::BeaverTriples,
            broadcast::{
                Broadcast, BroadcastShare, BROADCAST_SHARE_PLAIN_SIZE,
                BROADCAST_SHARE_PLAIN_SIZE_AB,
            },
            input::{self, Input},
        },
    },
    utils::marshalling::Marshalling,
};

use super::Signature;

impl Signature {
    /// Verify a plain signature given a [`PublicKey`]
    pub fn verify_signature(public_key: &PublicKey, signature: &Vec<u8>) -> Result<bool, String> {
        // Expansion of the parity matrix H'
        let h_prime: HPrimeMatrix = gen_hmatrix(public_key.seed_h);

        // Signature parsing
        // This function recomputes the hash `h2` and the resulting view opening challenges from the signature.
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

        // Recompute First challenge (MPC challenge)
        let chal = MPCChallenge::new(h1);

        let broadcast = Broadcast::parse(&broad_plain)?;
        let mut sh_broadcast = [[[0u8; BROADCAST_SHARE_PLAIN_SIZE]; PARAM_L]; PARAM_TAU];
        let mut commitments: [Hash; PARAM_TAU] = [[0u8; PARAM_DIGEST_SIZE]; PARAM_TAU];

        // Inverse MPC computation and regeneration of Merkle commitments
        let mut plain = [0u8; BROADCAST_SHARE_PLAIN_SIZE];
        plain[..BROADCAST_SHARE_PLAIN_SIZE_AB].copy_from_slice(&broad_plain);
        for e in 0..PARAM_TAU {
            let mut commitments_prime = [[0u8; PARAM_DIGEST_SIZE]; PARAM_L];
            for (li, i) in view_opening_challenges[e].iter().enumerate() {
                let with_offset = (*i as usize) != 0;

                // We need to compute the following:
                // sh_broadcast[e][i] = (broad_plain, 0) + sum^ℓ_(j=1) fi^j · broad_share[e][j]
                let f_i = i.to_le_bytes()[0];

                sh_broadcast[e][li] =
                    input::compute_share(&plain, &broadcast_shares[e], f_i, *i == 0u16);

                // Recompute beaver triples
                let broadcast_share = BroadcastShare::parse(&sh_broadcast[e][li])?;
                let beaver_triples = mpc::inverse_party_computation(
                    wit_share[e][li],
                    &broadcast_share,
                    &chal,
                    h_prime,
                    public_key.y,
                    &broadcast,
                    with_offset,
                )?;

                let input_share = Input::append_beaver_triples(
                    wit_share[e][li],
                    BeaverTriples::new(beaver_triples.0, beaver_triples.1, beaver_triples.2),
                );

                // Recompute commitment
                commitments_prime[li] =
                    commitments::commit_share(&salt, e as u16, *i, &input_share);
            }

            let Ok(root) = MerkleTree::get_root_from_auth_path(
                &mut auth[e],
                &commitments_prime,
                &view_opening_challenges[e],
                #[cfg(feature = "kat")]
                None,
                #[cfg(not(feature = "kat"))]
                Some(salt),
            ) else {
                return Err("Merkle root verification failed".to_string());
            };
            commitments[e] = root;
        }

        // Recompute h1' and compare with h1
        if h1 == Signature::gen_h1(&public_key.seed_h, &public_key.y, salt, commitments) {
            Ok(true)
        } else {
            Err("Hashes do not match".to_string())
        }
    }
}
