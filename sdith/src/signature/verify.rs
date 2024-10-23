use crate::arith::gf256::gf256_vector::gf256_add_vector_with_padding;
use crate::arith::matrices::{gen_hmatrix, HPrimeMatrix};
use crate::keygen::PublicKey;
use crate::mpc::broadcast::{Broadcast, BroadcastShare};
use crate::subroutines::merkle_tree::get_merkle_root_from_auth;
use crate::{
    arith::gf256::{
        gf256_vector::{gf256_add_vector, gf256_add_vector_mul_scalar},
        FieldArith,
    },
    constants::{
        params::{PARAM_L, PARAM_N, PARAM_TAU},
        types::Hash,
    },
    mpc::{broadcast::BROADCAST_SHARE_PLAIN_SIZE, challenge::Challenge, mpc::MPC},
    subroutines::commitments::commit_share,
};

use super::{input::Input, signature::Signature};

impl Signature {
    pub(crate) fn verify_signature(
        public_key: PublicKey,
        signature: Signature,
        message: &Vec<u8>,
    ) -> Result<bool, &'static str> {
        // Expansion of parity-check matrix
        let h_prime: HPrimeMatrix = gen_hmatrix(public_key.seed_h);

        // Signature parsing
        let (salt, h1, broad_plain, broadcast_shares, wit_share, mut auth) = (
            signature.salt,
            signature.h1,
            signature.broadcast_plain,
            signature.broadcast_shares,
            signature.solution_share,
            signature.auth,
        );

        // First challenge (MPC challenge) Only generate one in the case of threshold variant
        let chal = Challenge::new(h1);

        // Second challenge (view-opening challenge)
        let h2 = Signature::gen_h2(message, &salt, &h1, &broad_plain, &broadcast_shares);

        // Compute the view-opening challenges
        let view_opening_challenges = MPC::expand_view_challenge_hash(h2);

        let broadcast = Broadcast::parse(broad_plain);
        let mut sh_broadcast = [[[0u8; BROADCAST_SHARE_PLAIN_SIZE]; PARAM_L]; PARAM_TAU];
        let mut commitments: [Hash; PARAM_TAU] = [Hash::default(); PARAM_TAU];

        // Party computation and regeneration of Merkle commitments
        for e in 0..PARAM_TAU {
            let mut commitments_prime = [Hash::default(); PARAM_L];
            for (li, i) in view_opening_challenges[e].iter().enumerate() {
                let with_offset = (*i as usize) != PARAM_N;

                if *i as usize == PARAM_N {
                    // TODO test this case
                    sh_broadcast[e][li] = broadcast_shares[e][li as usize];
                } else {
                    // We need to compute the following:
                    // sh_broadcast[e][i] = (broad_plain, 0) + sum^ℓ_(j=1) fi^j · broad_share[e][j]
                    let f_i = i.to_le_bytes()[0];

                    let mut eval_sum = [0u8; BROADCAST_SHARE_PLAIN_SIZE];

                    // Compute the inner sum
                    // sum^ℓ_(j=1) fi^j · broad_share[e][j]
                    for j in 0..PARAM_L {
                        gf256_add_vector_mul_scalar(
                            &mut eval_sum,
                            &broadcast_shares[e][j],
                            f_i.field_pow((j + 1) as u8),
                        );
                    }

                    // Add the input_plain to the sum
                    // (broad_plain, 0) + eval_sum
                    gf256_add_vector_with_padding(&mut eval_sum, &broad_plain);

                    // sh_broadcast[e][i] = ...
                    gf256_add_vector(&mut sh_broadcast[e][li], &eval_sum);
                }

                // Verify the Merkle path
                let broadcast_share = BroadcastShare::parse(sh_broadcast[e][li]);
                let beaver_triples = MPC::inverse_party_computation(
                    wit_share[e][li],
                    &broadcast_share,
                    &chal,
                    h_prime,
                    public_key.y,
                    &broadcast,
                    with_offset,
                );

                let input_share = Input::append_beaver_triples(wit_share[e][li], beaver_triples);

                // Commit to the shares
                commitments_prime[li] = commit_share(&salt, e as u16, *i - 1, &input_share);
            }

            let Ok(root) = get_merkle_root_from_auth(
                &mut auth[e],
                &commitments_prime,
                &view_opening_challenges[e],
                Some(salt),
            ) else {
                return Err("Merkle root verification failed");
            };
            commitments[e] = root;
        }

        // Compute h1' and compare with h1
        if h1 == Signature::gen_h1(&public_key.seed_h, &public_key.y, salt, commitments) {
            Ok(true)
        } else {
            Err("Hashes do not match")
        }
    }
}
