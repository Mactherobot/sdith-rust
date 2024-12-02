use crate::arith::gf256::gf256_matrices::{gen_hmatrix, HPrimeMatrix};
use crate::mpc::beaver::generate_beaver_triples;
use crate::mpc::{
    compute_broadcast, compute_input_shares, expand_view_challenge_hash, party_computation,
    ComputeInputSharesResult,
};
use crate::subroutines::marshalling::Marshalling;
use crate::utils::iterator::*;
use crate::witness::SOLUTION_PLAIN_SIZE;
use crate::{
    constants::{
        params::{PARAM_DIGEST_SIZE, PARAM_L, PARAM_N, PARAM_TAU},
        types::{Hash, Salt, Seed},
    },
    keygen::SecretKey,
    mpc::{broadcast::BROADCAST_SHARE_PLAIN_SIZE, challenge::Challenge},
    subroutines::{commitments::commit_share, merkle_tree::MerkleTree, prg::PRG},
};

use super::input::INPUT_SIZE;
use super::{input::Input, signature::Signature};

impl Signature {
    #[inline(always)]
    pub fn commit_shares(
        input_shares: &Box<[[[u8; INPUT_SIZE]; PARAM_N]; PARAM_TAU]>,
        salt: Salt,
    ) -> ([[u8; 32]; 6], Vec<MerkleTree>) {
        let mut commitments: [Hash; PARAM_TAU] = [[0u8; PARAM_DIGEST_SIZE]; PARAM_TAU];
        let mut merkle_trees: Vec<MerkleTree> = Vec::with_capacity(PARAM_TAU);
        let mut commitments_prime = [[0u8; PARAM_DIGEST_SIZE]; PARAM_N];
        for e in 0..PARAM_TAU {
            get_iterator(&mut commitments_prime)
                .enumerate()
                .for_each(|(i, commitment)| {
                    *commitment = commit_share(&salt, e as u16, i as u16, &input_shares[e][i]);
                });

            let merkle_tree = MerkleTree::new(commitments_prime, None); // TODO: I spec there is a salt here. In implementation there is not.
            commitments[e] = merkle_tree.get_root();
            merkle_trees.push(merkle_tree);
        }

        (commitments, merkle_trees)
    }

    pub fn sign_message(
        entropy: (Seed, Salt),
        secret_key: &SecretKey,
        message: &Vec<u8>,
    ) -> Result<Self, String> {
        // TODO: error handling

        // Expansion of the parity matrix H'
        let h_prime: HPrimeMatrix = gen_hmatrix(secret_key.seed_h);

        // Randomness generation for the Beaver triples and the shares
        let (mseed, salt) = entropy;
        let mut prg = PRG::init(&mseed, Some(&salt));
        let (a, b, c) = generate_beaver_triples(&mut prg);

        let input = Input {
            solution: secret_key.solution,
            beaver_ab: (a, b),
            beaver_c: c,
        };

        // Compute input shares for the MPC
        let input_plain = input.serialise();
        let ComputeInputSharesResult(input_shares, input_coefs): ComputeInputSharesResult =
            compute_input_shares(&input_plain, &mut prg);

        // Commit shares
        let (commitments, merkle_trees) = Signature::commit_shares(&input_shares, salt);

        // First challenge (MPC challenge)

        // h1 = Hash1 (seedH , y, salt, com[1], . . . , com[τ ])
        let h1 = Signature::gen_h1(&secret_key.seed_h, &secret_key.y, salt, commitments);
        let chal = Challenge::new(h1);

        // MPC Simulation
        let broadcast_result = compute_broadcast(input, &chal, h_prime, secret_key.y);
        if broadcast_result.is_err() {
            return Err("MPC Simulation failed".to_string());
        }

        let broadcast = broadcast_result.unwrap();

        let broadcast_plain = broadcast.serialise();

        let mut broadcast_shares = [[[0u8; BROADCAST_SHARE_PLAIN_SIZE]; PARAM_L]; PARAM_TAU];

        // Run through Tau and l to compute the broadcast shares
        for e in 0..PARAM_TAU {
            for j in 0..PARAM_L {
                let broadcast_share = party_computation(
                    input_coefs[e][j],
                    &chal,
                    h_prime,
                    secret_key.y,
                    &broadcast,
                    false,
                )
                .unwrap();

                broadcast_shares[e][j] = broadcast_share.serialise();
            }
        }

        // Second challenge (view-opening challenge)
        let h2 = Signature::gen_h2(message, &salt, &h1, &broadcast_plain, &broadcast_shares);

        // Create the set of view-opening challenges
        let view_opening_challenges = expand_view_challenge_hash(h2);

        // Signature building
        let mut solution_share = [[[0u8; SOLUTION_PLAIN_SIZE]; PARAM_L]; PARAM_TAU];
        let mut auth: [Vec<Hash>; PARAM_TAU] = Default::default();
        for e in 0..PARAM_TAU {
            auth[e] = merkle_trees[e].get_merkle_path(&view_opening_challenges[e]);
            for (li, i) in view_opening_challenges[e].iter().enumerate() {
                // Truncate witness share by removing beaver triples from the plain value
                solution_share[e][li] =
                    Input::truncate_beaver_triples(&input_shares[e][(*i) as usize]);
            }
        }

        // Build the signature
        let signature = Signature {
            message: message.clone(),
            salt,
            h1,
            broadcast_plain,
            broadcast_shares,
            auth,
            solution_share,
            view_opening_challenges,
        };

        Ok(signature)
    }
}
