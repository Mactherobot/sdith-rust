use crate::{
    constants::{
        params::{PARAM_DIGEST_SIZE, PARAM_L, PARAM_M_SUB_K, PARAM_N, PARAM_SALT_SIZE, PARAM_TAU},
        types::{Hash, Salt, Seed},
    },
    mpc::{
        broadcast::{BroadcastShare, BROADCAST_PLAIN_SIZE, BROADCAST_SHARE_PLAIN_SIZE},
        mpc::MPC,
    },
    subroutines::{
        commitments::commit_share,
        merkle_tree::MerkleTree,
        prg::hashing::{hash_1, hash_2},
    },
    witness::SOLUTION_PLAIN_SIZE,
};

use super::input::{Input, INPUT_SIZE};

pub(super) struct Signature {
    pub(super) salt: Salt,
    pub(super) h1: Hash,
    pub(super) broadcast_plain: [u8; BROADCAST_PLAIN_SIZE],
    pub(super) broadcast_shares: [[[u8; BROADCAST_SHARE_PLAIN_SIZE]; PARAM_L]; PARAM_TAU],
    // wit_share from spec
    pub(super) solution_share: [[[u8; SOLUTION_PLAIN_SIZE]; PARAM_L]; PARAM_TAU],
    pub(super) auth: [Vec<Hash>; PARAM_TAU],
}

impl Signature {
    /// Create a new signature
    ///
    /// # Arguments
    ///
    /// * `salt` - The salt used to generate the signature
    /// * `h1` - Fiat-Shamir hash from Hash_1
    /// * `broadcast_plain` - Serialised broadcast value
    /// * `broadcast_shares_plain` - Serialised broadcast shares
    /// * `view_opening_challenges` - The view opening challenges I[e] = {1.. / N} / *i
    /// * `merkle_trees` - The Merkle trees for each iteration
    /// * `input_shares` - The input shares for each party
    pub(super) fn new(
        salt: Salt,
        h1: Hash,
        broadcast_plain: [u8; BROADCAST_PLAIN_SIZE],
        broadcast_shares: [[[u8; BROADCAST_SHARE_PLAIN_SIZE]; PARAM_L]; PARAM_TAU],
        auth: [Vec<Hash>; PARAM_TAU],
        solution_share: [[[u8; SOLUTION_PLAIN_SIZE]; PARAM_L]; PARAM_TAU],
    ) -> Self {
        Signature {
            salt,
            h1,
            broadcast_plain,
            broadcast_shares,
            auth,
            solution_share,
        }
    }

    pub(crate) fn serialise(&self) -> Vec<u8> {
        let mut serialised = vec![];
        serialised.extend_from_slice(&self.salt);
        serialised.extend_from_slice(&self.h1);
        serialised.extend_from_slice(&self.broadcast_plain);

        for e in 0..PARAM_TAU {
            for i in 0..PARAM_L {
                serialised.extend_from_slice(&self.broadcast_shares[e][i]);
                serialised.extend_from_slice(&self.solution_share[e][i]);
            }
        }

        // Append auth
        for auth in &self.auth {
            for hash in auth {
                serialised.extend_from_slice(hash);
            }
        }

        serialised
    }

    pub(crate) fn parse(signature_plain: Vec<u8>) -> Signature {
        let mut bytes_required = PARAM_DIGEST_SIZE + PARAM_SALT_SIZE;
        bytes_required += BROADCAST_PLAIN_SIZE;
        bytes_required += PARAM_TAU * PARAM_L * BROADCAST_SHARE_PLAIN_SIZE;
        bytes_required += PARAM_TAU * PARAM_L * SOLUTION_PLAIN_SIZE;
        assert!(signature_plain.len() > bytes_required);
        // Create offset to be used for inserting into the sig byte array
        let mut offset = 0;

        let salt: Salt = signature_plain[offset..offset + PARAM_SALT_SIZE]
            .try_into()
            .unwrap();
        offset += PARAM_SALT_SIZE;

        // H1
        let h1: Hash = signature_plain[offset..offset + PARAM_DIGEST_SIZE]
            .try_into()
            .unwrap();
        offset += PARAM_DIGEST_SIZE;

        // Plain Broadcast
        let broadcast_plain: [u8; BROADCAST_PLAIN_SIZE] = signature_plain
            [offset..offset + BROADCAST_PLAIN_SIZE]
            .try_into()
            .unwrap();
        offset += BROADCAST_PLAIN_SIZE;

        let mut solution_share = [[[0u8; SOLUTION_PLAIN_SIZE]; PARAM_L]; PARAM_TAU];
        let mut broadcast_shares = [[[0u8; BROADCAST_SHARE_PLAIN_SIZE]; PARAM_L]; PARAM_TAU];
        for e in 0..PARAM_TAU {
            for i in 0..PARAM_L {
                // Broadcast shares
                broadcast_shares[e][i] = signature_plain
                    [offset..offset + BROADCAST_SHARE_PLAIN_SIZE]
                    .try_into()
                    .unwrap();
                offset += BROADCAST_SHARE_PLAIN_SIZE;

                // Witness shares
                solution_share[e][i] = signature_plain[offset..offset + SOLUTION_PLAIN_SIZE]
                    .try_into()
                    .unwrap();
                offset += SOLUTION_PLAIN_SIZE;
            }
        }
        // We need to create the view opening challenges in order to get the auth paths.
        // We can do this by computing the second hash
        // and then expanding the view opening challenges
        let h2 = Signature::gen_h2(&[], &salt, &h1, &broadcast_plain, &broadcast_shares);

        let view_opening_challenges = MPC::expand_view_challenges_threshold(h2);
        // Expand the view opening challenges

        // Get
        let auth_lengths = MerkleTree::get_auth_size(view_opening_challenges);

        let mut auth: [Vec<Hash>; PARAM_TAU] = Default::default();
        for (e, auth_len) in auth_lengths.iter().enumerate() {
            let mut auth_path = Vec::with_capacity(*auth_len as usize);
            for _ in 0..*auth_len {
                auth_path.push(
                    signature_plain[offset..offset + PARAM_DIGEST_SIZE]
                        .try_into()
                        .unwrap(),
                );
                offset += PARAM_DIGEST_SIZE;
            }
            auth[e] = (auth_path);
        }

        Signature {
            salt,
            h1,
            broadcast_plain,
            broadcast_shares,
            solution_share,
            auth,
        }
    }

    /// Fiat-Shamir Hash1
    /// h1 = Hash (1, seedH , y, salt, com[1], . . . , com[τ ])
    pub(super) fn gen_h1(
        seed_h: &Seed,
        y: &[u8; PARAM_M_SUB_K],
        salt: Salt,
        commitments: [Hash; PARAM_TAU],
    ) -> Hash {
        let mut h1_data: Vec<&[u8]> = vec![seed_h, y, &salt];
        for e in 0..PARAM_TAU {
            h1_data.push(&commitments[e]);
        }
        hash_1(h1_data)
    }

    /// Fiat-Shamir Hash2
    /// h2 = Hash (2, message, salt, h1, broadcast_plain, broadcast_shares_plain)
    pub(super) fn gen_h2(
        message: &[u8],
        salt: &Salt,
        h1: &Hash,
        broadcast_plain: &[u8],
        broadcast_shares: &[[[u8; BROADCAST_SHARE_PLAIN_SIZE]; PARAM_L]; PARAM_TAU],
    ) -> Hash {
        let mut h2_data: Vec<&[u8]> = vec![message, salt, h1, broadcast_plain];
        for e in 0..PARAM_TAU {
            for i in 0..PARAM_L {
                h2_data.push(&broadcast_shares[e][i]);
            }
        }

        hash_2(h2_data)
    }
}

#[cfg(test)]
mod signature_tests {

    use super::*;
    use crate::constants::params::{PARAM_DIGEST_SIZE, PARAM_SEED_SIZE};

    #[test]
    fn test_serialise_deserialise_signature() {
        let auth_lengths: [usize; PARAM_TAU] = [5, 6, 7, 8, 9, 10];
        let auth_vec = auth_lengths
            .iter()
            .map(|&len| vec![Hash::default(); len])
            .collect::<Vec<Vec<Hash>>>();

        let mut auth: [Vec<Hash>; PARAM_TAU] = Default::default();
        for (i, vec) in auth_vec.into_iter().enumerate() {
            auth[i] = vec;
        }

        let sign = Signature {
            salt: [1u8; PARAM_SALT_SIZE],
            h1: [2u8; PARAM_DIGEST_SIZE],
            broadcast_plain: [3u8; BROADCAST_PLAIN_SIZE],
            broadcast_shares: [[[4u8; BROADCAST_SHARE_PLAIN_SIZE]; PARAM_L]; PARAM_TAU],
            solution_share: [[[5u8; SOLUTION_PLAIN_SIZE]; PARAM_L]; PARAM_TAU],
            auth,
        };

        let serialised = sign.serialise();
        let deserialised = Signature::parse(serialised);

        assert_eq!(sign.salt, deserialised.salt);
        assert_eq!(sign.h1, deserialised.h1);
        assert_eq!(sign.broadcast_plain, deserialised.broadcast_plain);
        assert_eq!(sign.broadcast_shares, deserialised.broadcast_shares);
        assert_eq!(sign.solution_share, deserialised.solution_share);

        // Check auths
        for (i, auth) in sign.auth.iter().enumerate() {
            for (j, hash) in auth.iter().enumerate() {
                assert_eq!(hash, &deserialised.auth[i][j]);
            }
        }
    }
}
