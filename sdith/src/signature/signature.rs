use crate::{
    arith::matrices::MatrixGF256,
    constants::{
        params::{PARAM_DIGEST_SIZE, PARAM_L, PARAM_N, PARAM_SALT_SIZE, PARAM_TAU},
        types::{CommitmentsArray, Hash, Salt, Seed},
    },
    keygen::SecretKey,
    mpc::{
        broadcast::{BROADCAST_PLAIN_SIZE, BROADCAST_SHARE_PLAIN_SIZE},
        challenge::Challenge,
        mpc::MPC,
    },
    subroutines::{
        commitments::commit_share,
        merkle_tree::MerkleTree,
        prg::{
            hashing::{hash_1, hash_2},
            prg::PRG,
        },
    },
    witness::{HPrimeMatrix, SOLUTION_PLAIN_SIZE},
};

use super::input::{Input, INPUT_SIZE};

struct Signature {
    salt: Salt,
    h1: Hash,
    broadcast_plain: [u8; BROADCAST_PLAIN_SIZE],
    broadcast_shares_plain: [u8; BROADCAST_SHARE_PLAIN_SIZE],
    // wit_share from spec
    solution_share: [[[u8; SOLUTION_PLAIN_SIZE]; PARAM_L]; PARAM_TAU],
    auth: [Vec<Hash>; PARAM_TAU],
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
    fn new(
        salt: Salt,
        h1: Hash,
        broadcast_plain: [u8; BROADCAST_PLAIN_SIZE],
        broadcast_shares_plain: [u8; BROADCAST_SHARE_PLAIN_SIZE],
        view_opening_challenges: [[u16; PARAM_L]; PARAM_TAU],
        merkle_trees: Vec<MerkleTree>,
        // Shares of the input (s_a, Q', P) and the Beaver triples (a, b, c) for each party
        input_shares: [[[u8; INPUT_SIZE]; PARAM_N]; PARAM_TAU],
    ) -> Self {
        // Signature building
        let mut solution_share = [[[0u8; SOLUTION_PLAIN_SIZE]; PARAM_L]; PARAM_TAU];
        let mut auth: [Vec<Hash>; PARAM_TAU] = Default::default();
        for e in 0..PARAM_TAU {
            // Fetch auth path for
            auth[e] = merkle_trees[e].get_merkle_path(&view_opening_challenges[e]);
            for (_i, i) in view_opening_challenges[e].iter().enumerate() {
                // Truncate witness share by removing beaver triples from the plain value
                solution_share[e][_i] = Input::truncate_beaver_triples(input_shares[e][*i as usize])
            }
        }

        Signature {
            salt,
            h1,
            broadcast_plain,
            broadcast_shares_plain,
            auth,
            solution_share,
        }
    }

    pub(crate) fn serialise(&self) -> Vec<u8> {
        let mut serialised = vec![];
        serialised.extend_from_slice(&self.salt);
        serialised.extend_from_slice(&self.h1);
        serialised.extend_from_slice(&self.broadcast_plain);
        serialised.extend_from_slice(&self.broadcast_shares_plain);

        for e in 0..PARAM_TAU {
            for i in 0..PARAM_L {
                serialised.extend_from_slice(&self.solution_share[e][i]);
            }
        }

        // Append auth sizes
        for auth in &self.auth {
            serialised.extend_from_slice(&(auth.len() as u16).to_le_bytes());
        }

        // Append auth
        for auth in &self.auth {
            for hash in auth {
                serialised.extend_from_slice(hash);
            }
        }

        serialised
    }

    pub(crate) fn deserialise(signature_plain: Vec<u8>) -> Signature {
        let mut offset = 0;
        let salt: Salt = signature_plain[offset..offset + PARAM_SALT_SIZE]
            .try_into()
            .unwrap();
        offset += PARAM_SALT_SIZE;

        let h1: Hash = signature_plain[offset..offset + PARAM_DIGEST_SIZE]
            .try_into()
            .unwrap();
        offset += PARAM_DIGEST_SIZE;

        let broadcast_plain: [u8; BROADCAST_PLAIN_SIZE] = signature_plain
            [offset..offset + BROADCAST_PLAIN_SIZE]
            .try_into()
            .unwrap();
        offset += BROADCAST_PLAIN_SIZE;

        let broadcast_shares_plain: [u8; BROADCAST_SHARE_PLAIN_SIZE] = signature_plain
            [offset..offset + BROADCAST_SHARE_PLAIN_SIZE]
            .try_into()
            .unwrap();
        offset += BROADCAST_SHARE_PLAIN_SIZE;

        let mut solution_share = [[[0u8; SOLUTION_PLAIN_SIZE]; PARAM_L]; PARAM_TAU];
        for e in 0..PARAM_TAU {
            for i in 0..PARAM_L {
                solution_share[e][i] = signature_plain[offset..offset + SOLUTION_PLAIN_SIZE]
                    .try_into()
                    .unwrap();
                offset += SOLUTION_PLAIN_SIZE;
            }
        }

        let auth_lengths = (0..PARAM_TAU)
            .map(|_| {
                let len =
                    u16::from_le_bytes(signature_plain[offset..offset + 2].try_into().unwrap());
                offset += 2;
                len
            })
            .collect::<Vec<u16>>();

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
            broadcast_shares_plain,
            solution_share,
            auth,
        }
    }
}

pub(crate) fn sign_message(
    entropy: (Seed, Salt),
    secret_key: SecretKey,
    message: &[u8],
) -> Signature {
    // Expansion of the parity matrix H'
    let h_prime = HPrimeMatrix::gen_random(&mut PRG::init(&secret_key.seed_h, None));

    // Randomness generation for the Beaver triples and the shares
    let (mseed, salt) = entropy;
    let mut prg = PRG::init(&mseed, Some(&salt));
    let (a, b, c) = MPC::generate_beaver_triples(&mut prg);

    let input = Input {
        solution: secret_key.solution,
        beaver_ab: (a, b),
        beaver_c: c,
    };

    // Compute input shares for the MPC
    // let mut input_shares
    let input_shares = input.compute_input_shares(&mut prg);
    let mut commitments: [CommitmentsArray; PARAM_TAU] = [[Hash::default(); PARAM_N]; PARAM_TAU];

    // Commit shares
    let mut merkle_trees: Vec<MerkleTree> = Vec::with_capacity(PARAM_TAU);
    for e in 0..PARAM_TAU {
        for i in 0..PARAM_N {
            // Commit to the shares
            commitments[e][i] = commit_share(&salt, e as u16, i as u16, &input_shares[e][i]);
        }
        merkle_trees.push(MerkleTree::new(commitments[e], Some(salt)));
    }

    // First challenge (MPC challenge)

    // h1 = Hash1 (seedH , y, salt, com[1], . . . , com[τ ])
    let mut h1_data: Vec<&[u8]> = vec![&secret_key.seed_h, &secret_key.y, &salt];
    for e in 0..PARAM_TAU {
        for i in 0..PARAM_N {
            h1_data.push(&commitments[e][i]);
        }
    }
    let h1 = hash_1(h1_data);
    let chal = Challenge::new(h1);

    // MPC Simulation
    let beaver_triples = (a, b, c);
    let broadcast = MPC::compute_broadcast(input, chal.clone(), h_prime, secret_key.y);

    // Run throuh Tau and l to compute the broadcast shares
    let broadcast_shares = MPC::party_computation(
        secret_key.solution,
        beaver_triples,
        chal,
        &broadcast,
        false,
        h_prime,
        secret_key.y,
    );

    let broadcast_plain = broadcast.serialise();
    let broadcast_shares_plain = broadcast_shares.serialise();

    // Second challenge (view-opening challenge)
    // Create the hash data for h2, contains message, salt, h1, broadcast_plain, broadcast_shares_plain
    let h2_data: Vec<&[u8]> = vec![
        message,
        &salt,
        &h1,
        &broadcast_plain,
        &broadcast_shares_plain,
    ];

    let h2 = hash_2(h2_data);

    // Create the set of view-opening challenges
    let view_opening_challenges = MPC::expand_view_challenges_threshold(h2);

    // Build the signature
    let signature = Signature::new(
        salt,
        h1,
        broadcast_plain,
        broadcast_shares_plain,
        view_opening_challenges,
        merkle_trees,
        input_shares,
    );

    signature
}

#[cfg(test)]
mod signature_tests {
    use super::*;
    use crate::constants::params::PARAM_DIGEST_SIZE;

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
            broadcast_shares_plain: [4u8; BROADCAST_SHARE_PLAIN_SIZE],
            solution_share: [[[5u8; SOLUTION_PLAIN_SIZE]; PARAM_L]; PARAM_TAU],
            auth,
        };

        let serialised = sign.serialise();
        let deserialised = Signature::deserialise(serialised);

        assert_eq!(sign.salt, deserialised.salt);
        assert_eq!(sign.h1, deserialised.h1);
        assert_eq!(sign.broadcast_plain, deserialised.broadcast_plain);
        assert_eq!(
            sign.broadcast_shares_plain,
            deserialised.broadcast_shares_plain
        );
        assert_eq!(sign.solution_share, deserialised.solution_share);

        for (i,auth_len) in auth_lengths.iter().enumerate() {
            assert_eq!(auth_len, &deserialised.auth[i].len());
        }
    }
}
